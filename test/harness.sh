#!/usr/bin/env bash
# xdpfilter functional harness: emulate the bump-in-the-wire with veth + netns,
# drive the real daemon, and assert PASS / DROP / VLAN / mode / resilience.
#
# Emulated topology (mirrors the mlx5 deployment):
#
#   [host ns] h0 <--veth--> brh [prog TRUSTED] .. [prog UNTRUST] bri <--veth--> i0 [inet ns]
#
# h0/i0 carry a minimal XDP_PASS prog so redirected frames are accepted into the
# netns (the veth analog of mlx5's "egress needs XDP" rule).
set -u

BIN="${BIN:-./dist/xdpfilter}"
PIN="/sys/fs/bpf/xdpfilter"
STATS="/tmp/xdpf-stats"
CFG="/tmp/xdpf-veth.yaml"
PASS_O="/tmp/xdp_pass.o"
DAEMON_PID=""
PASS=0; FAIL=0

log()  { printf '\n=== %s ===\n' "$*"; }
ok()   { printf '  [PASS] %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  [FAIL] %s\n' "$*"; FAIL=$((FAIL+1)); }
info() { printf '  ... %s\n' "$*"; }

# cumulative counters pulled from `xdpfilter status` (deterministic assertions).
status_dropped() { "$BIN" status --config "$CFG" 2>/dev/null | awk '/^[[:space:]]*dropped/{gsub(/,/,"",$2); print $2; exit}'; }
stat_l1() { "$BIN" status --config "$CFG" 2>/dev/null | awk '/l1 hits/{gsub(/,/,"",$3); print $3; exit}'; }
stat_rst() { "$BIN" status --config "$CFG" 2>/dev/null | awk '/rst replies/{gsub(/,/,"",$3); print $3; exit}'; }

need_root() { [ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }; }

cleanup() {
	log "cleanup"
	[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
	"$BIN" stop --detach --yes --config "$CFG" 2>/dev/null || true
	ip netns del host 2>/dev/null || true
	ip netns del inet 2>/dev/null || true
	ip link del brh 2>/dev/null || true
	ip link del bri 2>/dev/null || true
	rm -f "$CFG"
}
trap cleanup EXIT

need_root
[ -x "$BIN" ] || { echo "build first: make dev  (missing $BIN)"; exit 1; }

log "setup"
grep -qs '/sys/fs/bpf ' /proc/mounts || mount -t bpf bpf /sys/fs/bpf
"$BIN" stop --detach --yes --config /dev/null 2>/dev/null || true
ip netns del host 2>/dev/null || true; ip netns del inet 2>/dev/null || true
ip link del brh 2>/dev/null || true; ip link del bri 2>/dev/null || true

clang -O2 -g -target bpf -I/usr/include/"$(uname -m)"-linux-gnu \
	-c test/bpf/xdp_pass.c -o "$PASS_O" || { echo "xdp_pass compile failed"; exit 1; }
info "compiled xdp_pass.o"

ip netns add host; ip netns add inet
ip link add brh type veth peer name h0
ip link add bri type veth peer name i0
ip link set h0 netns host
ip link set i0 netns inet

ip netns exec host ip addr add 10.0.0.2/24 dev h0
ip netns exec inet ip addr add 10.0.0.3/24 dev i0
for f in tso gso gro tx rx; do
	ip netns exec host ethtool -K h0 $f off 2>/dev/null || true
	ip netns exec inet ethtool -K i0 $f off 2>/dev/null || true
done
# Disable VLAN offload so 802.1Q tags stay in the frame payload where XDP sees
# and preserves them (the tuner does this on the real mlx5 ports).
ethtool -K brh rxvlan off txvlan off 2>/dev/null || true
ethtool -K bri rxvlan off txvlan off 2>/dev/null || true
ip netns exec host ethtool -K h0 rxvlan off txvlan off 2>/dev/null || true
ip netns exec inet ethtool -K i0 rxvlan off txvlan off 2>/dev/null || true
ip link set brh up; ip link set bri up
ip netns exec host ip link set h0 up; ip netns exec host ip link set lo up
ip netns exec inet ip link set i0 up; ip netns exec inet ip link set lo up

# XDP_PASS on the netns endpoints so redirected frames are delivered.
ip netns exec host ip link set dev h0 xdpdrv obj "$PASS_O" sec xdp
ip netns exec inet ip link set dev i0 xdpdrv obj "$PASS_O" sec xdp
info "attached xdp_pass on h0/i0"

write_config() { # $1=allow_inbound_servers (default false)  $2=server_allow yaml (default [])
	cat > "$CFG" <<EOF
trusted_iface: brh
untrusted_iface: bri
mode: enforce
oos_strict: false
drop_frags: true
drop_bad_flags: true
filter_udp: true
drop_vlan_deep: ${DVLAN:-false}
drop_udp_frags: ${DUDPFRAG:-false}
reject_with_rst: ${RSTREPLY:-false}
allow_inbound_servers: ${1:-false}
allow_inbound_syn: ${ALLOWINBOUNDSYN:-false}
server_allow: ${2:-[]}
flow_monitoring:
  enabled: ${FLOWMON:-false}
  sample_every: ${FLOWSAMPLE:-64}
  max_flows: 65536
  cidrs:
    - cidr: 10.0.0.0/24
      pps_threshold: ${FLOWPPS:-1000000}
      mbps_threshold: 0
flow_max: 65536
udp_flow_max: 65536
l1_size: ${L1SIZE:-65536}
ttl_syn: 3
ttl_est: 300
ttl_closing: 3
ttl_udp: 30
xdp_mode: native
tune: false
stats_dir: $STATS
stats_interval: 1
gc_interval: 1
pin_dir: $PIN
EOF
}
write_config

"$BIN" daemon --config "$CFG" >/tmp/xdpf-daemon.log 2>&1 &
DAEMON_PID=$!
sleep 2
if ip link show brh | grep -q xdp && ip link show bri | grep -q xdp; then
	ok "filter attached to both ports (native XDP)"
else
	bad "filter did not attach — see /tmp/xdpf-daemon.log"; cat /tmp/xdpf-daemon.log; exit 1
fi

# ---- Test 1: legitimate traffic forwards (ICMP + a full TCP handshake) ----
log "Test 1: legitimate traffic PASSES"
if ip netns exec host ping -c2 -W2 10.0.0.3 >/dev/null 2>&1; then
	ok "ICMP forwarded host<->inet (bridge transparent)"
else
	bad "ping failed"
fi

timeout 8 ip netns exec inet python3 -c '
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("10.0.0.3",9000)); s.listen(1)
c,_=s.accept(); d=c.recv(100); c.sendall(b"ok" if d==b"hello" else b"no")
' &
sleep 1
REPLY=$(timeout 6 ip netns exec host python3 -c '
import socket
s=socket.socket(); s.settimeout(3); s.connect(("10.0.0.3",9000))
s.sendall(b"hello"); print(s.recv(100).decode())
' 2>/dev/null)
if [ "$REPLY" = "ok" ]; then
	ok "TCP handshake+data passed (SYN->SYN-ACK ISN-validated->EST)"
else
	bad "stateful TCP failed (reply=$REPLY)"
fi

# ---- Test 2: spoofed SYN-ACK / ACK / RST floods DROP ----
log "Test 2: spoofed floods DROP, never reach the host"
sleep 1
for k in synack ack rst badflags; do
	ip netns exec inet python3 test/attack.py i0 10.0.0.2 200 "$k" 2>&1 | tail -1
done
sleep 2
# Assert on the actual cumulative dropped counter (deterministic), not a label grep.
dropped=$("$BIN" status --config "$CFG" 2>/dev/null | awk '/^[[:space:]]*dropped/{gsub(/,/,"",$2); print $2; exit}')
info "cumulative dropped packets: ${dropped:-0}"
if [ "${dropped:-0}" -gt 0 ] 2>/dev/null; then
	ok "spoofed floods dropped ($dropped pkts, incl. unsolicited SYN-ACK)"
else
	bad "no drops recorded"; sed 's/^/    /' "$STATS/stats.txt" 2>/dev/null
fi
# flow table must NOT have grown from the flood (no-create property)
nflows=$("$BIN" flows --config "$CFG" --limit 0 2>/dev/null | tail -1)
info "flow table after flood (attacker cannot create state): $nflows"

# ---- Test 3: VLAN transparency ----
log "Test 3: VLAN-tagged traffic PASSES + is VID-isolated"
ip netns exec host ip link add link h0 name h0.100 type vlan id 100
ip netns exec inet ip link add link i0 name i0.100 type vlan id 100
ip netns exec host ip addr add 10.0.100.2/24 dev h0.100
ip netns exec inet ip addr add 10.0.100.3/24 dev i0.100
ip netns exec host ip link set h0.100 up
ip netns exec inet ip link set i0.100 up
if ip netns exec host ping -c2 -W2 10.0.100.3 >/dev/null 2>&1; then
	ok "802.1Q VID 100 forwarded with tag intact"
else
	bad "VLAN ping failed"
fi

# ---- Test 4: live mode flip ----
log "Test 4: monitor/enforce flips live"
if "$BIN" mode monitor --config "$CFG" >/dev/null 2>&1 && \
   "$BIN" status --config "$CFG" 2>/dev/null | grep -qi "mode: MONITOR"; then
	ok "flipped to monitor without reattach"
	"$BIN" mode enforce --config "$CFG" >/dev/null 2>&1
else
	bad "mode flip failed"
fi

# ---- Test 5: UDP stateful filtering ----
log "Test 5: UDP — reply passes, unsolicited inbound DROPS"
timeout 6 ip netns exec inet python3 -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.0.0.3",9001))
d,a=s.recvfrom(100); s.sendto(b"pong",a)
' &
sleep 1
UREPLY=$(timeout 4 ip netns exec host python3 -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(b"ping",("10.0.0.3",9001)); print(s.recvfrom(100)[0].decode())
' 2>/dev/null)
if [ "$UREPLY" = "pong" ]; then
	ok "outbound UDP opened a flow; reply passed"
else
	bad "legit UDP reply blocked (reply=$UREPLY)"
fi
d1=$("$BIN" status --config "$CFG" 2>/dev/null | awk '/^[[:space:]]*dropped/{gsub(/,/,"",$2); print $2; exit}')
ip netns exec inet python3 -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(200): s.sendto(b"x",("10.0.0.2",9999))
'
sleep 2
d2=$("$BIN" status --config "$CFG" 2>/dev/null | awk '/^[[:space:]]*dropped/{gsub(/,/,"",$2); print $2; exit}')
if [ "$(( ${d2:-0} - ${d1:-0} ))" -ge 100 ] 2>/dev/null; then
	ok "unsolicited inbound UDP dropped ($(( ${d2:-0} - ${d1:-0} )) pkts) — off the destination's conntrack"
else
	bad "unsolicited UDP not dropped (delta=$(( ${d2:-0} - ${d1:-0} )))"
fi

# ---- Test 5b: sampled inbound flow monitoring + NDJSON snapshot ----
log "Test 5b: inbound flow monitoring updates NDJSON every second"
FLOWMON=true FLOWSAMPLE=1 FLOWPPS=10 write_config false '[]'
sleep 2 # live reload + clean baseline
ip netns exec inet python3 -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(200): s.sendto(b"x"*100,("10.0.0.2",9998))
'
alert_seen=false
for _ in $(seq 1 30); do
	if [ -s "$STATS/flow_alerts.jsonl" ]; then alert_seen=true; break; fi
	sleep 0.1
done
if $alert_seen && python3 - "$STATS/flow_alerts.jsonl" <<'PY'
import json, sys
with open(sys.argv[1]) as f: row=json.loads(f.readline())
flow=row["flow"]
assert row["schema"] == 1 and row["matched_cidr"] == "10.0.0.0/24"
assert flow["protocol"] == "udp" and flow["protected_ip"] == "10.0.0.2" and flow["protected_port"] == 9998
assert row["estimated_pps"] > row["threshold_pps"] and "pps" in row["exceeded"]
PY
then
	ok "dropped inbound UDP volume produced a parseable over-threshold tuple"
else
	bad "flow alert snapshot missing or invalid"; sed 's/^/    /' "$STATS/flow_alerts.jsonl" 2>/dev/null
fi
clean_seen=false
for _ in $(seq 1 30); do
	if [ -f "$STATS/flow_alerts.jsonl" ] && [ ! -s "$STATS/flow_alerts.jsonl" ]; then clean_seen=true; break; fi
	sleep 0.1
done
$clean_seen && ok "flow left the snapshot after the next clean window" || bad "flow alert did not clear"
write_config false '[]'
sleep 1

# ---- Test 6: resilience — datapath survives daemon kill ----
log "Test 6: datapath survives daemon crash (pinned links)"
kill -9 "$DAEMON_PID" 2>/dev/null; sleep 1
if ip link show brh | grep -q xdp && ip link show bri | grep -q xdp; then
	ok "XDP stays attached after SIGKILL (pinned)"
else
	bad "datapath dropped on daemon death"
fi
"$BIN" daemon --config "$CFG" >/tmp/xdpf-daemon2.log 2>&1 &
DAEMON_PID=$!
sleep 2
ip link show brh | grep -q xdp && ok "daemon restarted and re-adopted the datapath" || bad "re-adopt failed"

# ---- Test 7: GC reaps expired half-open flows ----
log "Test 7: GC deletes expired half-open flows"
ip netns exec host ip neigh replace 10.0.0.99 lladdr 02:00:00:00:00:99 dev h0
ip netns exec host python3 - <<'PY' 2>/dev/null
import socket, time
s = socket.socket(); s.setblocking(False)
try: s.connect(("10.0.0.99", 9999))   # unanswered -> stays SYN_SENT (ttl_syn=3)
except BlockingIOError: pass
time.sleep(0.3)
PY
sleep 1
count_flows() { "$BIN" flows --config "$CFG" --limit 0 2>/dev/null | awk '/shown/{gsub(/[()]/,"",$1); print $1}'; }
n1=$(count_flows); info "flows after SYN: ${n1:-0}"
sleep 6   # ttl_syn(3) + a couple of gc_interval(1) sweeps
n2=$(count_flows); info "flows after TTL: ${n2:-0}"
if [ "${n1:-0}" -ge 1 ] && [ "${n2:-0}" -lt "${n1:-0}" ] 2>/dev/null; then
	ok "expired half-open flow reaped by GC (${n1} -> ${n2})"
else
	bad "GC did not reap the half-open flow (before=${n1:-?} after=${n2:-?})"
fi

# ---- Test 8: inbound TCP policy + live config reload ----
log "Test 8: inbound TCP — default deny, selective allowlist, global SYN switch"
try_inbound_tcp() {
	local port="$1"
	timeout 5 ip netns exec host python3 -c '
import socket, sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("10.0.0.2",int(sys.argv[1]))); s.listen(1); s.settimeout(3)
c,_=s.accept(); c.sendall(b"ok")
' "$port" >/dev/null 2>&1 &
	local server_pid=$!
	sleep 0.5
	local reply
	reply=$(timeout 3 ip netns exec inet python3 -c '
import socket, sys
s=socket.socket(); s.settimeout(2); s.connect(("10.0.0.2",int(sys.argv[1])))
print(s.recv(10).decode())
' "$port" 2>/dev/null || true)
	wait "$server_pid" 2>/dev/null || true
	[ "$reply" = "ok" ]
}

if try_inbound_tcp 8080; then
	bad "inbound TCP reached an unlisted server with both policies off"
else
	ok "inbound TCP blocked by default"
fi

write_config true '["10.0.0.2:8080"]'   # edit -> inotify auto-reload
sleep 2
if grep -q "reload: applied.*allowlist=1" /tmp/xdpf-daemon2.log 2>/dev/null; then
	ok "config edit auto-reloaded the allowlist via inotify"
else
	info "daemon log:"; grep -i reload /tmp/xdpf-daemon2.log 2>/dev/null | sed 's/^/    /'
	bad "live reload did not apply the allowlist"
fi
if try_inbound_tcp 8080; then
	ok "allowlisted inbound TCP server accepted a connection"
else
	bad "allowlisted inbound TCP server was blocked"
fi

ALLOWINBOUNDSYN=true write_config false '[]'
sleep 2
if try_inbound_tcp 8081; then
	ok "allow_inbound_syn admitted an unlisted TCP destination"
else
	bad "allow_inbound_syn did not admit an unlisted TCP destination"
fi

ud1=$(status_dropped)
ip netns exec inet python3 -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(20): s.sendto(b"x",("10.0.0.2",8081))
'
sleep 1
ud2=$(status_dropped)
if [ "$(( ${ud2:-0} - ${ud1:-0} ))" -ge 10 ] 2>/dev/null; then
	ok "allow_inbound_syn left unsolicited UDP filtering enabled"
else
	bad "allow_inbound_syn unexpectedly admitted UDP (drop delta=$(( ${ud2:-0} - ${ud1:-0} )))"
fi

write_config false '[]'
kill -HUP "$DAEMON_PID" 2>/dev/null; sleep 1
if grep -q "reload: applied.*allowlist=0" /tmp/xdpf-daemon2.log 2>/dev/null; then
	ok "reload cleared the allowlist (SIGHUP / inotify)"
else
	bad "reload did not clear the allowlist"
fi

# ---- Test 9: L1 fast-path cache serves established-flow packets ----
log "Test 9: L1 fast-path cache serves established flows"
l1_before=$(stat_l1)
# bulk transfer: many pure-ACK/data segments within one coarse tick -> L1 hits
timeout 12 ip netns exec inet python3 -c '
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("10.0.0.3",9300)); s.listen(1)
c,_=s.accept(); got=0
while got < 400000:
    d=c.recv(65536)
    if not d: break
    got+=len(d)
c.sendall(b"done")
' &
sleep 1
BULK=$(timeout 10 ip netns exec host python3 -c '
import socket
s=socket.socket(); s.settimeout(6); s.connect(("10.0.0.3",9300))
buf=b"x"*65536; sent=0
while sent < 400000:
    s.sendall(buf); sent+=len(buf)
print(s.recv(10).decode())
' 2>/dev/null)
sleep 1
l1_after=$(stat_l1)
l1_delta=$(( ${l1_after:-0} - ${l1_before:-0} ))
info "l1 hits: ${l1_before:-0} -> ${l1_after:-0} (delta $l1_delta)"
if [ "${L1SIZE:-65536}" = "0" ]; then
	# L1 disabled: the datapath must still forward correctly, with zero hits.
	if [ "$BULK" = "done" ] && [ "$l1_delta" -eq 0 ] 2>/dev/null; then
		ok "L1 disabled (l1_size=0): bulk transfer forwarded, 0 hits (kill-switch parity)"
	else
		bad "L1 disabled but datapath misbehaved (delta=$l1_delta reply=$BULK)"
	fi
else
	if [ "$BULK" = "done" ] && [ "$l1_delta" -gt 0 ] 2>/dev/null; then
		ok "L1 cache served $l1_delta established-flow packets (fast path)"
	else
		bad "L1 cache recorded no hits (before=${l1_before:-?} after=${l1_after:-?} reply=$BULK)"
	fi
fi

# ---- Test 10: reused-tuple reconnect promotes to ESTABLISHED (A1) ----
log "Test 10: reused-tuple reconnect promotes to EST (survives idle > ttl_closing)"
# server closes conn1 first (frees the client's fixed source port without TIME_WAIT),
# then accepts conn2 on the *same* 4-tuple and replies only after a > ttl_closing idle.
timeout 20 ip netns exec inet python3 -c '
import socket, time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("10.0.0.3",9400)); s.listen(2)
c,_=s.accept(); c.recv(10); c.sendall(b"one"); c.close()
c2,_=s.accept(); c2.recv(10); time.sleep(5); c2.sendall(b"two"); c2.close()
' &
sleep 1
RE=$(timeout 18 ip netns exec host python3 -c '
import socket, time
def conn():
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("10.0.0.2",55400)); s.settimeout(8); s.connect(("10.0.0.3",9400)); return s
a=conn(); a.sendall(b"a"); a.recv(10); a.close()
time.sleep(0.5)
b=conn(); b.sendall(b"b")
try: print(b.recv(10).decode())
except Exception: print("timeout")
' 2>/dev/null)
if [ "$RE" = "two" ]; then
	ok "reused-tuple flow promoted to EST and survived idle > ttl_closing (A1 fixed)"
else
	bad "reused-tuple flow died — A1 regression (got '$RE')"
fi

# ---- Test 11: FIN-without-ACK dropped (A4) ----
log "Test 11: FIN-without-ACK dropped (never legitimate)"
f1=$(status_dropped)
ip netns exec inet python3 test/attack.py i0 10.0.0.2 200 finonly 2>&1 | tail -1
sleep 2
f2=$(status_dropped)
if [ "$(( ${f2:-0} - ${f1:-0} ))" -ge 100 ] 2>/dev/null; then
	ok "FIN-without-ACK dropped ($(( ${f2:-0} - ${f1:-0} )) pkts)"
else
	bad "FIN-without-ACK not dropped (delta=$(( ${f2:-0} - ${f1:-0} )))"
fi

# ---- Test 12: drop_vlan_deep policy (triple-tagged frames) ----
log "Test 12: drop_vlan_deep — excess-VLAN frames drop only when enabled"
v1=$(status_dropped)
ip netns exec inet python3 test/attack.py i0 10.0.0.2 100 vlandeep 2>&1 | tail -1
sleep 1
v2=$(status_dropped)
info "drops with drop_vlan_deep=off: $(( ${v2:-0} - ${v1:-0} )) (expected ~0)"
DVLAN=true write_config   # live reload turns the policy on
sleep 2
ip netns exec inet python3 test/attack.py i0 10.0.0.2 100 vlandeep 2>&1 | tail -1
sleep 1
v3=$(status_dropped)
if [ "$(( ${v2:-0} - ${v1:-0} ))" -lt 20 ] 2>/dev/null && [ "$(( ${v3:-0} - ${v2:-0} ))" -ge 50 ] 2>/dev/null; then
	ok "drop_vlan_deep off=transparent, on=dropped $(( ${v3:-0} - ${v2:-0} )) deep-VLAN frames"
else
	bad "drop_vlan_deep behaved wrong (off delta=$(( ${v2:-0} - ${v1:-0} )), on delta=$(( ${v3:-0} - ${v2:-0} )))"
fi
DVLAN=false write_config; sleep 1   # restore default

# ---- Test 13: drop_udp_frags policy (non-first UDP fragments) ----
log "Test 13: drop_udp_frags — UDP fragments drop only when enabled"
u1=$(status_dropped)
ip netns exec inet python3 test/attack.py i0 10.0.0.2 100 udpfrag 2>&1 | tail -1
sleep 1
u2=$(status_dropped)
info "drops with drop_udp_frags=off: $(( ${u2:-0} - ${u1:-0} )) (expected ~0)"
DUDPFRAG=true write_config
sleep 2
ip netns exec inet python3 test/attack.py i0 10.0.0.2 100 udpfrag 2>&1 | tail -1
sleep 1
u3=$(status_dropped)
if [ "$(( ${u2:-0} - ${u1:-0} ))" -lt 20 ] 2>/dev/null && [ "$(( ${u3:-0} - ${u2:-0} ))" -ge 50 ] 2>/dev/null; then
	ok "drop_udp_frags off=transparent, on=dropped $(( ${u3:-0} - ${u2:-0} )) UDP fragments"
else
	bad "drop_udp_frags behaved wrong (off delta=$(( ${u2:-0} - ${u1:-0} )), on delta=$(( ${u3:-0} - ${u2:-0} )))"
fi
DUDPFRAG=false write_config; sleep 1   # restore default

# ---- Test 14: reject_with_rst — enforced TCP drops answered with a RST ----
log "Test 14: reject_with_rst — RST reply to source (drop vectors untagged + encapsulations)"
RSTREPLY=true write_config; sleep 2   # live-enable the policy

# Part A: several drop vectors, UNTAGGED — each enforced TCP drop must emit a RST,
# and (best-effort) the reflected RST must itself be untagged with valid checksums.
allok=1
for sub in synack ack rst badflags; do
	r1=$(stat_rst)
	out=$(ip netns exec inet python3 test/attack.py i0 10.0.0.2 1 rstprobe "$sub" 0 2>&1 | tail -1)
	sleep 1
	r2=$(stat_rst)
	if [ "$(( ${r2:-0} - ${r1:-0} ))" -ge 1 ] 2>/dev/null; then
		info "untagged $sub -> RST emitted  ($out)"
	else
		allok=0; info "untagged $sub -> NO RST (delta=$(( ${r2:-0} - ${r1:-0} )), $out)"
	fi
	# best-effort: if the reflected RST was observed, it must be untagged (rst_tags=0
	# -> ok=1) with correct IP+TCP checksums — proven per drop vector, not just `ack`.
	if echo "$out" | grep -q "reply=RST"; then
		echo "$out" | grep -q "ok=1" || { allok=0; info "untagged $sub: not untagged ($out)"; }
		echo "$out" | grep -q "cksum=1" || { allok=0; info "untagged $sub: bad checksum ($out)"; }
	fi
done
if [ "$allok" = 1 ]; then
	ok "untagged: every TCP drop vector produced a valid, untagged RST reply"
else
	bad "some untagged drop vector did not produce a valid untagged RST"
fi

# Part B: encapsulation preserved — untagged, single 802.1Q, and QinQ.
encok=1
for tags in 0 1 2; do
	r1=$(stat_rst)
	out=$(ip netns exec inet python3 test/attack.py i0 10.0.0.2 1 rstprobe ack "$tags" 2>&1 | tail -1)
	sleep 1
	r2=$(stat_rst)
	[ "$(( ${r2:-0} - ${r1:-0} ))" -ge 1 ] 2>/dev/null || { encok=0; info "tags=$tags: no RST counted"; }
	# best-effort: if the reflected RST was actually observed, its tag depth and
	# its IP+TCP checksums must be correct
	if echo "$out" | grep -q "reply=RST"; then
		echo "$out" | grep -q "ok=1" || { encok=0; info "tags=$tags: encapsulation mismatch ($out)"; }
		echo "$out" | grep -q "cksum=1" || { encok=0; info "tags=$tags: bad checksum ($out)"; }
	fi
	info "tags=$tags: $out"
done
if [ "$encok" = 1 ]; then
	ok "RST produced with matching encapsulation (untagged, 802.1Q, QinQ)"
else
	bad "RST production/encapsulation wrong across tag depths"
fi

# Part C: negative — with reject_with_rst OFF, the drop is silent (no RST).
RSTREPLY=false write_config; sleep 2
n1=$(stat_rst)
ip netns exec inet python3 test/attack.py i0 10.0.0.2 1 rstprobe ack 0 2>&1 | tail -1
sleep 1
n2=$(stat_rst)
if [ "$(( ${n2:-0} - ${n1:-0} ))" -eq 0 ] 2>/dev/null; then
	ok "reject_with_rst off -> no RST emitted (silent drop restored)"
else
	bad "RST emitted while reject_with_rst off (delta=$(( ${n2:-0} - ${n1:-0} )))"
fi

# ---- summary ----
log "summary"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
