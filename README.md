# xdpfilter

A transparent, two-port XDP filter that drops spoofed and out-of-state TCP and UDP before it reaches the
CPU or the host behind it. It sits inline between a protected network and the internet like a bump in the
wire: frames enter one port and leave the other unchanged, except for the ones it decides to drop. State
is kept in the NIC data path (BPF maps), so unsolicited floods, such as SYN-ACK reflection or UDP
amplification, never reach the downstream host and never touch its conntrack table.

It runs on any XDP-capable NIC: Mellanox/NVIDIA ConnectX (`mlx5`), Intel (`ice`, `i40e`, `ixgbe`, `igb`,
`igc`), Broadcom (`bnxt`), and others. On drivers without native XDP it falls back to generic (SKB) mode.

## Architecture

```
  protected side                     box: two XDP-attached ports                     internet side
  (host / servers)                                                                   (upstream)

                       PORT_T  [xdp: TRUSTED]                    [xdp: UNTRUSTED]  PORT_U
   outbound  ────────────►  parse ─►  learn flow  ─►  redirect ───────────────────►  ──────────►
   (SYN, data, query)                     │            (DEVMAP)                        to internet
                                          v
                            ┌────────────────────────────────────────┐
                            │ shared, pinned BPF maps                │
                            │   l1cache       per-CPU L1 flow cache  │
                            │   flows         TCP flow state (LRU)   │
                            │   udp_flows     UDP flow state (LRU)   │
                            │   features      live policy + TTLs     │
                            │   server_allow  inbound allowlist      │
                            │   stats         per-CPU counters       │
                            └────────────────────────────────────────┘
                                          ^
   inbound   ◄──────────  redirect  ◄─  validate against flow  ◄─  parse  ◄──────────  ◄──────────
   (replies pass)                          │                                            from internet
                                           └─►  no match  ─►  XDP_DROP  (never reaches the host)
                                                            └─►  or RST ► source  (optional, reject_with_rst)
```

One BPF program is loaded twice, once per port, with a compile-time constant marking the port as trusted
or untrusted, so each side keeps only the branch it needs. Forwarding is done entirely in XDP: a frame is
redirected to the peer port through a `DEVMAP`, unmodified, so MAC addresses and VLAN tags pass through
untouched. Maps and links are pinned under `/sys/fs/bpf/xdpfilter`, so the data path survives a daemon
restart with no interruption and a binary upgrade swaps the program atomically.

## How it works

The trusted side is the only side that creates flow state. An outbound packet (from the protected
network) records or refreshes a flow; an inbound packet (from the internet) is checked against it:

- **TCP.** An outbound SYN opens a half-open flow and stores the client's ISN. An inbound SYN-ACK is
  forwarded only if it matches that flow and acknowledges `ISN + 1`; otherwise it is dropped. Out-of-state
  ACK, RST, FIN and data are dropped.
- **UDP.** An outbound datagram opens a short-lived flow; inbound UDP is forwarded only if it matches one.
  Unsolicited inbound UDP is dropped, which keeps floods and reflected replies off the host's conntrack.
- **Everything else** (ARP, IPv6, other L3) is forwarded transparently.

Because only the trusted side inserts entries, an off-path attacker cannot grow or exhaust the flow
tables: a spoofed packet is a lock-free lookup miss followed by `XDP_DROP`, with no allocation. Hosts
that should accept unsolicited inbound connections (a DNS resolver, a public service) are named in
`server_allow`.

Two modes: **monitor** counts what it would drop but forwards everything, and **enforce** actually drops.
Start in monitor, confirm only attack traffic is flagged, then switch.

### What it drops

Every drop is counted by reason (`xdpfilter status`, and `stats.txt`), so you can see exactly which
vector is being blocked:

| Attack / packet | Why it is dropped | Reason counter |
|---|---|---|
| **Unsolicited SYN-ACK flood** (reflection/amplification) | no matching outbound SYN | `unsolicited SYN-ACK` |
| **Forged SYN-ACK** guessing an open flow | ACK does not equal the stored `ISN + 1` | `bad ISN` |
| **Out-of-state ACK / data flood** | no live flow for the 4-tuple | `out-of-state in` |
| **Blind RST / FIN injection** | no live flow (in-state RSTs are also seq-validated by the host) | `out-of-state RST` |
| **Unsolicited inbound SYN** to a non-allowlisted host | not in `server_allow` (and per-source SYN rate limited) | `inbound SYN (no server)` |
| **Port scans** — null, XMAS, SYN+FIN, SYN+RST, FIN-without-ACK | illegal TCP flag combinations | `bad TCP flags` |
| **TCP fragment evasion** | non-first fragment can't be matched to a flow | `TCP fragment` |
| **UDP reflection / amplification** (DNS, NTP, memcached, …) | no outbound flow and not an allowlisted server | `unsolicited UDP` |
| **UDP fragment floods** (optional) | non-first UDP fragment, `drop_udp_frags` on | `UDP fragment` |
| **VLAN-stacking evasion** (optional) | more 802.1Q tags than inspected, `drop_vlan_deep` on | `excess VLAN tags` |
| **Malformed / truncated frames**, wrong IP version | headers do not parse | `malformed` |
| Flow-table exhaustion under flood | insert failed (observability, not itself an attack) | `flow-table full` |

With `reject_with_rst` on, enforced TCP drops on the untrusted port answer the source with a RST instead
of dropping silently (see [`reject_with_rst`](#reject_with_rst) below); the per-vector reason counters
still record what was rejected.

Reflected TCP RST and FIN carry a subtlety: the filter forwards in-state RST/FIN (the protected host
does its own RFC 5961 sequence validation), but it will **not** let a single spoofed RST/FIN quietly
demote a live connection to the short closing timeout — the flow is re-promoted to established as soon as
the host keeps talking, so a blind-RST does not shorten a long-lived idle connection's lifetime.

## Requirements

- A Linux kernel with multi-buffer XDP (`xdp.frags`): **5.18+**; developed and tested on 6.x/7.x.
- Two network ports to bridge.
- Runtime: `ethtool`, `iproute2`, `systemd` (declared by the package).

## Build

The BPF object is compiled with clang at build time and embedded in the binary, so the target needs no
compiler, headers, or BTF. The build host needs `clang`, `llvm`, `libbpf-dev`, `linux-libc-dev`, Go, and
[nfpm](https://github.com/goreleaser/nfpm).

```sh
make build              # bpf2go + static amd64 binary -> dist/xdpfilter
make deb VERSION=0.1.0  # Debian package -> xdpfilter_0.1.0_amd64.deb
make dev                # native-arch binary for the local test harness
```

The BPF object is compiled with `-mcpu=v3` (the alu32/jmp32 ISA, kernel 5.1+), which the 5.18 floor makes
unconditionally safe.

A fresh checkout must run `go generate ./...` (done by `make`) before a bare `go build`, since the
generated bindings are not committed.

## Install and set up

```sh
sudo apt install ./xdpfilter_0.1.0_amd64.deb
sudo xdpfilter setup
```

`setup` lists the interfaces with their probed XDP capability, blinks a port on request
(`ethtool --identify`), asks which two ports to bridge and for the policy, sizes the BPF maps from the
effective host/cgroup memory and possible CPU count, previews the resolved tuning, and offers to enable
the service on boot and start it. It defaults to monitor mode.

```sh
xdpfilter status                 # live counters, mode, occupancy
xdpfilter mode enforce           # start dropping, no reattach
xdpfilter manage                 # interactive dashboard and configuration console
cat /var/lib/xdp_stats/stats.txt
```

## Usage

| Command | Purpose |
|---|---|
| `xdpfilter setup` | first-run wizard: pick ports, policy, tuning; enable/start |
| `xdpfilter run` | start the systemd service |
| `xdpfilter stop [--detach]` | stop the service; `--detach` also removes the bridge |
| `xdpfilter status [--watch]` | live counters, occupancy, mode |
| `xdpfilter mode monitor\|enforce` | switch mode live |
| `xdpfilter reload` | re-read the config live (also happens automatically on edit) |
| `xdpfilter flows [--limit N] [--vlan V]` | sample the TCP and UDP flow tables |
| `xdpfilter manage [--config P]` | interactive live dashboard, configuration, flows, and operations |
| `xdpfilter tune [--dry-run]` | apply or preview the tuning profile |
| `xdpfilter check` | preflight: config, interfaces, bpffs, memlock, root |

### Interactive management console

Run `sudo xdpfilter manage` on a terminal locally or over SSH. The CGO-free
terminal interface exposes the live dashboard, policy and TTL switches,
allowlist CRUD, bounded flow browsing, every structural/runtime/tuning option,
and service operations. Changes are staged until **Ctrl-S** is pressed.

The Apply preview classifies changes by operational impact. Policy, TTL, mode,
and allowlist changes update the pinned BPF maps immediately. Flow-table sizes,
runtime intervals, and tuning require a service restart. Interface, XDP mode,
and pin-directory changes require a guarded detach/reattach and may briefly
interrupt forwarding. The Operations section places datapath detach and tuning
restore behind typed confirmations.

Allow a host behind the box to receive unsolicited inbound connections (for example a DNS resolver on
UDP 53). Edit the config and the daemon applies the change immediately, with no restart and no dropped
sessions:

```sh
# /etc/xdpfilter/config.yaml
allow_inbound_servers: true
server_allow:
  - 10.0.0.53:53      # covers TCP and UDP
```

```sh
sudo xdpfilter reload    # or just save the file; the daemon watches it
xdpfilter flows          # e.g.
# proto host                  internet              vid   state     age
# TCP   10.0.0.10:44163       93.184.216.34:443     0     EST       12s
# UDP   10.0.0.10:51900       1.1.1.1:53            0     UDP       1s
```

To admit inbound TCP connections to every protected IP and port, without changing UDP filtering, use
`allow_inbound_syn: true`. The global TCP switch and the selective allowlist are additive; the SYN
rate limits still apply to both paths.

## Configuration

`/etc/xdpfilter/config.yaml`, written by the wizard:

```yaml
trusted_iface: enp65s0f0        # faces the protected network
untrusted_iface: enp65s0f1      # faces the internet
mode: monitor                   # monitor | enforce
oos_strict: false               # false adopts flows already established when the box is inserted
allow_inbound_servers: false    # permit inbound SYN/UDP to allowlisted servers
allow_inbound_syn: false        # permit inbound TCP SYN to every protected IP and port
server_allow: []                # ["10.0.0.53:53", ...] — covers TCP and UDP
filter_udp: true                # stateful UDP filtering
drop_frags: true                # drop non-first TCP fragments
drop_bad_flags: true            # drop null / XMAS / SYN+FIN / SYN+RST / FIN-without-ACK
drop_udp_frags: false           # also drop non-first UDP fragments
drop_vlan_deep: false           # drop frames with more 802.1Q tags than are inspected (2)
reject_with_rst: false          # answer enforced inbound TCP drops with a RST to the source (see note below)
flow_monitoring:
  enabled: false                # sampled inbound per-flow PPS/Mbps monitoring
  sample_every: 64              # power of two; 1 counts every packet
  max_flows: 262144             # bounded sampled-flow LRU counter capacity
  cidrs:
    - cidr: 10.0.0.0/24         # protected IPv4 destinations; longest prefix wins
      pps_threshold: 100000     # 0 disables this metric
      mbps_threshold: 500       # decimal Mbit/s; 0 disables this metric
flow_max: 16777216              # concrete TCP capacity selected during setup
udp_flow_max: 4194304           # concrete UDP capacity selected during setup
l1_size: 65536                  # concrete per-CPU slots (power of two; 0 disables)
lru_percpu: false               # per-CPU LRU flow tables (no cross-CPU contention on insert)
ttl_syn: 10                     # seconds; ttl_est: 300; ttl_closing: 10; ttl_udp: 30
xdp_mode: native                # native | generic | auto (native, generic fallback)
tune: true                      # apply the tuning profile on start
tuning:
  ring_size: 0                  # 0 retains the driver's setting
  channels: 0                   # 0 derives one common CPU/hardware-capped count
  netdev_max_backlog: 0         # 0 retains the kernel setting
  netdev_budget: 0              # 0 retains the kernel setting
```

The wizard reserves a bounded portion of currently usable memory, accounts for fixed and per-CPU maps,
and divides the remaining estimate 4:1 between TCP and UDP. It uses cgroup ancestor limits when they are
tighter than host RAM; possible CPUs, rather than only online CPUs, are used for per-CPU map estimates.
The displayed byte costs are conservative planning estimates, not guaranteed kernel allocation sizes.
The selected numbers are written to YAML: later daemon starts do not silently resize structural maps.
Expert values entered in the wizard or YAML are preserved, and `lru_percpu` remains opt-in.

Policy fields (`mode`, `oos_strict`, `allow_inbound_servers`, `allow_inbound_syn`, `server_allow`,
`filter_udp`, `drop_frags`, `drop_bad_flags`, `drop_udp_frags`, `drop_vlan_deep`, `reject_with_rst`, the
TTLs) are applied live when the file changes — through inotify, `xdpfilter reload`, or
`systemctl reload xdpfilter`. Structural changes (interfaces, table sizes, `l1_size`, `lru_percpu`,
`xdp_mode`) need a restart, which re-adopts the pinned data path without dropping traffic.

Flow-monitoring enablement, sampling, CIDRs, and thresholds also reload live. Only
`flow_monitoring.max_flows` needs a service restart because it changes the BPF map capacity.
Monitoring runs exclusively on the untrusted-side XDP program and counts valid inbound IPv4 TCP/UDP
tuples before policy enforcement, including traffic later dropped or reported as a would-drop. The
disabled path returns before sampling or map lookups; when enabled, the default 1-in-64 sampler performs
CIDR and counter-map work for only the selected packets. Overlapping CIDRs use the most-specific rule,
and a flow is listed when either configured threshold is exceeded.

### `reject_with_rst`

Off by default. When on (and in enforce mode), an enforced TCP drop on the untrusted port is answered with
a RST sent back to the packet's source, instead of a silent drop — the same idea as an iptables
`REJECT --reject-with tcp-reset` rule, so the sender aborts instead of retransmitting. It only ever acts
on the internet-facing port; the trusted side never emits anything. Note that inbound source addresses can
be spoofed, so — like the iptables rule — the RST may be sent to an unrelated host. RSTs emitted show up
as `rst replies` in `xdpfilter status`.

## Tuning

When `tune` is set, the daemon applies a performance profile on start and snapshots the original values so
package removal restores them. It enables the BPF JIT, disables NUMA balancing, and per port turns VLAN
and LRO offload off (VLAN offload must be off for XDP to see the tag). Automatic channels use one common
count across both ports, capped by each NIC's advertised combined-channel maximum and its online,
process-allowed NUMA-local CPUs after reserving the housekeeping CPU. Explicit ring and channel requests
are clamped to advertised hardware maxima. Zero ring, backlog, and budget overrides retain the current
driver or kernel values because CPU/RAM alone cannot determine safe optimal values.

The profile also enables symmetric RSS so both directions of a flow land on the same queue index and
enables `rx_cqe_compress` on mlx5. It disables `irqbalance`, pins each port's queue IRQs to online local
cores, and sets the CPU governor to `performance`. Changes that require a reboot or firmware change (PCIe
relaxed ordering, SMT, C-states, IOMMU) are printed as recommendations, not applied.

## Statistics

Every 10 seconds the daemon writes `/var/lib/xdp_stats/stats.txt`: processed, redirected, dropped and
`l1 hits` totals, a breakdown of drops by reason (the table in [What it drops](#what-it-drops)), and a
per-VLAN table. Counters are per-CPU, so collection does not contend with the data path. A drop-rate spike
is flagged in the file and logged to the journal.

Independently, every second the daemon atomically replaces
`/var/lib/xdp_stats/flow_alerts.jsonl`. It is an NDJSON snapshot with one schema-versioned JSON object per
currently over-threshold flow and is empty when there are no current violations. Each line includes the
normalized protocol/protected/internet endpoint tuple, both VLAN IDs, estimated rates, thresholds,
matched CIDR, sample factor, window length, and UTC observation time. `xdpfilter manage` provides CIDR
rule editing and renders the same live snapshot in its **Flow Monitoring** section.


## License

Licensed under the GNU General Public License v2.0; see [LICENSE](LICENSE). The in-kernel BPF program is
declared `GPL` because the kernel requires it to use GPL-only helpers such as `bpf_redirect_map`.
