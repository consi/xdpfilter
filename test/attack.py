#!/usr/bin/env python3
"""Inject spoofed / out-of-state / evasion-shaped traffic at the untrusted side
of the veth bridge, to prove the filter drops it.

usage: attack.py <iface> <dst_ip> [count] [kind] [opts...]

kinds:
  synack   (default) unsolicited SYN-ACK   — the headline: no matching outbound SYN
  ack                 out-of-state bare ACK
  rst                 out-of-state bare RST
  badflags            SYN+FIN               (null/xmas/SYN+FIN/SYN+RST family)
  finonly             FIN without ACK       — never legitimate
  frag                non-first TCP fragment
  udpfrag             non-first UDP fragment (for drop_udp_frags)
  vlandeep            triple-802.1Q-tagged IPv4/TCP (for drop_vlan_deep)
  rsttuple <sp> <dp>  a single RST for an *exact* 4-tuple (targeted teardown test)
  rstprobe <sub> <tags>  one out-of-state segment of kind <sub> (synack|ack|rst|
                      badflags|finonly) from a REAL source with <tags> (0/1/2)
                      VLAN tags, then sniff for the reflected RST (reject_with_rst).
                      Prints "rstprobe sub=K tags=N reply=RST|none [rst_tags=M ok=0|1]".

Each spoofed packet uses a random source (except rsttuple/rstprobe), so none
matches a real outbound SYN — the filter must drop them all (except in monitor
mode).
"""
import sys
from scapy.all import Ether, Dot1Q, IP, TCP, UDP, sendp, fragment, AsyncSniffer, raw

iface = sys.argv[1]
dst = sys.argv[2]
count = int(sys.argv[3]) if len(sys.argv) > 3 else 200
kind = sys.argv[4] if len(sys.argv) > 4 else "synack"


def count_vlan(p):
    n = 0
    while p.getlayer(Dot1Q, n + 1) is not None:
        n += 1
    return n


if kind == "rstprobe":
    # Send ONE out-of-state segment from a real, non-spoofed source (so the
    # reflected RST comes back to us) carrying `tags` VLAN tags, and sniff for the
    # RST the untrusted side should synthesize when reject_with_rst is on. The
    # sub-kind selects the drop vector (each maps to a different reason), so the
    # harness can confirm every enforced TCP drop yields a RST. Verifies both that
    # a RST is produced and that the encapsulation is preserved. Observation is
    # best-effort (some virtual NICs don't carry XDP_TX frames): always exits 0 —
    # the harness treats the `rst replies` counter as authoritative.
    sub = sys.argv[5] if len(sys.argv) > 5 else "ack"
    tags = int(sys.argv[6]) if len(sys.argv) > 6 else 0
    src = sys.argv[7] if len(sys.argv) > 7 else "10.0.0.3"
    sport, dport = 12345, 80
    subflags = {"synack": "SA", "ack": "A", "rst": "R", "badflags": "SF", "finonly": "F"}
    if sub not in subflags:
        raise SystemExit("unknown rstprobe sub-kind %r" % sub)
    l2 = Ether()
    for v in [10, 20][:tags]:
        l2 = l2 / Dot1Q(vlan=v)
    probe = l2 / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                            flags=subflags[sub], seq=1000, ack=2000)

    def is_reflected_rst(p):
        return (p.haslayer(TCP) and (int(p[TCP].flags) & 0x04) and
                p[TCP].sport == dport and p[TCP].dport == sport and
                p.haslayer(IP) and p[IP].src == dst and p[IP].dst == src)

    snf = AsyncSniffer(iface=iface, lfilter=is_reflected_rst, count=1, timeout=3)
    snf.start()
    sendp(probe, iface=iface, verbose=False)
    snf.join()
    if snf.results:
        rp = snf.results[0]
        rt = count_vlan(rp)
        # validate the reflected checksums: clear them, let scapy recompute, compare
        ipc, tcpc = rp[IP].chksum, rp[TCP].chksum
        chk = rp.copy()
        del chk[IP].chksum
        del chk[TCP].chksum
        chk = Ether(raw(chk))
        cok = int(ipc == chk[IP].chksum and tcpc == chk[TCP].chksum)
        print("rstprobe sub=%s tags=%d reply=RST rst_tags=%d ok=%d cksum=%d" %
              (sub, tags, rt, int(rt == tags), cok))
    else:
        print("rstprobe sub=%s tags=%d reply=none" % (sub, tags))
    sys.exit(0)


def mk(i):
    src = "203.0.113.%d" % (i % 254 + 1)
    ip = IP(src=src, dst=dst)
    if kind == "synack":
        return Ether() / ip / TCP(sport=1024 + i, dport=80, flags="SA", seq=i, ack=i + 12345)
    if kind == "ack":
        return Ether() / ip / TCP(sport=1024 + i, dport=80, flags="A", seq=i, ack=i)
    if kind == "rst":
        return Ether() / ip / TCP(sport=1024 + i, dport=80, flags="R", seq=i)
    if kind == "badflags":  # SYN+FIN
        return Ether() / ip / TCP(sport=1024 + i, dport=80, flags="SF", seq=i)
    if kind == "finonly":  # FIN with no ACK bit — illegitimate
        return Ether() / ip / TCP(sport=1024 + i, dport=80, flags="F", seq=i)
    if kind == "frag":  # non-first fragment of a TCP datagram
        pkt = ip / TCP(sport=1024 + i, dport=80, flags="A") / ("x" * 64)
        return Ether() / fragment(pkt, fragsize=16)[-1]
    if kind == "udpfrag":  # non-first fragment of a UDP datagram
        pkt = ip / UDP(sport=1024 + i, dport=9999) / ("x" * 64)
        return Ether() / fragment(pkt, fragsize=16)[-1]
    if kind == "vlandeep":  # 3 stacked VLAN tags — deeper than the filter parses
        return (Ether() / Dot1Q(vlan=10) / Dot1Q(vlan=20) / Dot1Q(vlan=30) /
                ip / TCP(sport=1024 + i, dport=80, flags="A", seq=i))
    if kind == "rsttuple":  # one RST for an exact tuple: attack.py <if> <dst> 1 rsttuple <sp> <dp> [src]
        sp = int(sys.argv[5])
        dp = int(sys.argv[6])
        s = sys.argv[7] if len(sys.argv) > 7 else "10.0.0.3"
        return Ether() / IP(src=s, dst=dst) / TCP(sport=sp, dport=dp, flags="R", seq=1000 + i)
    raise SystemExit("unknown kind %r" % kind)


pkts = [mk(i) for i in range(count)]
sendp(pkts, iface=iface, verbose=False)
print("sent %d %s packets to %s via %s" % (count, kind, dst, iface))
