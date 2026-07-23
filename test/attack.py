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

Each spoofed packet uses a random source (except rsttuple), so none matches a
real outbound SYN — the filter must drop them all (except in monitor mode).
"""
import sys
from scapy.all import Ether, Dot1Q, IP, TCP, UDP, sendp, fragment

iface = sys.argv[1]
dst = sys.argv[2]
count = int(sys.argv[3]) if len(sys.argv) > 3 else 200
kind = sys.argv[4] if len(sys.argv) > 4 else "synack"


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
