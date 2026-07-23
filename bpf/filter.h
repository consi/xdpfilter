/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xdpfilter — shared types & constants for the XDP data plane.
 *
 * This header is included by the BPF C program. bpf2go reads the compiled BTF
 * and generates matching Go types (filterFlowKey, filterFlowVal, ...), so the
 * layouts here are the single source of truth for both sides. Keep everything
 * explicitly sized and padded — no host-dependent types.
 */
#ifndef __XDPFILTER_FILTER_H
#define __XDPFILTER_FILTER_H

#include <linux/types.h> /* __u8/__u16/__u32/__be16/__be32 (from linux-libc-dev on the target) */

/* ---- L2/L3/L4 constants (defined locally so the program needs no <linux/if_ether.h> etc.) ---- */
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* TCP flag bits (byte 13 of the TCP header) */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#define MAX_VLAN_DEPTH 2 /* 802.1Q + one QinQ tag */
#define VLAN_VID_MASK 0x0FFF
#define IP_FRAG_OFF_MASK 0x1FFF /* the 13 fragment-offset bits of frag_off */

/*
 * Coarse-time unit. Instead of dividing ktime_ns by 1e9 per packet (a real
 * BPF_DIV64 on the hot path), we shift: 1 tick = 2^30 ns ≈ 1.073741824 s.
 * last_seen, now, and every ttl_* live in these ticks. The Go side converts
 * config seconds -> ticks (rounding up) and ticks -> seconds for display, using
 * the same shift.
 */
#define NOW_SHIFT 30

/* ---- flow-table key & value ---- */

/*
 * Direction-independent key. The program knows its port role at load time
 * (ROLE_TRUSTED rodata), so it always places the internet side and the
 * protected-host side in the same slots — an outbound SYN and its inbound
 * SYN-ACK therefore produce the identical key.
 *
 * vlans = (outer_vid << 12) | inner_vid, 0 == untagged. Including it isolates
 * identical 4-tuples that live on different customer VLANs.
 */
struct flow_key {
	__u32 inet_ip;   /* internet-side IPv4 (network byte order) */
	__u32 host_ip;   /* protected-side IPv4 (network byte order) */
	__u16 inet_port; /* internet-side TCP port (network byte order) */
	__u16 host_port; /* protected-side TCP port (network byte order) */
	__u32 vlans;     /* outer<<12 | inner */
} __attribute__((packed));

enum flow_state {
	ST_NONE = 0,
	ST_SYN_SENT,  /* outbound SYN seen, awaiting SYN-ACK */
	ST_SYN_RCVD,  /* inbound SYN to an allowlisted server (policy) */
	ST_EST,       /* handshake progressed / adopted */
	ST_CLOSING,   /* a FIN/RST was seen, draining */
	ST_UDP,       /* UDP pseudo-flow (outbound-initiated) */
};

/* flow_val.flags bits */
#define FL_ISN_VALID 0x01  /* client_isn is populated (outbound-initiated flow) */
#define FL_CLOSED_OUT 0x02 /* CLOSING was entered via an *outbound* FIN/RST (a
			    * locally-initiated close). An inbound RST/FIN leaves
			    * this clear, so the trusted side can re-promote a flow
			    * that was moved to CLOSING by a spoofed inbound close. */

struct flow_val {
	__u32 client_isn; /* ISN from the trusted-side SYN; SYN-ACK must ack isn+1 */
	__u32 last_seen;  /* coarse ticks (bpf_ktime_get_coarse_ns >> NOW_SHIFT) */
	__u8 state;       /* enum flow_state */
	__u8 flags;       /* FL_* */
	__u16 _pad;
};

/*
 * L1 flow cache entry — a per-CPU direct-mapped cache in front of the LRU flow
 * table. Established TCP (ST_EST) and UDP (ST_UDP) flows are hot at line rate;
 * a hit skips the LRU-hash lookup entirely. Populated only on authoritative
 * forward decisions, revalidated every coarse tick (see filter.bpf.c).
 */
struct l1_entry {
	struct flow_key key; /* 16B; the normalized flow key this slot caches */
	__u32 last_seen;     /* coarse tick this slot was last validated */
	__u8 state;          /* ST_EST or ST_UDP only */
	__u8 _pad[3];
};

/* ---- live-flippable policy (features map, single entry) ---- */

#define MODE_MONITOR 0 /* count would-drops, forward everything */
#define MODE_ENFORCE 1 /* actually drop */

#define OOS_ADOPT 0  /* outbound out-of-state -> adopt as ESTABLISHED (default) */
#define OOS_STRICT 1 /* outbound out-of-state -> drop */

struct features {
	__u8 mode;                  /* MODE_MONITOR | MODE_ENFORCE */
	__u8 oos_out_strict;        /* OOS_ADOPT | OOS_STRICT */
	__u8 allow_inbound_servers; /* 0/1 — permit inbound SYN/UDP to allowlisted servers */
	__u8 drop_frags;            /* 0/1 — drop non-first TCP fragments (default 1) */
	__u8 drop_bad_flags;        /* 0/1 — drop null/xmas/SYN+FIN/SYN+RST/FIN-no-ACK (default 1) */
	__u8 filter_udp;            /* 0/1 — stateful UDP filtering (default 1) */
	__u8 drop_vlan_deep;        /* 0/1 — drop frames with > MAX_VLAN_DEPTH tags (default 0) */
	__u8 drop_udp_frags;        /* 0/1 — drop non-first UDP fragments (default 0) */
	__u8 reject_with_rst;       /* 0/1 — untrusted side answers enforced TCP drops with a RST
	                             * to the source instead of a silent drop (default 0), like an
	                             * iptables REJECT --reject-with tcp-reset. The source may be
	                             * spoofed, so the RST can land on an unrelated host. */
	/* NOTE: ttl_* are in coarse ticks (NOW_SHIFT), not seconds — the loader
	 * converts config seconds -> ticks. */
	__u32 ttl_syn;              /* SYN_SENT / SYN_RCVD idle timeout */
	__u32 ttl_est;              /* ESTABLISHED idle timeout */
	__u32 ttl_closing;          /* CLOSING drain timeout */
	__u32 ttl_udp;              /* UDP pseudo-flow idle timeout */
};

/* ---- inbound-server allowlist ---- */
struct srv_key {
	__u32 ip;   /* network byte order */
	__u16 port; /* network byte order */
	__u16 _pad;
};

/* ---- per-source SYN token bucket (inbound-server policy only) ---- */
struct tbkt {
	__u64 tokens; /* fixed-point *1000 */
	__u64 ts_ns;
};

/* ---- drop reason codes (index into drop_reason PERCPU_ARRAY) ---- */
enum drop_reason {
	RSN_UNSOL_SYNACK = 0, /* the headline: inbound SYN-ACK with no matching outbound SYN */
	RSN_BAD_ISN,          /* inbound SYN-ACK matched a tuple but not the ISN */
	RSN_OOS_IN,           /* inbound ACK/data/FIN with no live flow */
	RSN_OOS_OUT,          /* outbound out-of-state and policy == strict */
	RSN_OOS_RST,          /* inbound RST with no live flow */
	RSN_INBOUND_SYN,      /* inbound lone SYN, not an allowlisted server */
	RSN_BAD_FLAGS,        /* null / xmas / SYN+FIN / SYN+RST */
	RSN_TCP_FRAG,         /* non-first TCP fragment */
	RSN_MALFORMED,        /* truncated / bad headers / bad IP version */
	RSN_UDP_OOS,          /* unsolicited inbound UDP (no outbound flow / not a server) */
	/* --- appended (keep existing indices stable for pinned-map/stats compat) --- */
	RSN_MAP_FAIL,         /* flow-state insert failed (LRU pressure / -ENOMEM) */
	RSN_VLAN_DEPTH,       /* more VLAN tags than MAX_VLAN_DEPTH (policy on) */
	RSN_UDP_FRAG,         /* non-first UDP fragment (policy on) */
	RSN__MAX,
};

/* ---- statistics (all PERCPU, summed in userspace) ---- */
struct stats_global {
	__u64 rx_pkts, rx_bytes;         /* every packet */
	__u64 redir_pkts, redir_bytes;   /* forwarded to peer port */
	__u64 drop_pkts, drop_bytes;     /* enforced drops */
	__u64 nonip_pkts, nonip_bytes;   /* non-IPv4 passed through */
	__u64 nontcp_pkts, nontcp_bytes; /* IPv4 non-TCP passed through */
	__u64 l1_hits;                   /* L1 flow-cache fast-path forwards */
	__u64 rst_pkts, rst_bytes;       /* reject_with_rst: RSTs reflected to the source */
};

struct vlan_stat {
	__u64 pkts, bytes, drops;
};

#endif /* __XDPFILTER_FILTER_H */
