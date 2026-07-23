// SPDX-License-Identifier: GPL-2.0
/*
 * xdpfilter — transparent bump-in-the-wire XDP TCP filter.
 *
 * Author: Marek Wajdzik <marek@jest.pro>  (C) 2026
 *
 * One source, loaded twice (once per port) with different rodata (ROLE_TRUSTED,
 * PEER_IDX). Both instances share every map. The trusted side is the only side
 * that creates flow state; the untrusted side validates inbound packets against
 * it and drops anything out-of-state — so a spoofed SYN-ACK / ACK / RST flood is
 * a lockless lookup miss -> XDP_DROP that never allocates and never reaches the
 * protected host.
 *
 * Forwarding is pure XDP: legitimate frames are redirected to the peer port via
 * a DEVMAP, unmodified, so MAC + VLAN tags pass through and the box stays L2
 * transparent.
 *
 * Hot path: established flows (the line-rate case) are served from a per-CPU
 * direct-mapped L1 cache (see l1cache / L1_MASK) that skips the shared LRU-hash
 * lookup entirely. Symmetric-XOR RSS + IRQ-to-core pinning (applied by the Go
 * tuner) keeps a flow's packets on one CPU, which is what makes per-CPU caching
 * effective.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "filter.h"

char _license[] SEC("license") = "GPL";

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* ---- per-load specialization (rewritten by the Go loader before load) ---- */
volatile const __u8 ROLE_TRUSTED = 1;  /* 1 on the protected-side port, 0 on internet-side */
volatile const __u32 PEER_IDX = 0;     /* tx_ports index of the *other* port */
volatile const __u32 L1_MASK = 0;      /* l1cache size-1 (power-of-two); 0 disables the L1 fast path */
volatile const __u8 MULTIBUF = 0;      /* 1 => use bpf_xdp_get_buff_len for byte accounting (jumbo/multi-buf) */

/* ---- on-wire headers (self-contained; avoids <linux/ip.h> bitfield quirks) ---- */
struct ethhdr {
	__u8 dest[ETH_ALEN];
	__u8 source[ETH_ALEN];
	__be16 h_proto;
};

struct vlan_hdr {
	__be16 tci;          /* PCP(3) | DEI(1) | VID(12) */
	__be16 encap_proto;
};

struct iphdr_min {
	__u8 ver_ihl;        /* version(4) | ihl(4) */
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;     /* flags(3) | fragment offset(13) */
	__u8 ttl;
	__u8 protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
};

struct tcphdr_min {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u8 doff_res;       /* data offset(4) | reserved(4) */
	__u8 flags;          /* CWR ECE URG ACK PSH RST SYN FIN */
	__be16 window;
	__be16 check;
	__be16 urg_ptr;
};

struct udphdr_min {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
};

/* ---- maps ---- */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH); /* common (global) LRU: lookups are lockless RCU */
	__type(key, struct flow_key);
	__type(value, struct flow_val);
	__uint(max_entries, 1 << 20);        /* default; Go overrides from config.flow_max */
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH); /* UDP pseudo-flows; only trusted side inserts */
	__type(key, struct flow_key);
	__type(value, struct flow_val);
	__uint(max_entries, 1 << 20);        /* default; Go overrides from config.udp_flow_max */
} udp_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); /* per-CPU L1 flow cache (direct-mapped) */
	__type(key, __u32);
	__type(value, struct l1_entry);
	__uint(max_entries, 1 << 16);        /* default; Go overrides from config.l1_size (1 if disabled) */
} l1cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 2);
} tx_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct features);
	__uint(max_entries, 1);
} features SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct srv_key);
	__type(value, __u8);
	__uint(max_entries, 1024);
} server_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct tbkt);
	__uint(max_entries, 1 << 16);
} synbkt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, RSN__MAX);
} drop_reason SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct stats_global);
	__uint(max_entries, 1);
} stats_global SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct vlan_stat);
	__uint(max_entries, 4096);
} stats_vlan SEC(".maps");

/* ---- small helpers ---- */
#define ACT_FORWARD (-1)

/* coarse time in NOW_SHIFT-ticks (>>30 ≈ 1.07s) — avoids a per-packet 64-bit div */
static __always_inline __u32 now_tick(void)
{
	return (__u32)(bpf_ktime_get_coarse_ns() >> NOW_SHIFT);
}

static __always_inline struct features *get_features(void)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(&features, &z);
}

static __always_inline void stat_reason(__u32 reason)
{
	__u64 *c = bpf_map_lookup_elem(&drop_reason, &reason);
	if (c)
		(*c)++;
}

static __always_inline struct stats_global *sg(void)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(&stats_global, &z);
}

/* resolve the per-VLAN stats slot once; callers mutate through the pointer so a
 * packet touches this map at most once (rx accounting + a possible drop reuse it) */
static __always_inline struct vlan_stat *stat_vlan_ptr(__u32 vid)
{
	if (vid > 4095)
		vid = 0;
	return bpf_map_lookup_elem(&stats_vlan, &vid);
}

/* ttl for a state, in NOW_SHIFT-ticks */
static __always_inline __u32 ttl_for(const struct features *f, __u8 state)
{
	if (state == ST_EST)
		return f->ttl_est;
	if (state == ST_CLOSING)
		return f->ttl_closing;
	if (state == ST_UDP)
		return f->ttl_udp;
	return f->ttl_syn; /* SYN_SENT / SYN_RCVD */
}

static __always_inline int expired(const struct features *f, const struct flow_val *v, __u32 now)
{
	__u32 ttl = ttl_for(f, v->state);
	if (now < v->last_seen) /* cross-CPU/clock skew wrote a newer stamp: treat as fresh */
		return 0;
	return (now - v->last_seen) > ttl;
}

static __always_inline int bad_flags(__u8 flags)
{
	if (flags == 0) /* null scan */
		return 1;
	if ((flags & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN))
		return 1;
	if ((flags & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST))
		return 1;
	if ((flags & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG)) /* xmas */
		return 1;
	if ((flags & (TCP_FIN | TCP_ACK)) == TCP_FIN) /* FIN without ACK — never legitimate */
		return 1;
	return 0;
}

/* refresh last_seen only when the coarse tick changed — avoids dirtying the
 * flow's cache line on every packet of a busy connection */
static __always_inline void touch(struct flow_val *v, __u32 now)
{
	if (v->last_seen != now)
		v->last_seen = now;
}

static __always_inline int flow_key_eq(const struct flow_key *a, const struct flow_key *b)
{
	/* field-by-field: every member is naturally aligned, so this is five
	 * aligned scalar compares (no unaligned 16B load on the packed struct) */
	return a->inet_ip == b->inet_ip &&
	       a->host_ip == b->host_ip &&
	       a->inet_port == b->inet_port &&
	       a->host_port == b->host_port &&
	       a->vlans == b->vlans;
}

/* Murmur3 32-bit finalizer — spreads the folded 4-tuple across the L1 index */
static __always_inline __u32 fmix32(__u32 h)
{
	h ^= h >> 16;
	h *= 0x85ebca6bU;
	h ^= h >> 13;
	h *= 0xc2b2ae35U;
	h ^= h >> 16;
	return h;
}

static __always_inline __u32 l1_index(const struct flow_key *k)
{
	__u32 h = k->inet_ip ^ k->host_ip ^ k->vlans ^
		  (((__u32)k->inet_port << 16) | (__u32)k->host_port);
	return fmix32(h) & L1_MASK;
}

/* L1 lookup: hit iff the slot holds this exact key, was validated this tick, and
 * caches the expected state (ST_EST for TCP / ST_UDP for UDP). Returns the slot
 * pointer (for write-through on the miss/populate path) via *slot. */
static __always_inline int l1_hit(__u32 idx, const struct flow_key *k, __u8 want_state,
				   __u32 now, struct l1_entry **slot)
{
	struct l1_entry *e = bpf_map_lookup_elem(&l1cache, &idx);
	*slot = e;
	if (e && e->last_seen == now && e->state == want_state && flow_key_eq(&e->key, k))
		return 1;
	return 0;
}

/* write-through: cache an authoritative EST/UDP forward for this tick */
static __always_inline void l1_put(struct l1_entry *slot, const struct flow_key *k,
				   __u8 state, __u32 now)
{
	if (!slot)
		return;
	slot->key = *k;
	slot->last_seen = now;
	slot->state = state;
}

/* ---- outbound: trusted -> internet. This side owns state creation. ----
 * *cache_st is set to ST_EST when the forward decision is L1-cacheable. */
static __always_inline int handle_outbound(const struct features *f, struct flow_key *k,
					   __u8 flags, __u32 seq, __u32 now, __u8 *cache_st)
{
	struct flow_val *v = bpf_map_lookup_elem(&flows, k);

	if ((flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) { /* lone SYN */
		if (!v) {
			struct flow_val nv = {};
			nv.state = ST_SYN_SENT;
			nv.client_isn = seq;
			nv.flags = FL_ISN_VALID;
			nv.last_seen = now;
			if (bpf_map_update_elem(&flows, k, &nv, BPF_ANY))
				stat_reason(RSN_MAP_FAIL);
		} else {
			/* tuple reuse or SYN retransmit: reset the authoritative state to
			 * THIS handshake so the matching SYN-ACK validates against the new
			 * ISN, and a reused CLOSING/expired slot doesn't inherit stale state.
			 * FL_ISN_VALID assignment also clears FL_CLOSED_OUT. */
			v->state = ST_SYN_SENT;
			v->client_isn = seq;
			v->flags = FL_ISN_VALID;
			touch(v, now);
		}
		return ACT_FORWARD;
	}

	if (flags & TCP_RST) {
		if (v) {
			v->state = ST_CLOSING;
			v->flags |= FL_CLOSED_OUT; /* locally-initiated close */
			touch(v, now);
		}
		return ACT_FORWARD;
	}

	if (v && !expired(f, v, now)) {
		if (flags & TCP_FIN) {
			v->state = ST_CLOSING;
			v->flags |= FL_CLOSED_OUT;
		} else if (v->state == ST_CLOSING) {
			/* re-promote only if the close was NOT locally initiated — i.e. a
			 * spoofed inbound RST/FIN moved us to CLOSING but the host keeps
			 * talking. Our own FIN/RST (FL_CLOSED_OUT) keeps it draining. */
			if (!(v->flags & FL_CLOSED_OUT)) {
				v->state = ST_EST;
				*cache_st = ST_EST;
			}
		} else {
			v->state = ST_EST; /* ACK/data/SYN-ACK promotes */
			*cache_st = ST_EST;
		}
		touch(v, now);
		return ACT_FORWARD;
	}

	/* out-of-state outbound (no match or expired) */
	if (f->oos_out_strict)
		return RSN_OOS_OUT;

	/* adopt: the trusted side is inserted into a live network */
	{
		struct flow_val nv = {};
		nv.state = ST_EST;
		nv.last_seen = now;
		if (bpf_map_update_elem(&flows, k, &nv, BPF_ANY))
			stat_reason(RSN_MAP_FAIL);
	}
	*cache_st = ST_EST;
	return ACT_FORWARD;
}

/* per-source SYN rate limit for the inbound-server path (policy on only) */
static __always_inline int syn_token_ok(__u32 src_ip)
{
	/* ~50 SYN/s, burst 100, fixed-point *1000 */
	const __u64 rate = 50, burst = 100 * 1000ULL;
	struct tbkt *b = bpf_map_lookup_elem(&synbkt, &src_ip);
	__u64 tnow = bpf_ktime_get_coarse_ns();

	if (!b) {
		struct tbkt nb = { .tokens = burst - 1000, .ts_ns = tnow };
		bpf_map_update_elem(&synbkt, &src_ip, &nb, BPF_ANY);
		return 1;
	}
	{
		/* guard cross-CPU clock skew: a negative delta must not refill */
		__u64 elapsed = (tnow >= b->ts_ns) ? (tnow - b->ts_ns) : 0;
		__u64 add = (elapsed * rate) / 1000000ULL; /* ns -> tokens*1000 */
		__u64 tok = b->tokens + add;
		if (tok > burst)
			tok = burst;
		b->ts_ns = tnow;
		if (tok < 1000) {
			b->tokens = tok;
			return 0;
		}
		b->tokens = tok - 1000;
		return 1;
	}
}

/* ---- inbound: internet -> trusted. Validate only; never insert unless the
 * inbound-server policy is on and the target is allowlisted. ----
 * *cache_st is set to ST_EST when the forward decision is L1-cacheable. */
static __always_inline int handle_inbound(const struct features *f, struct flow_key *k,
					  __u8 flags, __u32 ack_seq, __u32 now, __u8 *cache_st)
{
	struct flow_val *v = bpf_map_lookup_elem(&flows, k);
	int live = v && !expired(f, v, now);

	if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) { /* SYN-ACK — the headline */
		if (!live)
			return RSN_UNSOL_SYNACK;
		if (v->state == ST_SYN_SENT) {
			if (!(v->flags & FL_ISN_VALID) || ack_seq != v->client_isn + 1)
				return RSN_BAD_ISN;
			v->state = ST_EST;
		}
		touch(v, now);
		return ACT_FORWARD;
	}

	if ((flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) { /* inbound lone SYN (to a server) */
		if (!f->allow_inbound_servers)
			return RSN_INBOUND_SYN;
		{
			struct srv_key sk = { .ip = k->host_ip, .port = k->host_port };
			if (!bpf_map_lookup_elem(&server_allow, &sk))
				return RSN_INBOUND_SYN;
		}
		if (!syn_token_ok(k->inet_ip))
			return RSN_INBOUND_SYN;
		/* reset a fresh SYN_RCVD only over an absent / expired / closing slot;
		 * a live SYN_SENT/EST/SYN_RCVD is left intact so a spoofed inbound SYN
		 * on a live tuple can't clobber an in-flight handshake's ISN state. */
		if (!v || expired(f, v, now) || v->state == ST_CLOSING) {
			struct flow_val nv = {};
			nv.state = ST_SYN_RCVD;
			nv.last_seen = now;
			if (bpf_map_update_elem(&flows, k, &nv, BPF_ANY))
				stat_reason(RSN_MAP_FAIL);
		} else {
			touch(v, now);
		}
		return ACT_FORWARD;
	}

	if (flags & TCP_RST) {
		if (!live)
			return RSN_OOS_RST;
		v->state = ST_CLOSING; /* inbound close: no FL_CLOSED_OUT (may be spoofed) */
		touch(v, now);
		return ACT_FORWARD;
	}

	/* ACK / data / FIN */
	if (!live)
		return RSN_OOS_IN;
	if (flags & TCP_FIN)
		v->state = ST_CLOSING; /* inbound-initiated close */
	else if (v->state == ST_SYN_RCVD)
		v->state = ST_EST;
	touch(v, now);
	if (v->state == ST_EST) /* pure ACK/data on an established flow — cacheable */
		*cache_st = ST_EST;
	return ACT_FORWARD;
}

/* ---- UDP: outbound opens a pseudo-flow; inbound must match one (or target an
 * allowlisted server). This keeps unsolicited UDP off the destination host —
 * and out of its conntrack table. ---- */
static __always_inline int handle_outbound_udp(struct flow_key *k, __u32 now, __u8 *cache_st)
{
	struct flow_val *v = bpf_map_lookup_elem(&udp_flows, k);
	if (!v) {
		struct flow_val nv = {};
		nv.state = ST_UDP;
		nv.last_seen = now;
		if (bpf_map_update_elem(&udp_flows, k, &nv, BPF_ANY))
			stat_reason(RSN_MAP_FAIL);
	} else {
		touch(v, now);
	}
	*cache_st = ST_UDP;
	return ACT_FORWARD;
}

static __always_inline int handle_inbound_udp(const struct features *f, struct flow_key *k,
					      __u32 now, __u8 *cache_st)
{
	struct flow_val *v = bpf_map_lookup_elem(&udp_flows, k);
	if (v && !expired(f, v, now)) {
		touch(v, now);
		*cache_st = ST_UDP;
		return ACT_FORWARD;
	}
	if (f->allow_inbound_servers) {
		struct srv_key sk = { .ip = k->host_ip, .port = k->host_port };
		if (bpf_map_lookup_elem(&server_allow, &sk))
			return ACT_FORWARD; /* allowlisted UDP server; no state, not cached */
	}
	return RSN_UDP_OOS;
}

static __always_inline int do_forward(struct stats_global *g, __u64 len)
{
	if (g) {
		g->redir_pkts++;
		g->redir_bytes += len;
	}
	return bpf_redirect_map(&tx_ports, PEER_IDX, 0);
}

static __always_inline int do_drop(const struct features *f, struct stats_global *g,
				   struct vlan_stat *vs, __u32 reason, __u64 len)
{
	stat_reason(reason);
	if (f->mode == MODE_ENFORCE) {
		if (g) {
			g->drop_pkts++;
			g->drop_bytes += len;
		}
		if (vs)
			vs->drops++;
		return XDP_DROP;
	}
	/* monitor: forward anyway, but the reason counter recorded the would-drop */
	return do_forward(g, len);
}

SEC("xdp.frags")
int xdp_filter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u64 len = data_end - data;
	__u32 now = now_tick();
	__u32 outer_vid = 0, inner_vid = 0;
	int vlan_trunc = 0;

	struct features *f = get_features();
	if (!f) /* control plane not ready — forward, stay transparent (never black-hole) */
		return bpf_redirect_map(&tx_ports, PEER_IDX, 0);

	struct stats_global *g = sg(); /* one lookup, threaded through every path */

	/* full frame length for accounting (multi-buffer frames span >1 buffer) */
	if (MULTIBUF)
		len = bpf_xdp_get_buff_len(ctx);

	/* ethernet */
	struct ethhdr *eth = data;
	if (unlikely((void *)(eth + 1) > data_end)) {
		struct vlan_stat *vs0 = stat_vlan_ptr(0);
		if (g) { g->rx_pkts++; g->rx_bytes += len; }
		if (vs0) { vs0->pkts++; vs0->bytes += len; }
		return do_drop(f, g, vs0, RSN_MALFORMED, len);
	}
	__be16 proto = eth->h_proto;
	void *cur = eth + 1;

	/* up to two VLAN tags */
#pragma unroll
	for (int i = 0; i < MAX_VLAN_DEPTH; i++) {
		if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
			break;
		struct vlan_hdr *vh = cur;
		if ((void *)(vh + 1) > data_end) {
			vlan_trunc = 1;
			break;
		}
		__u16 vid = bpf_ntohs(vh->tci) & VLAN_VID_MASK;
		if (i == 0)
			outer_vid = vid;
		else
			inner_vid = vid;
		proto = vh->encap_proto;
		cur = vh + 1;
	}

	/* rx accounting (every packet, keyed by outer VID); vs is reused on drop */
	struct vlan_stat *vs = stat_vlan_ptr(outer_vid);
	if (g) { g->rx_pkts++; g->rx_bytes += len; }
	if (vs) { vs->pkts++; vs->bytes += len; }

	/* a truncated VLAN tag is a runt we can't parse */
	if (unlikely(vlan_trunc))
		return do_drop(f, g, vs, RSN_MALFORMED, len);

	/* more VLAN tags than MAX_VLAN_DEPTH — L3/L4 is unreachable, so this frame
	 * bypasses all inspection. Policy decides drop vs. transparent forward. */
	if (unlikely(proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD))) {
		if (f->drop_vlan_deep)
			return do_drop(f, g, vs, RSN_VLAN_DEPTH, len);
		if (g) { g->nonip_pkts++; g->nonip_bytes += len; }
		return do_forward(g, len);
	}

	if (proto != bpf_htons(ETH_P_IP)) {
		/* ARP, IPv6, LLDP, STP, ... — forward transparently */
		if (g) { g->nonip_pkts++; g->nonip_bytes += len; }
		return do_forward(g, len);
	}

	/* IPv4 */
	struct iphdr_min *ip = cur;
	if (unlikely((void *)(ip + 1) > data_end))
		return do_drop(f, g, vs, RSN_MALFORMED, len);
	if (unlikely((ip->ver_ihl >> 4) != 4)) /* ethertype says IPv4 but version nibble disagrees */
		return do_drop(f, g, vs, RSN_MALFORMED, len);
	__u32 ihl = (ip->ver_ihl & 0x0F) * 4;
	if (unlikely(ihl < sizeof(*ip)))
		return do_drop(f, g, vs, RSN_MALFORMED, len);
	void *l4 = (void *)ip + ihl;
	if (unlikely(l4 > data_end))
		return do_drop(f, g, vs, RSN_MALFORMED, len);

	/* TCP first: it is the dominant, filtered protocol */
	if (likely(ip->protocol == IPPROTO_TCP)) {
		/* non-first fragment of a TCP datagram (evasion-shaped) */
		if (unlikely(ip->frag_off & bpf_htons(IP_FRAG_OFF_MASK))) {
			if (f->drop_frags)
				return do_drop(f, g, vs, RSN_TCP_FRAG, len);
			return do_forward(g, len);
		}

		struct tcphdr_min *tcp = l4;
		if (unlikely((void *)(tcp + 1) > data_end))
			return do_drop(f, g, vs, RSN_MALFORMED, len);
		__u8 flags = tcp->flags;

		if (f->drop_bad_flags && unlikely(bad_flags(flags)))
			return do_drop(f, g, vs, RSN_BAD_FLAGS, len);

		/* normalized, direction-independent key */
		struct flow_key k = {};
		k.vlans = ((__u32)outer_vid << 12) | inner_vid;
		if (ROLE_TRUSTED) {
			k.host_ip = ip->saddr;
			k.inet_ip = ip->daddr;
			k.host_port = tcp->source;
			k.inet_port = tcp->dest;
		} else {
			k.inet_ip = ip->saddr;
			k.host_ip = ip->daddr;
			k.inet_port = tcp->source;
			k.host_port = tcp->dest;
		}

		/* L1 fast path: pure ACK/data (no SYN/FIN/RST) on an established flow.
		 * The ACK requirement also excludes null-scans. */
		__u32 l1_idx = 0;
		struct l1_entry *slot = NULL;
		int l1_ok = L1_MASK && ((flags & (TCP_SYN | TCP_FIN | TCP_RST)) == 0) &&
			    (flags & TCP_ACK);
		if (l1_ok) {
			l1_idx = l1_index(&k);
			if (l1_hit(l1_idx, &k, ST_EST, now, &slot)) {
				if (g)
					g->l1_hits++;
				return do_forward(g, len);
			}
		}

		__u8 cache_st = 0;
		int r;
		if (ROLE_TRUSTED)
			r = handle_outbound(f, &k, flags, bpf_ntohl(tcp->seq), now, &cache_st);
		else
			r = handle_inbound(f, &k, flags, bpf_ntohl(tcp->ack_seq), now, &cache_st);

		if (r == ACT_FORWARD) {
			if (l1_ok && cache_st == ST_EST)
				l1_put(slot, &k, ST_EST, now);
			return do_forward(g, len);
		}
		return do_drop(f, g, vs, (__u32)r, len);
	}

	/* UDP: stateful reply-only filtering (protect the destination's conntrack) */
	if (ip->protocol == IPPROTO_UDP && f->filter_udp) {
		/* a non-first fragment has no L4 ports — can't key it; policy decides */
		if (unlikely(ip->frag_off & bpf_htons(IP_FRAG_OFF_MASK))) {
			if (f->drop_udp_frags)
				return do_drop(f, g, vs, RSN_UDP_FRAG, len);
			return do_forward(g, len);
		}
		struct udphdr_min *udp = l4;
		if (unlikely((void *)(udp + 1) > data_end))
			return do_drop(f, g, vs, RSN_MALFORMED, len);
		struct flow_key uk = {};
		uk.vlans = ((__u32)outer_vid << 12) | inner_vid;
		if (ROLE_TRUSTED) {
			uk.host_ip = ip->saddr;
			uk.inet_ip = ip->daddr;
			uk.host_port = udp->source;
			uk.inet_port = udp->dest;
		} else {
			uk.inet_ip = ip->saddr;
			uk.host_ip = ip->daddr;
			uk.inet_port = udp->source;
			uk.host_port = udp->dest;
		}

		/* L1 fast path for established UDP pseudo-flows */
		__u32 l1_idx = 0;
		struct l1_entry *slot = NULL;
		if (L1_MASK) {
			l1_idx = l1_index(&uk);
			if (l1_hit(l1_idx, &uk, ST_UDP, now, &slot)) {
				if (g)
					g->l1_hits++;
				return do_forward(g, len);
			}
		}

		__u8 cache_st = 0;
		int ur = ROLE_TRUSTED ? handle_outbound_udp(&uk, now, &cache_st)
				      : handle_inbound_udp(f, &uk, now, &cache_st);
		if (ur == ACT_FORWARD) {
			if (L1_MASK && cache_st == ST_UDP)
				l1_put(slot, &uk, ST_UDP, now);
			return do_forward(g, len);
		}
		return do_drop(f, g, vs, (__u32)ur, len);
	}

	/* IPv4 non-TCP (and UDP with filtering off) — forward transparently */
	if (g) { g->nontcp_pkts++; g->nontcp_bytes += len; }
	return do_forward(g, len);
}
