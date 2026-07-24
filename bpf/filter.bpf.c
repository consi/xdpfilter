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

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* ---- per-load specialization (rewritten by the Go loader before load) ---- */
volatile const __u8 ROLE_TRUSTED = 1;  /* 1 on the protected-side port, 0 on internet-side */
volatile const __u32 PEER_IDX = 0;     /* tx_ports index of the *other* port */
volatile const __u32 L1_MASK = 0;      /* l1cache size-1 (power-of-two); 0 disables the L1 fast path */
volatile const __u8 MULTIBUF = 0;      /* 1 => use bpf_xdp_get_buff_len for byte accounting (jumbo/multi-buf) */

/* Mutable at runtime through the collection's mmapable data maps. Disabled
 * monitoring returns before the PRNG helper or either monitoring map lookup. */
volatile __u32 FLOW_MONITOR_ENABLED;
volatile __u32 FLOW_MONITOR_SAMPLE_MASK = 63; /* sample_every-1 */

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
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct flow_cidr_key);
	__type(value, __u8);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} flow_monitor_cidrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_monitor_key);
	__type(value, struct flow_counter);
	__uint(max_entries, 1 << 18); /* Go overrides from flow_monitoring.max_flows */
} flow_monitor_counters SEC(".maps");

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

_Static_assert(sizeof(struct flow_key) == 16, "flow_key must remain exactly 16 bytes");

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

/* Account a small random sample of inbound TCP/UDP packets. Callers invoke this
 * only after their already-required port-role check selected the untrusted
 * side. Only the sampled 1/N packets touch the LPM and shared LRU maps. */
static __always_inline void monitor_flow(const struct flow_key *k, __u8 protocol, __u64 len)
{
	if (!FLOW_MONITOR_ENABLED)
		return;
	if (bpf_get_prandom_u32() & FLOW_MONITOR_SAMPLE_MASK)
		return;

	struct flow_cidr_key ck = {
		.prefixlen = 32,
		.addr = k->host_ip,
	};
	__u8 *matched = bpf_map_lookup_elem(&flow_monitor_cidrs, &ck);
	if (!matched)
		return;

	struct flow_monitor_key mk = {.flow = *k, .protocol = protocol};
	struct flow_counter *v = bpf_map_lookup_elem(&flow_monitor_counters, &mk);
	if (v) {
		__sync_fetch_and_add(&v->packets, 1);
		__sync_fetch_and_add(&v->bytes, len);
		return;
	}
	struct flow_counter fresh = {.packets = 1, .bytes = len};
	if (bpf_map_update_elem(&flow_monitor_counters, &mk, &fresh, BPF_NOEXIST)) {
		/* A racing CPU may have inserted the same tuple. Preserve this sample. */
		v = bpf_map_lookup_elem(&flow_monitor_counters, &mk);
		if (v) {
			__sync_fetch_and_add(&v->packets, 1);
			__sync_fetch_and_add(&v->bytes, len);
		}
	}
}

static __noinline void stat_reason(__u32 reason)
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
	__u64 a0, a1, b0, b1;

	/* l1_entry.key is at offset zero in an 8-aligned map value and callers
	 * declare stack keys aligned(8). Copying into scalar words is alias-safe
	 * and lets LLVM lower the packed key to aligned u64 loads; builtin memcmp
	 * itself must not be used because its ordering semantics induce byte loads. */
	a = __builtin_assume_aligned(a, 8);
	b = __builtin_assume_aligned(b, 8);
	__builtin_memcpy(&a0, a, sizeof(a0));
	__builtin_memcpy(&a1, (const char *)a + sizeof(a0), sizeof(a1));
	__builtin_memcpy(&b0, b, sizeof(b0));
	__builtin_memcpy(&b1, (const char *)b + sizeof(b0), sizeof(b1));
	return a0 == b0 && a1 == b1;
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

static __always_inline __u32 l1_index(const struct flow_key *k, __u32 mask)
{
	__u32 h = k->inet_ip ^ k->host_ip ^ k->vlans ^
		  (((__u32)k->inet_port << 16) | (__u32)k->host_port);
	return fmix32(h) & mask;
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
	/* The normal miss is the once-per-tick revalidation of the same entry.
	 * Avoid rewriting its 16-byte key (and state) in that case; only the tick
	 * changes. A collision replacement still writes the complete entry. */
	if (slot->state == state && flow_key_eq(&slot->key, k)) {
		if (slot->last_seen != now)
			slot->last_seen = now;
		return;
	}
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
		} else if (v->state == ST_SYN_RCVD && (flags & TCP_SYN)) {
			/* our server's SYN-ACK to an inbound-initiated handshake: the client
			 * hasn't ACKed yet, so keep SYN_RCVD (ttl_syn) rather than promoting to
			 * EST (ttl_est). A blind spoofed inbound SYN can thus only tie up a slot
			 * for ttl_syn, not the full established timeout; the client's inbound ACK
			 * completes the promotion (see handle_inbound). Not L1-cacheable. */
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

	/* adopt: the trusted side is inserted into a live network. An outbound FIN
	 * adopts straight into CLOSING (draining, ttl_closing) with FL_CLOSED_OUT — the
	 * tail-end close of a pre-existing connection shouldn't be resurrected as a
	 * fresh ttl_est flow. Everything else adopts as EST and is L1-cacheable.
	 * (An outbound RST never reaches here — the RST branch above returns early.) */
	{
		struct flow_val nv = {};
		int cacheable = 0;
		if (flags & TCP_FIN) {
			nv.state = ST_CLOSING;
			nv.flags = FL_CLOSED_OUT;
		} else {
			nv.state = ST_EST;
			cacheable = 1;
		}
		nv.last_seen = now;
		if (bpf_map_update_elem(&flows, k, &nv, BPF_ANY)) {
			stat_reason(RSN_MAP_FAIL);
		} else if (cacheable) {
			/* Never authorize a tuple in L1 when its authoritative insert
			 * failed: the initiating packet may fail open, not its replies. */
			*cache_st = ST_EST;
		}
	}
	return ACT_FORWARD;
}

/* Token-bucket core (fixed-point *1000): charge one packet against the bucket
 * stored under `key` in synbkt at `rate` tokens/s, burst = 2s worth. Symmetric
 * RSS spreads one key's packets across CPUs, so tokens/ts_ns are updated
 * concurrently — every read-modify-write here is atomic so the limit can't leak
 * by a factor of the core count. Returns 1 to admit, 0 to reject. */
static __noinline int tbkt_charge(__u32 key, __u64 rate)
{
	const __u64 burst = rate * 2 * 1000ULL;
	struct tbkt *b = bpf_map_lookup_elem(&synbkt, &key);
	__u64 tnow = bpf_ktime_get_coarse_ns();

	if (!b) {
		struct tbkt nb = { .tokens = burst - 1000, .ts_ns = tnow };
		bpf_map_update_elem(&synbkt, &key, &nb, BPF_ANY);
		return 1;
	}

	/* Refill: elect a single refiller per interval with a CAS on ts_ns so
	 * concurrent CPUs can't double-credit (the loser's CAS fails and it skips).
	 * The clock is read per-CPU; the (tnow > last) test also guards cross-CPU
	 * skew (a stale/negative delta never refills). add uses a shift, not a
	 * BPF_DIV64: >>20 is ÷1048576 ≈ ÷1e6, i.e. ~4.6% stricter than nominal. */
	__u64 last = b->ts_ns;
	if (tnow > last && (tnow - last) >= (1ULL << 20)) { /* ~1.05 ms min interval */
		if (__sync_val_compare_and_swap(&b->ts_ns, last, tnow) == last) {
			__u64 add = ((tnow - last) * rate) >> 20;
			__u64 cur = b->tokens;
			if (cur < burst) {
				__u64 room = burst - cur;
				if (add > room)
					add = room; /* clamp to headroom: can't overshoot burst */
				if (add)
					__sync_fetch_and_add(&b->tokens, add);
			}
		}
	}

	/* Spend one packet with a bounded atomic CAS. On sustained contention (many
	 * CPUs charging the same key at once — i.e. an in-progress flood on a single
	 * source) fail-open after a few tries rather than spin or risk corrupting the
	 * counter via a fetch-and-sub underflow race. */
#pragma unroll
	for (int i = 0; i < 4; i++) {
		__u64 cur = b->tokens;
		if (cur < 1000)
			return 0;
		if (__sync_val_compare_and_swap(&b->tokens, cur, cur - 1000) == cur)
			return 1;
	}
	return 1;
}

/* per-source SYN rate limit for the inbound-server path (policy on only).
 * src_ip is network-order; 0.0.0.0 is never a routable source, so it can't
 * collide with syn_global_ok's reserved key 0. ~50 SYN/s, burst 100. */
static __always_inline int syn_token_ok(__u32 src_ip)
{
	return tbkt_charge(src_ip, 50);
}

/* Global admission cap on inbound-server SYNs, charged in addition to the
 * per-source bucket. A spoofed flood from *random* sources sails through every
 * per-source bucket (each source is new) and would otherwise insert a SYN_RCVD
 * flow per packet, churning the shared LRU tables and evicting live flows. This
 * bounds the aggregate SYN-insert rate. Keyed at 0 (0.0.0.0 can't be a real
 * source, so it never aliases a per-source bucket). Rate is fixed here (filter.h
 * has no config slot for it); 64x the per-source rate is generous headroom. */
static __always_inline int syn_global_ok(void)
{
	return tbkt_charge(0, 50 * 64);
}

/* ---- inbound: internet -> trusted. Validate only; never insert unless the
 * global inbound-SYN policy is on or the target is allowlisted. ----
 * *cache_st is set to ST_EST when the forward decision is L1-cacheable. */
static __always_inline int handle_inbound(const struct features *f, struct flow_key *k,
					  __u8 flags, __u32 ack_seq, __u32 now, __u8 *cache_st)
{
	struct flow_val *v = bpf_map_lookup_elem(&flows, k);
	int live = v && !expired(f, v, now);

	if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) { /* SYN-ACK — the headline */
		if (!live)
			return RSN_UNSOL_SYNACK;
		/* Validate the ack against the stored ISN for ANY live outbound-initiated
		 * flow (FL_ISN_VALID), not just ST_SYN_SENT: otherwise a spoofed SYN-ACK on
		 * an already-ESTABLISHED/CLOSING tuple is forwarded and refreshes the flow's
		 * TTL. Legit SYN-ACK retransmits always ack isn+1, so this is FP-free except
		 * for TCP Fast Open (SYN carried data -> SYN-ACK acks isn+1+datalen), which
		 * the pre-existing ST_SYN_SENT check already dropped — no new FP class.
		 * Adopted / inbound-server (ST_SYN_RCVD) flows have flags==0 and stay exempt. */
		if (v->flags & FL_ISN_VALID) {
			if (ack_seq != v->client_isn + 1)
				return RSN_BAD_ISN;
			if (v->state == ST_SYN_SENT)
				v->state = ST_EST;
		} else if (v->state == ST_SYN_SENT) {
			return RSN_BAD_ISN; /* SYN_SENT always has a valid ISN; preserved defensively */
		}
		touch(v, now);
		return ACT_FORWARD;
	}

	if ((flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) { /* inbound lone SYN (to a server) */
		if (!f->allow_inbound_syn) {
			if (!f->allow_inbound_servers)
				return RSN_INBOUND_SYN;
			struct srv_key sk = { .ip = k->host_ip, .port = k->host_port };
			if (!bpf_map_lookup_elem(&server_allow, &sk))
				return RSN_INBOUND_SYN;
		}
		if (!syn_token_ok(k->inet_ip))
			return RSN_INBOUND_SYN;
		/* global backstop: caps the aggregate inbound-SYN insert rate so a
		 * random-source flood can't churn the LRU tables (see syn_global_ok) */
		if (!syn_global_ok())
			return RSN_INBOUND_SYN;
		/* reset a fresh SYN_RCVD only over an absent / expired / closing slot;
		 * a live SYN_SENT/EST/SYN_RCVD is left intact so a spoofed inbound SYN
		 * on a live tuple can't clobber an in-flight handshake's ISN state. We
		 * deliberately do NOT touch() a live slot here: a rate-limited spoofed SYN
		 * retransmit must not be able to refresh a live flow's TTL indefinitely. A
		 * genuinely stalled handshake self-heals — once it ages past ttl_syn the
		 * next SYN retransmit falls into this recreate branch with a fresh stamp. */
		if (!live || v->state == ST_CLOSING) {
			struct flow_val nv = {};
			nv.state = ST_SYN_RCVD;
			nv.last_seen = now;
			if (bpf_map_update_elem(&flows, k, &nv, BPF_ANY))
				stat_reason(RSN_MAP_FAIL);
		}
		return ACT_FORWARD;
	}

	if (flags & TCP_RST) {
		if (!live)
			return RSN_OOS_RST;
		/* RFC 793: a RST while we're in SYN-SENT is acceptable only if it acks the
		 * SYN (ack == isn+1). Requiring that stops a blind spoofed RST at a
		 * connecting tuple from being forwarded and flipping us to CLOSING. A
		 * conforming peer refusing the connection always sends RST+ACK acking isn+1. */
		if (v->state == ST_SYN_SENT && (v->flags & FL_ISN_VALID) &&
		    (!(flags & TCP_ACK) || ack_seq != v->client_isn + 1))
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
		if (bpf_map_update_elem(&udp_flows, k, &nv, BPF_ANY)) {
			stat_reason(RSN_MAP_FAIL);
			return ACT_FORWARD; /* failed insert is not authoritative/cacheable */
		}
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

static __noinline int do_drop(const struct features *f, struct stats_global *g,
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

/* Cold parse failures can happen before the hot path needs policy. Resolve it
 * only here; retain the bootstrap fail-open behavior if the control map is not
 * available. */
static __noinline int do_drop_lazy(struct stats_global *g, struct vlan_stat *vs,
				   __u32 reason, __u64 len)
{
	struct features *f = get_features();

	if (!f)
		return bpf_redirect_map(&tx_ports, PEER_IDX, 0);
	return do_drop(f, g, vs, reason, len);
}

/* ---- optional TCP RST reply (untrusted side only, reject_with_rst) ----
 * Like an iptables REJECT --reject-with tcp-reset: instead of silently dropping
 * an enforced TCP drop, rewrite the frame in place into a RST addressed back to
 * the packet's source and XDP_TX it out the ingress port. The source may be
 * spoofed, so the RST can land on an unrelated host — hence opt-in. */

/* fold a 32-bit ones-complement accumulator down to the 16-bit checksum */
static __always_inline __u16 csum_fold(__u32 sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__u16)~sum;
}

/* RFC 793 §3.4 reset generation. Returns XDP_TX on success, -1 if bounds fail
 * (caller then falls back to the normal drop). */
static __noinline int build_and_send_rst(struct xdp_md *ctx, struct ethhdr *eth,
					 struct iphdr_min *ip, struct tcphdr_min *tcp)
{
	void *data_end = (void *)(long)ctx->data_end;
	if ((void *)(tcp + 1) > data_end) /* re-assert so the writes below verify */
		return -1;

	/* originals (network order unless noted) */
	__u8 in_flags = tcp->flags;
	__be32 in_seq = tcp->seq;
	__be32 in_ack = tcp->ack_seq;
	__u32 ihl = (ip->ver_ihl & 0x0F) * 4;
	__u16 tot_len = bpf_ntohs(ip->tot_len); /* host order */
	__u32 doff = (__u32)(tcp->doff_res >> 4) * 4;

	/* RST seq/ack: if the segment carried ACK, seq = seg.ACK (no ACK flag);
	 * otherwise seq = 0, ACK = seg.SEQ + seg.LEN (SYN and FIN each count 1). */
	__be32 rst_seq, rst_ack;
	__u8 rst_flags;
	if (in_flags & TCP_ACK) {
		rst_seq = in_ack;
		rst_ack = 0;
		rst_flags = TCP_RST;
	} else {
		__u32 seglen = (__u32)tot_len - ihl - doff;
		if (in_flags & TCP_SYN)
			seglen += 1;
		if (in_flags & TCP_FIN)
			seglen += 1;
		rst_seq = 0;
		rst_ack = bpf_htonl(bpf_ntohl(in_seq) + seglen);
		rst_flags = TCP_RST | TCP_ACK;
	}

	/* swap L2 MACs (frame is bounced back out the ingress port) */
	__u8 mac[ETH_ALEN];
	__builtin_memcpy(mac, eth->dest, ETH_ALEN);
	__builtin_memcpy(eth->dest, eth->source, ETH_ALEN);
	__builtin_memcpy(eth->source, mac, ETH_ALEN);

	/* swap L3 addrs (checksum-neutral: only tot_len changes below) */
	__be32 sip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = sip;

	/* shrink IP total length to a 20-byte TCP header (IP options, if any, kept)
	 * and patch the IP checksum incrementally (RFC 1624) for that one field */
	__u16 new_len = ihl + sizeof(*tcp);
	__u32 ics = (__u16)~bpf_ntohs(ip->check);
	ics += (__u16)~tot_len;
	ics += new_len;
	ip->tot_len = bpf_htons(new_len);
	ip->check = bpf_htons(csum_fold(ics));

	/* swap L4 ports, write the RST header, recompute the TCP checksum in full */
	__be16 sp = tcp->source;
	tcp->source = tcp->dest;
	tcp->dest = sp;
	tcp->seq = rst_seq;
	tcp->ack_seq = rst_ack;
	tcp->doff_res = 0x50; /* data offset 5, no options */
	tcp->flags = rst_flags;
	tcp->window = 0;
	tcp->urg_ptr = 0;
	tcp->check = 0;

	/* pseudo-header + the 20-byte header, summed as raw network-order words
	 * (endian-consistent: the fold is stored back raw) */
	__u32 sum = 0;
	__u16 *sa = (__u16 *)&ip->saddr;
	__u16 *da = (__u16 *)&ip->daddr;
	sum += sa[0] + sa[1] + da[0] + da[1];
	sum += bpf_htons(IPPROTO_TCP) + bpf_htons(sizeof(*tcp));
	__u16 *w = (__u16 *)tcp;
#pragma unroll
	for (int i = 0; i < (int)(sizeof(*tcp) / 2); i++)
		sum += w[i];
	tcp->check = csum_fold(sum);

	return XDP_TX;
}

/* TCP-drop wrapper: on the untrusted side in enforce mode with reject_with_rst,
 * answer with a RST instead of a silent drop. On the trusted side the leading
 * !ROLE_TRUSTED (frozen rodata) prunes to a plain do_drop. */
static __always_inline int do_drop_tcp(struct xdp_md *ctx, const struct features *f,
				       struct stats_global *g, struct vlan_stat *vs,
				       __u32 reason, __u64 len, struct ethhdr *eth,
				       struct iphdr_min *ip, struct tcphdr_min *tcp)
{
	if (!ROLE_TRUSTED && f->mode == MODE_ENFORCE && f->reject_with_rst) {
		if (build_and_send_rst(ctx, eth, ip, tcp) == XDP_TX) {
			stat_reason(reason); /* keep the per-vector counter visible */
			if (g) {
				g->rst_pkts++;
				g->rst_bytes += len;
			}
			return XDP_TX;
		}
	}
	return do_drop(f, g, vs, reason, len);
}

SEC("xdp.frags")
int xdp_filter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u64 len = data_end - data;
	__u32 outer_vid = 0, inner_vid = 0;
	int vlan_trunc = 0;

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
		return do_drop_lazy(g, vs0, RSN_MALFORMED, len);
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
		return do_drop_lazy(g, vs, RSN_MALFORMED, len);

	/* more VLAN tags than MAX_VLAN_DEPTH — L3/L4 is unreachable, so this frame
	 * bypasses all inspection. Policy decides drop vs. transparent forward. */
	if (unlikely(proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD))) {
		struct features *f = get_features();
		if (!f)
			return bpf_redirect_map(&tx_ports, PEER_IDX, 0);
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
		return do_drop_lazy(g, vs, RSN_MALFORMED, len);
	if (unlikely((ip->ver_ihl >> 4) != 4)) /* ethertype says IPv4 but version nibble disagrees */
		return do_drop_lazy(g, vs, RSN_MALFORMED, len);
	__u32 ihl = (ip->ver_ihl & 0x0F) * 4;
	if (unlikely(ihl < sizeof(*ip)))
		return do_drop_lazy(g, vs, RSN_MALFORMED, len);
	void *l4 = (void *)ip + ihl;
	if (unlikely(l4 > data_end))
		return do_drop_lazy(g, vs, RSN_MALFORMED, len);

	/* TCP first: it is the dominant, filtered protocol */
	if (likely(ip->protocol == IPPROTO_TCP)) {
		struct features *f = NULL;

		/* non-first fragment of a TCP datagram (evasion-shaped) */
		if (unlikely(ip->frag_off & bpf_htons(IP_FRAG_OFF_MASK))) {
			f = get_features();
			if (!f)
				return bpf_redirect_map(&tx_ports, PEER_IDX, 0);
			if (f->drop_frags)
				return do_drop(f, g, vs, RSN_TCP_FRAG, len);
			return do_forward(g, len);
		}

		struct tcphdr_min *tcp = l4;
		if (unlikely((void *)(tcp + 1) > data_end))
			return do_drop_lazy(g, vs, RSN_MALFORMED, len);
		/* data-offset must cover the 20-byte fixed header, and tot_len must reach
		 * past IP options + the full TCP header. Rejects RFC-invalid doff,
		 * Ethernet-padding-parsed-as-L4, and RFC 1858 tiny-first-fragment flag
		 * evasion. In-header fields only -> safe under xdp.frags multi-buffer. */
		__u32 doff = (__u32)(tcp->doff_res >> 4) * 4;
		if (unlikely(doff < sizeof(*tcp) || bpf_ntohs(ip->tot_len) < ihl + doff))
			return do_drop_lazy(g, vs, RSN_MALFORMED, len);
		__u8 flags = tcp->flags;
		__u32 l1_mask = L1_MASK;
		__u8 trusted = ROLE_TRUSTED;

		/* Every L1-eligible packet is ACK-bearing with SYN/FIN/RST clear, so
		 * bad_flags() cannot reject it. Resolve live policy before time/state
		 * work only for packets which do not have that proof. */
		int l1_ok = l1_mask && ((flags & (TCP_SYN | TCP_FIN | TCP_RST)) == 0) &&
			    (flags & TCP_ACK);
		if (!l1_ok) {
			f = get_features();
			if (!f)
				return bpf_redirect_map(&tx_ports, PEER_IDX, 0);
		}

		/* normalized, direction-independent key (aligned(8) so flow_key_eq's
		 * assume_aligned holds for the stack operand — see flow_key_eq) */
		struct flow_key k __attribute__((aligned(8))) = {};
		k.vlans = ((__u32)outer_vid << 12) | inner_vid;
		if (trusted) {
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
		if (!trusted)
			monitor_flow(&k, IPPROTO_TCP, len);
		if (f && f->drop_bad_flags && unlikely(bad_flags(flags)))
			return do_drop_tcp(ctx, f, g, vs, RSN_BAD_FLAGS, len, eth, ip, tcp);

		__u32 now = now_tick();

		/* L1 fast path: pure ACK/data (no SYN/FIN/RST) on an established flow.
		 * The ACK requirement also excludes null-scans. */
		__u32 l1_idx = 0;
		struct l1_entry *slot = NULL;
		if (l1_ok) {
			l1_idx = l1_index(&k, l1_mask);
			if (l1_hit(l1_idx, &k, ST_EST, now, &slot)) {
				if (g)
					g->l1_hits++;
				return do_forward(g, len);
			}
		}

		if (!f) {
			f = get_features();
			if (!f)
				return bpf_redirect_map(&tx_ports, PEER_IDX, 0);
		}

		__u8 cache_st = 0;
		int r;
		if (trusted)
			r = handle_outbound(f, &k, flags, bpf_ntohl(tcp->seq), now, &cache_st);
		else
			r = handle_inbound(f, &k, flags, bpf_ntohl(tcp->ack_seq), now, &cache_st);

		if (r == ACT_FORWARD) {
			if (l1_ok && cache_st == ST_EST)
				l1_put(slot, &k, ST_EST, now);
			return do_forward(g, len);
		}
		return do_drop_tcp(ctx, f, g, vs, (__u32)r, len, eth, ip, tcp);
	}

	/* UDP: stateful reply-only filtering (protect the destination's conntrack) */
	if (ip->protocol == IPPROTO_UDP) {
		struct features *f = get_features();
		if (!f)
			return bpf_redirect_map(&tx_ports, PEER_IDX, 0);

		/* a non-first fragment has no L4 ports — can't key it; policy decides */
		if (unlikely(ip->frag_off & bpf_htons(IP_FRAG_OFF_MASK))) {
			if (!f->filter_udp)
				goto nontcp;
			if (f->drop_udp_frags)
				return do_drop(f, g, vs, RSN_UDP_FRAG, len);
			return do_forward(g, len);
		}
		struct udphdr_min *udp = l4;
		if (unlikely((void *)(udp + 1) > data_end)) {
			if (!f->filter_udp)
				goto nontcp;
			return do_drop(f, g, vs, RSN_MALFORMED, len);
		}
		/* tot_len must reach past IP options + the 8-byte UDP header (padding /
		 * tiny-first-fragment guard; in-header fields only) */
		if (unlikely(bpf_ntohs(ip->tot_len) < ihl + sizeof(*udp))) {
			if (!f->filter_udp)
				goto nontcp;
			return do_drop(f, g, vs, RSN_MALFORMED, len);
		}
		struct flow_key uk __attribute__((aligned(8))) = {};
		__u8 trusted = ROLE_TRUSTED;
		uk.vlans = ((__u32)outer_vid << 12) | inner_vid;
		if (trusted) {
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
		if (!trusted)
			monitor_flow(&uk, IPPROTO_UDP, len);
		if (!f->filter_udp)
			goto nontcp;

		/* L1 fast path for established UDP pseudo-flows */
		__u32 l1_idx = 0;
		struct l1_entry *slot = NULL;
		__u32 l1_mask = L1_MASK;
		__u32 now = now_tick();
		if (l1_mask) {
			l1_idx = l1_index(&uk, l1_mask);
			if (l1_hit(l1_idx, &uk, ST_UDP, now, &slot)) {
				if (g)
					g->l1_hits++;
				return do_forward(g, len);
			}
		}

		__u8 cache_st = 0;
		int ur = trusted ? handle_outbound_udp(&uk, now, &cache_st)
				 : handle_inbound_udp(f, &uk, now, &cache_st);
		if (ur == ACT_FORWARD) {
			if (l1_mask && cache_st == ST_UDP)
				l1_put(slot, &uk, ST_UDP, now);
			return do_forward(g, len);
		}
		return do_drop(f, g, vs, (__u32)ur, len);
	}

	/* IPv4 non-TCP (and UDP with filtering off) — forward transparently */
nontcp:
	if (g) { g->nontcp_pkts++; g->nontcp_bytes += len; }
	return do_forward(g, len);
}
