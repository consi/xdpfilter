// SPDX-License-Identifier: GPL-2.0

package dataplane

import (
	"log"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/consi/xdpfilter/internal/config"
)

// flow_state values (mirror enum flow_state in bpf/filter.h).
const (
	stNone = iota
	stSynSent
	stSynRcvd
	stEst
	stClosing
	stUdp
)

// flowVal mirrors struct flow_val (numeric fields; native marshaling matches BPF).
type flowVal struct {
	ClientISN uint32
	LastSeen  uint32
	State     uint8
	Flags     uint8
	Pad       uint16
}

// MonotonicTick returns coarse ticks (CLOCK_MONOTONIC ns >> nowShift) — the same
// unit the BPF side stores in last_seen (bpf_ktime_get_coarse_ns >> NOW_SHIFT),
// so comparisons line up. 1 tick ≈ 1.073741824 s.
func MonotonicTick() uint32 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	ns := uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
	return uint32(ns >> nowShift)
}

// ticksToSec converts a coarse-tick age back to whole seconds (for display).
func ticksToSec(ticks uint32) uint32 {
	return uint32((uint64(ticks) << nowShift) / 1_000_000_000)
}

// ttlForState returns the per-state idle timeout in coarse ticks (config is in
// seconds; last_seen/now are ticks).
func ttlForState(cfg *config.Config, state uint8) uint32 {
	switch state {
	case stEst:
		return secToTicks(cfg.TTLEst)
	case stClosing:
		return secToTicks(cfg.TTLClosing)
	case stUdp:
		return secToTicks(cfg.TTLUdp)
	default: // SYN_SENT / SYN_RCVD / unknown
		return secToTicks(cfg.TTLSyn)
	}
}

// GCOnce sweeps the flow table once, deleting entries past their per-state TTL.
// Returns the live occupancy (post-sweep) and the number deleted.
//
// v1 uses a full iterate + deferred delete (correct and simple). A BatchLookup/
// BatchDelete variant is a drop-in optimization for very large tables.
func GCOnce(flows *ebpf.Map, cfg *config.Config) (live, deleted int) {
	now := MonotonicTick()
	if now == 0 {
		// Clock read failed: skip this sweep rather than treat every entry as
		// expired (now-last_seen would underflow) and evict the whole table.
		return 0, 0
	}
	var key [16]byte
	var val flowVal
	var expired [][16]byte
	total := 0

	it := flows.Iterate()
	for it.Next(&key, &val) {
		total++
		// A concurrent touch during this multi-second sweep can advance last_seen
		// past the once-latched now; the unsigned delta would underflow and delete
		// a live flow. Skip anything stamped in the (apparent) future.
		if val.LastSeen > now {
			continue
		}
		if now-val.LastSeen > ttlForState(cfg, val.State) {
			k := key // copy out of the iterator's reused buffer
			expired = append(expired, k)
		}
	}
	if err := it.Err(); err != nil {
		// A partial sweep is fine (we retry next tick) but shouldn't be silent.
		log.Printf("gc: iterate flows: %v", err)
	}
	for i := range expired {
		if err := flows.Delete(expired[i][:]); err == nil {
			deleted++
		}
	}
	return total - deleted, deleted
}
