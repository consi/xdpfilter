// SPDX-License-Identifier: GPL-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	flowEntryEstimate = uint64(128)
	l1EntryBytes      = uint64(24)
	fixedMapBytes     = uint64(10 << 20)
	statsBytesPerCPU  = uint64(98_512)
)

// HostResources describes the limits which matter to BPF map allocation.
// PossibleCPUs is deliberately separate: per-CPU maps allocate for possible,
// not merely online, CPUs.
type HostResources struct {
	MemoryTotal     uint64
	MemoryAvailable uint64
	EffectiveMemory uint64
	MemoryHeadroom  uint64
	CgroupLimit     uint64
	CgroupCurrent   uint64
	PossibleCPUs    int
	OnlineCPUs      int
	LimitedByCgroup bool
}

// ResourceRecommendation is a concrete, wizard-materializable appliance
// sizing proposal. It is never applied silently by Load.
type ResourceRecommendation struct {
	FlowMax        uint32
	UDPFlowMax     uint32
	L1Size         uint32
	MapBudgetBytes uint64
	EstimatedBytes uint64
	L1Bytes        uint64
	FixedBytes     uint64
}

type fileReader func(string) ([]byte, error)

// DetectHostResources probes the running Linux host and its memory cgroup.
func DetectHostResources() HostResources {
	return detectHostResources(os.ReadFile)
}

func detectHostResources(read fileReader) HostResources {
	memTotal, memAvailable := parseMeminfo(readFileOrEmpty(read, "/proc/meminfo"))
	possible := countCPUList(strings.TrimSpace(string(readFileOrEmpty(read, "/sys/devices/system/cpu/possible"))))
	online := countCPUList(strings.TrimSpace(string(readFileOrEmpty(read, "/sys/devices/system/cpu/online"))))
	if possible == 0 {
		possible = online
	}
	if possible == 0 {
		possible = 1
	}
	if online == 0 {
		online = possible
	}

	limit, current, cgroupHeadroom := detectCgroupMemory(read, memTotal)
	effective := memTotal
	limited := limit > 0 && (effective == 0 || limit < effective)
	if limited {
		effective = limit
	}
	headroom := memAvailable
	if cgroupHeadroom > 0 && (headroom == 0 || cgroupHeadroom < headroom) {
		headroom = cgroupHeadroom
	}
	if headroom == 0 {
		headroom = effective
	}

	return HostResources{
		MemoryTotal: memTotal, MemoryAvailable: memAvailable,
		EffectiveMemory: effective, MemoryHeadroom: headroom,
		CgroupLimit: limit, CgroupCurrent: current,
		PossibleCPUs: possible, OnlineCPUs: online,
		LimitedByCgroup: limited,
	}
}

// RecommendDedicated sizes preallocated maps for an appliance host. The raw
// budget is bounded by one third of effective RAM and current headroom, then
// reduced by 20% for allocator/kernel-version variance.
func RecommendDedicated(r HostResources) ResourceRecommendation {
	p := r.PossibleCPUs
	if p < 1 {
		p = 1
	}
	effective := r.EffectiveMemory
	if effective == 0 {
		effective = r.MemoryTotal
	}
	headroom := r.MemoryHeadroom
	if headroom == 0 {
		headroom = effective
	}
	rawBudget := min64(effective/3, headroom)
	budget := rawBudget * 4 / 5

	fixed := fixedMapBytes + statsBytesPerCPU*uint64(p)
	l1Budget := effective / 100
	slots := floorPowerOfTwo(l1Budget / (l1EntryBytes * uint64(p)))
	if slots > 1<<16 {
		slots = 1 << 16
	}
	if slots < 1<<12 {
		slots = 0
	}
	l1Bytes := slots * l1EntryBytes * uint64(p)
	if fixed+l1Bytes >= budget {
		slots, l1Bytes = 0, 0
	}

	flowBudget := uint64(0)
	if budget > fixed+l1Bytes {
		flowBudget = budget - fixed - l1Bytes
	}
	tcpEntries := roundDown1024((flowBudget * 4 / 5) / flowEntryEstimate)
	udpEntries := roundDown1024((flowBudget / 5) / flowEntryEstimate)
	tcpEntries = clamp64(tcpEntries, 1024, 1<<26)
	udpEntries = clamp64(udpEntries, 1024, 1<<24)

	estimated := fixed + l1Bytes + flowEntryEstimate*(tcpEntries+udpEntries)
	// On extremely constrained hosts, retain valid minimum map sizes even when
	// the estimate necessarily exceeds the recommendation budget.
	return ResourceRecommendation{
		FlowMax: uint32(tcpEntries), UDPFlowMax: uint32(udpEntries),
		L1Size: uint32(slots), MapBudgetBytes: budget,
		EstimatedBytes: estimated, L1Bytes: l1Bytes, FixedBytes: fixed,
	}
}

func detectCgroupMemory(read fileReader, hostTotal uint64) (limit, current, headroom uint64) {
	cgroup := string(readFileOrEmpty(read, "/proc/self/cgroup"))
	var rel, root string
	for _, line := range strings.Split(cgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" {
			root, rel = "/sys/fs/cgroup", parts[2]
			break
		}
		if containsWord(parts[1], "memory") {
			root, rel = "/sys/fs/cgroup/memory", parts[2]
		}
	}
	if root == "" {
		return 0, 0, 0
	}

	dir := filepath.Join(root, strings.TrimPrefix(filepath.Clean(rel), "/"))
	for {
		maxName, curName := "memory.max", "memory.current"
		if strings.HasSuffix(root, "/memory") {
			maxName, curName = "memory.limit_in_bytes", "memory.usage_in_bytes"
		}
		max := parseMemoryValue(readFileOrEmpty(read, filepath.Join(dir, maxName)), hostTotal)
		cur := parseMemoryValue(readFileOrEmpty(read, filepath.Join(dir, curName)), 0)
		if max > 0 {
			if limit == 0 || max < limit {
				limit, current = max, cur
			}
			if max > cur {
				h := max - cur
				if headroom == 0 || h < headroom {
					headroom = h
				}
			}
		}
		if dir == root {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir || !strings.HasPrefix(parent, root) {
			break
		}
		dir = parent
	}
	return limit, current, headroom
}

func parseMeminfo(b []byte) (total, available uint64) {
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			total = v << 10
		case "MemAvailable":
			available = v << 10
		}
	}
	return
}

func parseMemoryValue(b []byte, hostTotal uint64) uint64 {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "max" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v >= 1<<60 || (hostTotal > 0 && v > hostTotal*1024) {
		return 0
	}
	return v
}

func countCPUList(s string) int {
	n := 0
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, e1 := strconv.Atoi(lo)
			b, e2 := strconv.Atoi(hi)
			if e1 == nil && e2 == nil && b >= a {
				n += b - a + 1
			}
		} else if _, err := strconv.Atoi(part); err == nil {
			n++
		}
	}
	return n
}

func floorPowerOfTwo(v uint64) uint64 {
	if v == 0 {
		return 0
	}
	var p uint64 = 1
	for p <= v/2 {
		p <<= 1
	}
	return p
}

func readFileOrEmpty(read fileReader, path string) []byte {
	b, err := read(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return b
}

func containsWord(csv, want string) bool {
	for _, v := range strings.Split(csv, ",") {
		if v == want {
			return true
		}
	}
	return false
}

func roundDown1024(v uint64) uint64 { return v &^ 1023 }
func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
func clamp64(v, lo, hi uint64) uint64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
