// SPDX-License-Identifier: GPL-2.0

// Package stats reads the per-CPU BPF counters and renders a human-readable
// report to <stats_dir>/stats.txt every interval. All counters are PERCPU
// arrays, so collection is cheap and never contends with the datapath.
package stats

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/consi/xdpfilter/internal/dataplane"
	"github.com/consi/xdpfilter/internal/meta"
)

// Reason labels — index order MUST match enum drop_reason in bpf/filter.h.
var reasonLabels = []string{
	"unsolicited SYN-ACK",
	"bad ISN",
	"out-of-state in",
	"out-of-state out",
	"out-of-state RST",
	"inbound SYN (no server)",
	"bad TCP flags",
	"TCP fragment",
	"malformed",
	"unsolicited UDP",
	"flow-table full",
	"excess VLAN tags",
	"UDP fragment",
}

const numReasons = 13

type statsGlobalValue struct {
	RxPkts, RxBytes         uint64
	RedirPkts, RedirBytes   uint64
	DropPkts, DropBytes     uint64
	NonIPPkts, NonIPBytes   uint64
	NonTCPPkts, NonTCPBytes uint64
	L1Hits                  uint64
	RstPkts, RstBytes       uint64
}

type vlanStatValue struct {
	Pkts, Bytes, Drops uint64
}

// Snapshot is a summed-across-CPUs point-in-time reading.
type Snapshot struct {
	G       statsGlobalValue
	Reasons [numReasons]uint64
	Vlans   map[uint16]vlanStatValue
	When    time.Time
}

// Collect sums every per-CPU counter into a Snapshot.
func Collect(m *dataplane.SharedMaps) (Snapshot, error) {
	s := Snapshot{Vlans: make(map[uint16]vlanStatValue), When: time.Now()}

	var perG []statsGlobalValue
	if err := m.StatsGlobal.Lookup(uint32(0), &perG); err != nil {
		return s, fmt.Errorf("read stats_global: %w", err)
	}
	for _, c := range perG {
		s.G.RxPkts += c.RxPkts
		s.G.RxBytes += c.RxBytes
		s.G.RedirPkts += c.RedirPkts
		s.G.RedirBytes += c.RedirBytes
		s.G.DropPkts += c.DropPkts
		s.G.DropBytes += c.DropBytes
		s.G.NonIPPkts += c.NonIPPkts
		s.G.NonIPBytes += c.NonIPBytes
		s.G.NonTCPPkts += c.NonTCPPkts
		s.G.NonTCPBytes += c.NonTCPBytes
		s.G.L1Hits += c.L1Hits
		s.G.RstPkts += c.RstPkts
		s.G.RstBytes += c.RstBytes
	}

	for r := uint32(0); r < numReasons; r++ {
		var per []uint64
		if err := m.DropReason.Lookup(r, &per); err != nil {
			continue
		}
		var sum uint64
		for _, c := range per {
			sum += c
		}
		s.Reasons[r] = sum
	}

	for vid := uint32(0); vid < 4096; vid++ {
		var per []vlanStatValue
		if err := m.StatsVlan.Lookup(vid, &per); err != nil {
			continue
		}
		var agg vlanStatValue
		for _, c := range per {
			agg.Pkts += c.Pkts
			agg.Bytes += c.Bytes
			agg.Drops += c.Drops
		}
		if agg.Pkts > 0 || agg.Drops > 0 {
			s.Vlans[uint16(vid)] = agg
		}
	}
	return s, nil
}

// Reporter renders reports and detects drop-rate spikes across ticks.
type Reporter struct {
	Version   string
	StatsDir  string
	Ports     string // "eth0 (trusted) <-> eth1 (untrusted)"
	Occupancy func() (live int, max int)

	start      time.Time
	prev       *Snapshot
	baseline   [numReasons]float64 // EMA of per-reason drop rate
	spikeSince [numReasons]time.Time
}

func NewReporter(version, statsDir, ports string, occ func() (int, int)) *Reporter {
	return &Reporter{Version: version, StatsDir: statsDir, Ports: ports, Occupancy: occ, start: time.Now()}
}

// Tick collects, renders, and atomically writes stats.txt. It also returns any
// spike-warning lines it emitted (for journald logging by the caller).
func (r *Reporter) Tick(m *dataplane.SharedMaps, mode string) (string, error) {
	cur, err := Collect(m)
	if err != nil {
		return "", err
	}
	report, warn := r.render(&cur, mode)
	r.prev = &cur

	if err := os.MkdirAll(r.StatsDir, 0o755); err != nil {
		return warn, err
	}
	dst := filepath.Join(r.StatsDir, "stats.txt")
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, []byte(report), 0o644); err != nil {
		return warn, err
	}
	return warn, os.Rename(tmp, dst)
}

func (r *Reporter) render(cur *Snapshot, mode string) (report, warn string) {
	var b strings.Builder
	secs := 0.0
	if r.prev != nil {
		secs = cur.When.Sub(r.prev.When).Seconds()
	}

	live, max := 0, 0
	if r.Occupancy != nil {
		live, max = r.Occupancy()
	}
	occPct := 0.0
	if max > 0 {
		occPct = 100 * float64(live) / float64(max)
	}

	fmt.Fprintf(&b, "xdpfilter %s  mode: %s  up %s  %s\n",
		r.Version, strings.ToUpper(mode), uptime(time.Since(r.start)),
		cur.When.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "ports: %s   flows: %s / %s (%.1f%%)\n\n",
		r.Ports, comma(uint64(live)), comma(uint64(max)), occPct)

	fmt.Fprintf(&b, "%-14s %16s %10s %14s\n", "", "packets", "pps", "bitrate")
	row := func(name string, pkts, bytes uint64) {
		var dp, dbytes uint64
		if r.prev != nil {
			dp = pkts - prevPkts(r.prev, name)
			dbytes = bytes - prevBytes(r.prev, name)
		}
		fmt.Fprintf(&b, "  %-12s %16s %10s %14s\n", name, comma(pkts), ratePerSec(dp, secs), bitrate(dbytes, secs))
	}
	row("processed", cur.G.RxPkts, cur.G.RxBytes)
	row("redirected", cur.G.RedirPkts, cur.G.RedirBytes)
	row("dropped", cur.G.DropPkts, cur.G.DropBytes)
	row("non-TCP fwd", cur.G.NonTCPPkts+cur.G.NonIPPkts, cur.G.NonTCPBytes+cur.G.NonIPBytes)

	// L1 fast-path hits: established-flow packets that skipped the LRU-hash lookup
	// (a subset of "redirected"). Hit counter only — no byte column.
	{
		var d uint64
		if r.prev != nil {
			d = cur.G.L1Hits - r.prev.G.L1Hits
		}
		fmt.Fprintf(&b, "  %-12s %16s %10s %14s\n", "l1 hits", comma(cur.G.L1Hits), ratePerSec(d, secs), "")
	}

	// RST replies: enforced TCP drops answered with a RST to the source instead
	// of a silent drop (reject_with_rst, untrusted side). Zero unless enabled.
	if cur.G.RstPkts > 0 {
		row("rst replies", cur.G.RstPkts, cur.G.RstBytes)
	}

	// drops by reason (this interval)
	label := "drops by reason (this interval):"
	if mode == "monitor" {
		label = "would-drop by reason (monitor):"
	}
	fmt.Fprintf(&b, "\n%s\n", label)
	warnLine := ""
	for rIdx := 0; rIdx < numReasons; rIdx++ {
		var d uint64
		if r.prev != nil {
			d = cur.Reasons[rIdx] - r.prev.Reasons[rIdx]
		}
		if cur.Reasons[rIdx] == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %-26s %10s/s\n", reasonLabels[rIdx], ratePerSec(d, secs))
		if w := r.detectSpike(rIdx, d, secs, cur.When); w != "" {
			warnLine = w
		}
	}

	// per-VLAN
	fmt.Fprintf(&b, "\nper-VLAN (active):\n")
	fmt.Fprintf(&b, "  %-6s %12s %12s %14s\n", "VID", "proc pps", "drop pps", "bitrate")
	vids := make([]int, 0, len(cur.Vlans))
	for vid := range cur.Vlans {
		vids = append(vids, int(vid))
	}
	sort.Ints(vids)
	for _, vid := range vids {
		v := cur.Vlans[uint16(vid)]
		var dpk, ddr, dby uint64
		if r.prev != nil {
			if pv, ok := r.prev.Vlans[uint16(vid)]; ok {
				dpk = v.Pkts - pv.Pkts
				ddr = v.Drops - pv.Drops
				dby = v.Bytes - pv.Bytes
			} else {
				dpk, ddr, dby = v.Pkts, v.Drops, v.Bytes
			}
		}
		name := fmt.Sprintf("%d", vid)
		if vid == 0 {
			name = "none"
		}
		fmt.Fprintf(&b, "  %-6s %12s %12s %14s\n", name, ratePerSec(dpk, secs), ratePerSec(ddr, secs), bitrate(dby, secs))
	}

	if warnLine != "" {
		fmt.Fprintf(&b, "⚠ %s\n", warnLine)
	}
	fmt.Fprintf(&b, "\nxdpfilter %s — %s\n", r.Version, meta.Copyright)
	return b.String(), warnLine
}

// detectSpike keeps an EMA baseline per reason and flags sudden jumps.
func (r *Reporter) detectSpike(idx int, delta uint64, secs float64, when time.Time) string {
	if secs <= 0 {
		return ""
	}
	cur := float64(delta) / secs
	base := r.baseline[idx]
	const alpha = 0.3
	if base == 0 {
		r.baseline[idx] = cur
		return ""
	}
	spiking := cur > 1000 && cur > base*10
	if spiking {
		if r.spikeSince[idx].IsZero() {
			r.spikeSince[idx] = when
		}
		w := fmt.Sprintf("drop spike: %s %s/s (baseline %s/s) since %s",
			reasonLabels[idx], humanRate(cur), humanRate(base), r.spikeSince[idx].Format("15:04:05"))
		// don't fold a spike into the baseline
		return w
	}
	r.spikeSince[idx] = time.Time{}
	r.baseline[idx] = alpha*cur + (1-alpha)*base
	return ""
}

// ---- per-"row" delta helpers (map the printed name back to the prev snapshot) ----
func prevPkts(p *Snapshot, name string) uint64 {
	switch name {
	case "processed":
		return p.G.RxPkts
	case "redirected":
		return p.G.RedirPkts
	case "dropped":
		return p.G.DropPkts
	case "non-TCP fwd":
		return p.G.NonTCPPkts + p.G.NonIPPkts
	}
	return 0
}

func prevBytes(p *Snapshot, name string) uint64 {
	switch name {
	case "processed":
		return p.G.RxBytes
	case "redirected":
		return p.G.RedirBytes
	case "dropped":
		return p.G.DropBytes
	case "non-TCP fwd":
		return p.G.NonTCPBytes + p.G.NonIPBytes
	}
	return 0
}

// ---- formatting ----

func comma(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	pre := len(s) % 3
	if pre > 0 {
		out = append(out, s[:pre]...)
		if len(s) > pre {
			out = append(out, ',')
		}
	}
	for i := pre; i < len(s); i += 3 {
		out = append(out, s[i:i+3]...)
		if i+3 < len(s) {
			out = append(out, ',')
		}
	}
	return string(out)
}

func ratePerSec(delta uint64, secs float64) string {
	if secs <= 0 {
		return "-"
	}
	return humanRate(float64(delta) / secs)
}

func humanRate(v float64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.2f M", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1f K", v/1e3)
	default:
		return fmt.Sprintf("%.0f", v)
	}
}

func bitrate(bytesDelta uint64, secs float64) string {
	if secs <= 0 {
		return "-"
	}
	bits := float64(bytesDelta) * 8 / secs
	switch {
	case bits >= 1e9:
		return fmt.Sprintf("%.2f Gbit/s", bits/1e9)
	case bits >= 1e6:
		return fmt.Sprintf("%.0f Mbit/s", bits/1e6)
	case bits >= 1e3:
		return fmt.Sprintf("%.0f Kbit/s", bits/1e3)
	default:
		return fmt.Sprintf("%.0f bit/s", bits)
	}
}

func uptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %02d:%02d", days, h, m)
	}
	return fmt.Sprintf("%02d:%02d", h, m)
}

// PrintStatus writes a status summary to w (used by `xdpfilter status`).
func PrintStatus(m *dataplane.SharedMaps, version, ports string, occ func() (int, int)) string {
	r := NewReporter(version, "", ports, occ)
	report, _ := r.render(mustCollect(m), dataplane.Mode(m))
	return report
}

func mustCollect(m *dataplane.SharedMaps) *Snapshot {
	s, _ := Collect(m)
	return &s
}
