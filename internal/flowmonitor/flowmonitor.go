// SPDX-License-Identifier: GPL-2.0

// Package flowmonitor turns sampled BPF flow counters into one-second alert
// snapshots and persists the stable NDJSON machine interface.
package flowmonitor

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"github.com/cilium/ebpf"

	"github.com/consi/xdpfilter/internal/config"
	"github.com/consi/xdpfilter/internal/dataplane"
)

const Filename = "flow_alerts.jsonl"

type counter struct {
	Packets uint64
	Bytes   uint64
}

// Snapshot is one cumulative read of the sampled flow-counter map.
type Snapshot struct {
	Counters map[[20]byte]counter
	When     time.Time
}

// FlowID is the stable direction-normalized identity emitted for an alert.
type FlowID struct {
	Protocol      string `json:"protocol"`
	ProtectedIP   string `json:"protected_ip"`
	ProtectedPort uint16 `json:"protected_port"`
	InternetIP    string `json:"internet_ip"`
	InternetPort  uint16 `json:"internet_port"`
	OuterVLAN     uint16 `json:"outer_vlan"`
	InnerVLAN     uint16 `json:"inner_vlan"`
}

// Alert is one line of flow_alerts.jsonl. Fields form the public schema v1.
type Alert struct {
	Schema        int       `json:"schema"`
	ObservedAt    time.Time `json:"observed_at"`
	WindowSeconds float64   `json:"window_seconds"`
	Flow          FlowID    `json:"flow"`
	MatchedCIDR   string    `json:"matched_cidr"`
	EstimatedPPS  float64   `json:"estimated_pps"`
	EstimatedMbps float64   `json:"estimated_mbps"`
	ThresholdPPS  uint64    `json:"threshold_pps"`
	ThresholdMbps float64   `json:"threshold_mbps"`
	Exceeded      []string  `json:"exceeded"`
	SampleEvery   uint32    `json:"sample_every"`
}

// Reporter owns the previous cumulative snapshot used to derive rates.
type Reporter struct {
	StatsDir string
	prev     *Snapshot
	settings *config.FlowMonitoring
	spare    map[[20]byte]counter
	keys     [][20]byte
	values   []counter
}

func NewReporter(statsDir string) *Reporter { return &Reporter{StatsDir: statsDir} }

// Tick writes the current alert snapshot. A configuration transition publishes
// an empty baseline window so counters collected under two settings are never
// combined.
func (r *Reporter) Tick(m *dataplane.SharedMaps, cfg *config.Config) ([]Alert, error) {
	fm := cfg.FlowMonitoring
	changed := r.settings == nil || !reflect.DeepEqual(*r.settings, fm)
	copySettings := fm
	copySettings.CIDRs = append([]config.FlowMonitorCIDR(nil), fm.CIDRs...)
	r.settings = &copySettings

	// With no rules there is nothing to account or scan. Still replace the
	// public snapshot every second so consumers never retain stale alerts.
	if !fm.Enabled || len(fm.CIDRs) == 0 {
		if r.prev != nil {
			clear(r.prev.Counters)
			r.spare = r.prev.Counters
		}
		r.prev = nil
		return nil, r.write(nil)
	}
	cur, keys, values, err := collectInto(m.FlowMonitorCounters, r.spare, r.keys, r.values)
	if err != nil {
		return nil, err
	}
	r.spare, r.keys, r.values = nil, keys, values
	if changed || r.prev == nil {
		if r.prev != nil {
			clear(r.prev.Counters)
			r.spare = r.prev.Counters
		}
		r.prev = &cur
		return nil, r.write(nil)
	}
	alerts := alertsFrom(*r.prev, cur, fm)
	old := r.prev
	r.prev = &cur
	clear(old.Counters)
	r.spare = old.Counters
	return alerts, r.write(alerts)
}

// Collect batch-reads the bounded LRU map. The iterator fallback covers older
// kernels or map implementations which reject batch lookup.
func Collect(m *ebpf.Map) (Snapshot, error) {
	s, _, _, err := collectInto(m, nil, nil, nil)
	return s, err
}

func collectInto(m *ebpf.Map, counters map[[20]byte]counter, keys [][20]byte, values []counter) (Snapshot, [][20]byte, []counter, error) {
	if counters == nil {
		counters = make(map[[20]byte]counter)
	} else {
		clear(counters)
	}
	s := Snapshot{Counters: counters, When: time.Now()}
	if m == nil {
		return s, keys, values, errors.New("flow monitor counter map unavailable")
	}
	capacity := int(m.MaxEntries())
	if cap(keys) < capacity {
		keys = make([][20]byte, capacity)
	} else {
		keys = keys[:capacity]
	}
	if cap(values) < capacity {
		values = make([]counter, capacity)
	} else {
		values = values[:capacity]
	}
	var cursor ebpf.MapBatchCursor
	for {
		n, err := m.BatchLookup(&cursor, keys, values, nil)
		for i := 0; i < n; i++ {
			s.Counters[keys[i]] = values[i]
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return s, keys, values, nil
		}
		if err != nil {
			break
		}
		if n == 0 {
			return s, keys, values, nil
		}
	}

	// Discard a possibly partial batch and take one coherent best-effort scan.
	clear(s.Counters)
	var key [20]byte
	var value counter
	it := m.Iterate()
	for it.Next(&key, &value) {
		s.Counters[key] = value
	}
	if err := it.Err(); err != nil {
		return s, keys, values, fmt.Errorf("scan flow monitor counters: %w", err)
	}
	return s, keys, values, nil
}

func alertsFrom(prev, cur Snapshot, fm config.FlowMonitoring) []Alert {
	secs := cur.When.Sub(prev.When).Seconds()
	if secs <= 0 {
		return nil
	}
	keys := make([][20]byte, 0, len(cur.Counters))
	for key := range cur.Counters {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })

	alerts := make([]Alert, 0)
	for _, key := range keys {
		flow := decodeFlow(key)
		rule, ok := longestMatch(net.ParseIP(flow.ProtectedIP), fm.CIDRs)
		if !ok {
			continue
		}
		curCount := cur.Counters[key]
		oldCount := prev.Counters[key]
		deltaPackets, deltaBytes := curCount.Packets, curCount.Bytes
		if curCount.Packets >= oldCount.Packets {
			deltaPackets = curCount.Packets - oldCount.Packets
		}
		if curCount.Bytes >= oldCount.Bytes {
			deltaBytes = curCount.Bytes - oldCount.Bytes
		}
		scale := float64(fm.SampleEvery)
		pps := scale * float64(deltaPackets) / secs
		mbps := scale * float64(deltaBytes) * 8 / secs / 1_000_000
		var exceeded []string
		if rule.PPSThreshold > 0 && pps > float64(rule.PPSThreshold) {
			exceeded = append(exceeded, "pps")
		}
		if rule.MbpsThreshold > 0 && mbps > rule.MbpsThreshold {
			exceeded = append(exceeded, "mbps")
		}
		if len(exceeded) == 0 {
			continue
		}
		alerts = append(alerts, Alert{
			Schema: 1, ObservedAt: cur.When.UTC(), WindowSeconds: secs, Flow: flow,
			MatchedCIDR: rule.CIDR, EstimatedPPS: pps, EstimatedMbps: mbps,
			ThresholdPPS: rule.PPSThreshold, ThresholdMbps: rule.MbpsThreshold,
			Exceeded: exceeded, SampleEvery: fm.SampleEvery,
		})
	}
	return alerts
}

func decodeFlow(key [20]byte) FlowID {
	vlans := binary.LittleEndian.Uint32(key[12:16])
	proto := "unknown"
	switch key[16] {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	}
	return FlowID{
		Protocol:      proto,
		InternetIP:    net.IP(append([]byte(nil), key[0:4]...)).String(),
		ProtectedIP:   net.IP(append([]byte(nil), key[4:8]...)).String(),
		InternetPort:  binary.BigEndian.Uint16(key[8:10]),
		ProtectedPort: binary.BigEndian.Uint16(key[10:12]),
		OuterVLAN:     uint16((vlans >> 12) & 0x0fff), InnerVLAN: uint16(vlans & 0x0fff),
	}
}

func longestMatch(ip net.IP, rules []config.FlowMonitorCIDR) (config.FlowMonitorCIDR, bool) {
	bestBits := -1
	var best config.FlowMonitorCIDR
	for _, rule := range rules {
		_, network, err := net.ParseCIDR(rule.CIDR)
		if err != nil || !network.Contains(ip) {
			continue
		}
		ones, _ := network.Mask.Size()
		if ones > bestBits {
			bestBits, best = ones, rule
		}
	}
	return best, bestBits >= 0
}

func (r *Reporter) write(alerts []Alert) error {
	if err := os.MkdirAll(r.StatsDir, 0o755); err != nil {
		return err
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	for _, alert := range alerts {
		if err := enc.Encode(alert); err != nil {
			return err
		}
	}
	dst := filepath.Join(r.StatsDir, Filename)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, body.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// ReadAlerts parses an atomically published snapshot for interactive clients.
func ReadAlerts(path string) ([]Alert, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var alerts []Alert
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var alert Alert
		if err := json.Unmarshal(scanner.Bytes(), &alert); err != nil {
			return nil, fmt.Errorf("parse flow alert line %d: %w", len(alerts)+1, err)
		}
		if alert.Schema != 1 {
			return nil, fmt.Errorf("unsupported flow alert schema %d", alert.Schema)
		}
		alerts = append(alerts, alert)
	}
	return alerts, scanner.Err()
}
