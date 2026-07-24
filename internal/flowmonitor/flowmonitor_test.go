package flowmonitor

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/consi/xdpfilter/internal/config"
	"github.com/consi/xdpfilter/internal/dataplane"
)

func testKey(proto byte, protected, internet string, protectedPort, internetPort, outer, inner uint16) [20]byte {
	var key [20]byte
	copy(key[0:4], net.ParseIP(internet).To4())
	copy(key[4:8], net.ParseIP(protected).To4())
	binary.BigEndian.PutUint16(key[8:10], internetPort)
	binary.BigEndian.PutUint16(key[10:12], protectedPort)
	binary.LittleEndian.PutUint32(key[12:16], uint32(outer)<<12|uint32(inner))
	key[16] = proto
	return key
}

func TestAlertsScaleAndUseEitherThreshold(t *testing.T) {
	key := testKey(6, "10.0.0.10", "203.0.113.5", 443, 50000, 7, 2)
	when := time.Unix(100, 0)
	prev := Snapshot{When: when, Counters: map[[20]byte]counter{key: {Packets: 100, Bytes: 100000}}}
	cur := Snapshot{When: when.Add(time.Second), Counters: map[[20]byte]counter{key: {Packets: 102, Bytes: 102000}}}
	fm := config.FlowMonitoring{Enabled: true, SampleEvery: 64, CIDRs: []config.FlowMonitorCIDR{{
		CIDR: "10.0.0.0/24", PPSThreshold: 100, MbpsThreshold: 2,
	}}}
	alerts := alertsFrom(prev, cur, fm)
	if len(alerts) != 1 {
		t.Fatalf("alerts=%d, want 1", len(alerts))
	}
	got := alerts[0]
	if got.EstimatedPPS != 128 || len(got.Exceeded) != 1 || got.Exceeded[0] != "pps" {
		t.Fatalf("unexpected alert: %+v", got)
	}
	if got.Flow.Protocol != "tcp" || got.Flow.ProtectedPort != 443 || got.Flow.OuterVLAN != 7 || got.Flow.InnerVLAN != 2 {
		t.Fatalf("bad decoded flow: %+v", got.Flow)
	}
}

func TestLongestPrefixWins(t *testing.T) {
	key := testKey(17, "10.0.0.10", "203.0.113.5", 53, 50000, 0, 0)
	when := time.Unix(100, 0)
	prev := Snapshot{When: when, Counters: map[[20]byte]counter{key: {}}}
	cur := Snapshot{When: when.Add(time.Second), Counters: map[[20]byte]counter{key: {Packets: 2}}}
	fm := config.FlowMonitoring{Enabled: true, SampleEvery: 64, CIDRs: []config.FlowMonitorCIDR{
		{CIDR: "10.0.0.0/8", PPSThreshold: 10},
		{CIDR: "10.0.0.0/24", PPSThreshold: 200},
	}}
	if alerts := alertsFrom(prev, cur, fm); len(alerts) != 0 {
		t.Fatalf("less-specific rule won: %+v", alerts)
	}
}

func TestCounterResetUsesFreshValue(t *testing.T) {
	key := testKey(6, "10.0.0.10", "203.0.113.5", 443, 50000, 0, 0)
	when := time.Unix(100, 0)
	prev := Snapshot{When: when, Counters: map[[20]byte]counter{key: {Packets: 1000}}}
	cur := Snapshot{When: when.Add(time.Second), Counters: map[[20]byte]counter{key: {Packets: 2}}}
	fm := config.FlowMonitoring{Enabled: true, SampleEvery: 64, CIDRs: []config.FlowMonitorCIDR{{CIDR: "10.0.0.0/24", PPSThreshold: 100}}}
	alerts := alertsFrom(prev, cur, fm)
	if len(alerts) != 1 || alerts[0].EstimatedPPS != 128 {
		t.Fatalf("reset rate: %+v", alerts)
	}
}

func TestNDJSONRoundTripAndEmptySnapshot(t *testing.T) {
	dir := t.TempDir()
	r := NewReporter(dir)
	alert := Alert{Schema: 1, ObservedAt: time.Unix(100, 0).UTC(), Flow: FlowID{Protocol: "tcp"}, Exceeded: []string{"pps"}}
	if err := r.write([]Alert{alert}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, Filename)
	got, err := ReadAlerts(path)
	if err != nil || len(got) != 1 || got[0].Schema != 1 {
		t.Fatalf("ReadAlerts: %+v, %v", got, err)
	}
	if err := r.write(nil); err != nil {
		t.Fatal(err)
	}
	got, err = ReadAlerts(path)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty ReadAlerts: %+v, %v", got, err)
	}
}

func TestEnabledWithNoRulesPublishesEmptyWithoutMaps(t *testing.T) {
	dir := t.TempDir()
	r := NewReporter(dir)
	cfg := config.Default()
	cfg.FlowMonitoring.Enabled = true
	cfg.FlowMonitoring.CIDRs = nil
	if alerts, err := r.Tick(&dataplane.SharedMaps{}, cfg); err != nil || len(alerts) != 0 {
		t.Fatalf("Tick() alerts=%v err=%v", alerts, err)
	}
	alerts, err := ReadAlerts(filepath.Join(dir, Filename))
	if err != nil || len(alerts) != 0 {
		t.Fatalf("ReadAlerts() alerts=%v err=%v", alerts, err)
	}
}
