package stats

import (
	"testing"
	"time"
)

func TestRatesAndReset(t *testing.T) {
	base := time.Unix(100, 0)
	a := Snapshot{When: base, Vlans: map[uint16]vlanStatValue{7: {Pkts: 10}}}
	a.G.RxPkts = 100
	a.G.RxBytes = 1000
	a.Reasons[1] = 10
	b := Snapshot{When: base.Add(2 * time.Second), Vlans: map[uint16]vlanStatValue{7: {Pkts: 16}}}
	b.G.RxPkts = 120
	b.G.RxBytes = 1200
	b.Reasons[1] = 14
	r := Rates(&a, b)
	if r.ProcessedPPS != 10 || r.ProcessedBPS != 800 || r.ReasonPPS[1] != 2 || r.VLANPPS[7] != 3 {
		t.Fatalf("unexpected rates: %+v", r)
	}
	c := b
	c.When = c.When.Add(time.Second)
	c.G.RxPkts = 1
	if got := Rates(&b, c).ProcessedPPS; got != 0 {
		t.Fatalf("reset underflow: %v", got)
	}
}
