package tuning

import "testing"

const ethtoolRingsFixture = `Ring parameters for eth0:
Pre-set maximums:
RX:		8192
TX:		4096
Current hardware settings:
RX:		1024
TX:		2048
`

const ethtoolChannelsFixture = `Channel parameters for eth0:
Pre-set maximums:
RX:		n/a
TX:		n/a
Combined:	32
Current hardware settings:
RX:		n/a
TX:		n/a
Combined:	8
`

func TestParseEthtoolLimits(t *testing.T) {
	rings, ok := parseRingInfo(ethtoolRingsFixture)
	if !ok || rings.maxRX != 8192 || rings.maxTX != 4096 ||
		rings.currentRX != "1024" || rings.currentTX != "2048" {
		t.Fatalf("rings = %+v, ok %v", rings, ok)
	}
	channels, ok := parseChannelInfo(ethtoolChannelsFixture)
	if !ok || channels.maximum != 32 || channels.current != "8" {
		t.Fatalf("channels = %+v, ok %v", channels, ok)
	}
}

func TestResolveCommonChannels(t *testing.T) {
	ports := []channelLimit{
		{cpus: 15, maximum: 32},
		{cpus: 7, maximum: 4},
	}
	if got := resolveCommonChannels(0, ports); got != 4 {
		t.Fatalf("automatic channels = %d, want 4", got)
	}
	if got := resolveCommonChannels(16, ports); got != 4 {
		t.Fatalf("clamped channels = %d, want 4", got)
	}
	if got := resolveCommonChannels(2, ports); got != 2 {
		t.Fatalf("explicit safe channels = %d, want 2", got)
	}
}

func TestIntersectCPUsDropsOfflineAndDisallowed(t *testing.T) {
	local := parseCPUList("0-7")
	online := parseCPUList("0-3,6-7")
	allowed := parseCPUList("1-2,6")
	got := intersectCPUs(local, online, allowed)
	want := []int{1, 2, 6}
	if len(got) != len(want) {
		t.Fatalf("CPUs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CPUs = %v, want %v", got, want)
		}
	}
}
