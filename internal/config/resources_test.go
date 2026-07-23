package config

import (
	"fmt"
	"os"
	"testing"
)

func TestDetectHostResourcesCgroupV2Ancestors(t *testing.T) {
	gib := uint64(1 << 30)
	files := map[string]string{
		"/proc/meminfo":                            "MemTotal: 16777216 kB\nMemAvailable: 12582912 kB\n",
		"/sys/devices/system/cpu/possible":         "0-7,16-19\n",
		"/sys/devices/system/cpu/online":           "0-7\n",
		"/proc/self/cgroup":                        "0::/tenant/job\n",
		"/sys/fs/cgroup/tenant/job/memory.max":     fmt.Sprint(6 * gib),
		"/sys/fs/cgroup/tenant/job/memory.current": fmt.Sprint(2 * gib),
		"/sys/fs/cgroup/tenant/memory.max":         fmt.Sprint(8 * gib),
		"/sys/fs/cgroup/tenant/memory.current":     fmt.Sprint(1 * gib),
		"/sys/fs/cgroup/memory.max":                "max",
	}
	read := func(path string) ([]byte, error) {
		if value, ok := files[path]; ok {
			return []byte(value), nil
		}
		return nil, os.ErrNotExist
	}

	got := detectHostResources(read)
	if got.EffectiveMemory != 6*gib || got.MemoryHeadroom != 4*gib {
		t.Fatalf("memory = effective %d headroom %d, want 6/4 GiB", got.EffectiveMemory, got.MemoryHeadroom)
	}
	if !got.LimitedByCgroup || got.PossibleCPUs != 12 || got.OnlineCPUs != 8 {
		t.Fatalf("unexpected detection: %+v", got)
	}
}

func TestDetectHostResourcesCgroupV1(t *testing.T) {
	gib := uint64(1 << 30)
	files := map[string]string{
		"/proc/meminfo":                                         "MemTotal: 8388608 kB\nMemAvailable: 6291456 kB\n",
		"/sys/devices/system/cpu/possible":                      "0-3\n",
		"/sys/devices/system/cpu/online":                        "0-3\n",
		"/proc/self/cgroup":                                     "5:cpu,cpuacct:/slice/job\n7:memory:/slice/job\n",
		"/sys/fs/cgroup/memory/slice/job/memory.limit_in_bytes": fmt.Sprint(4 * gib),
		"/sys/fs/cgroup/memory/slice/job/memory.usage_in_bytes": fmt.Sprint(1 * gib),
		"/sys/fs/cgroup/memory/slice/memory.limit_in_bytes":     fmt.Sprint(5 * gib),
		"/sys/fs/cgroup/memory/slice/memory.usage_in_bytes":     fmt.Sprint(2 * gib),
	}
	read := func(path string) ([]byte, error) {
		if value, ok := files[path]; ok {
			return []byte(value), nil
		}
		return nil, os.ErrNotExist
	}

	got := detectHostResources(read)
	if got.EffectiveMemory != 4*gib || got.MemoryHeadroom != 3*gib || !got.LimitedByCgroup {
		t.Fatalf("unexpected v1 memory detection: %+v", got)
	}
}

func TestRecommendDedicated(t *testing.T) {
	gib := uint64(1 << 30)
	tests := []struct {
		name      string
		resources HostResources
		wantL1    bool
		wantCaps  bool
	}{
		{
			name:      "low memory disables L1",
			resources: HostResources{EffectiveMemory: 128 << 20, MemoryHeadroom: 128 << 20, PossibleCPUs: 64},
			wantL1:    false,
		},
		{
			name:      "ordinary appliance enables L1",
			resources: HostResources{EffectiveMemory: 16 * gib, MemoryHeadroom: 12 * gib, PossibleCPUs: 16},
			wantL1:    true,
		},
		{
			name:      "large appliance applies flow caps",
			resources: HostResources{EffectiveMemory: 1 << 40, MemoryHeadroom: 1 << 40, PossibleCPUs: 128},
			wantL1:    true,
			wantCaps:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RecommendDedicated(tt.resources)
			if (got.L1Size != 0) != tt.wantL1 {
				t.Fatalf("L1Size = %d", got.L1Size)
			}
			if got.FlowMax%1024 != 0 || got.UDPFlowMax%1024 != 0 {
				t.Fatalf("flow sizes are not 1024-entry aligned: %+v", got)
			}
			if got.L1Size > 1<<16 || got.FlowMax > 1<<26 || got.UDPFlowMax > 1<<24 {
				t.Fatalf("recommendation exceeds cap: %+v", got)
			}
			wantBudgetCap := min64(tt.resources.EffectiveMemory/3, tt.resources.MemoryHeadroom) * 4 / 5
			if got.MapBudgetBytes != wantBudgetCap {
				t.Fatalf("map budget = %d, want %d", got.MapBudgetBytes, wantBudgetCap)
			}
			if tt.wantCaps && (got.FlowMax != 1<<26 || got.UDPFlowMax != 1<<24) {
				t.Fatalf("flow caps not reached: %+v", got)
			}
		})
	}
}

func TestDefaultIsDeterministic(t *testing.T) {
	a, b := Default(), Default()
	if a.FlowMax != b.FlowMax || a.UDPFlowMax != b.UDPFlowMax || a.L1Size != b.L1Size {
		t.Fatalf("Default resource sizing changed between calls: %+v != %+v", a, b)
	}
}
