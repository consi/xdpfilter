package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

func validConfig() *Config {
	c := Default()
	c.TrustedIface, c.UntrustedIface = "eth0", "eth1"
	return c
}

func TestDiffImpact(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
		want   ChangeImpact
	}{
		{"live mode", func(c *Config) { c.Mode = "enforce" }, ImpactLive},
		{"live allowlist", func(c *Config) { c.ServerAllow = []string{"10.0.0.1:53"} }, ImpactLive},
		{"live flow monitor", func(c *Config) { c.FlowMonitoring.Enabled = true }, ImpactLive},
		{"live flow rules", func(c *Config) { c.FlowMonitoring.CIDRs = []FlowMonitorCIDR{{CIDR: "10.0.0.0/24", PPSThreshold: 100}} }, ImpactLive},
		{"restart table", func(c *Config) { c.FlowMax++ }, ImpactRestart},
		{"restart monitor capacity", func(c *Config) { c.FlowMonitoring.MaxFlows++ }, ImpactRestart},
		{"restart runtime", func(c *Config) { c.StatsInterval++ }, ImpactRestart},
		{"restart tuning", func(c *Config) { c.Tuning.RingSize = 512 }, ImpactRestart},
		{"reattach interface", func(c *Config) { c.TrustedIface = "eth2" }, ImpactReattach},
		{"reattach mode", func(c *Config) { c.XDPMode = "generic" }, ImpactReattach},
		{"reattach pin", func(c *Config) { c.PinDir = "/sys/fs/bpf/other" }, ImpactReattach},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := validConfig()
			b := a.Clone()
			tt.change(b)
			if got := Diff(a, b).Impact; got != tt.want {
				t.Fatalf("impact=%v want %v", got, tt.want)
			}
		})
	}
}

func TestCloneDoesNotAliasAllowlist(t *testing.T) {
	a := validConfig()
	a.ServerAllow = []string{"10.0.0.1:53"}
	b := a.Clone()
	b.ServerAllow[0] = "10.0.0.2:53"
	if a.ServerAllow[0] == b.ServerAllow[0] {
		t.Fatal("Clone aliased ServerAllow")
	}
}

func TestCloneDoesNotAliasFlowMonitorCIDRs(t *testing.T) {
	a := validConfig()
	a.FlowMonitoring.CIDRs = []FlowMonitorCIDR{{CIDR: "10.0.0.0/24", PPSThreshold: 100}}
	b := a.Clone()
	b.FlowMonitoring.CIDRs[0].CIDR = "10.1.0.0/24"
	if a.FlowMonitoring.CIDRs[0].CIDR == b.FlowMonitoring.CIDRs[0].CIDR {
		t.Fatal("Clone aliased FlowMonitoring.CIDRs")
	}
}

func TestFlowMonitoringValidation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*FlowMonitoring)
		ok   bool
	}{
		{"valid pps", func(f *FlowMonitoring) { f.CIDRs = []FlowMonitorCIDR{{CIDR: "10.0.0.0/24", PPSThreshold: 1}} }, true},
		{"valid mbps", func(f *FlowMonitoring) { f.CIDRs = []FlowMonitorCIDR{{CIDR: "10.0.0.0/24", MbpsThreshold: .5}} }, true},
		{"noncanonical", func(f *FlowMonitoring) { f.CIDRs = []FlowMonitorCIDR{{CIDR: "10.0.0.1/24", PPSThreshold: 1}} }, false},
		{"ipv6", func(f *FlowMonitoring) { f.CIDRs = []FlowMonitorCIDR{{CIDR: "2001:db8::/32", PPSThreshold: 1}} }, false},
		{"no threshold", func(f *FlowMonitoring) { f.CIDRs = []FlowMonitorCIDR{{CIDR: "10.0.0.0/24"}} }, false},
		{"duplicate", func(f *FlowMonitoring) {
			f.CIDRs = []FlowMonitorCIDR{{CIDR: "10.0.0.0/24", PPSThreshold: 1}, {CIDR: "10.0.0.0/24", PPSThreshold: 2}}
		}, false},
		{"overlap allowed", func(f *FlowMonitoring) {
			f.CIDRs = []FlowMonitorCIDR{{CIDR: "10.0.0.0/8", PPSThreshold: 1}, {CIDR: "10.0.0.0/24", PPSThreshold: 2}}
		}, true},
		{"bad sample", func(f *FlowMonitoring) { f.SampleEvery = 3 }, false},
		{"small map", func(f *FlowMonitoring) { f.MaxFlows = 100 }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.edit(&c.FlowMonitoring)
			if err := c.Validate(); (err == nil) != tt.ok {
				t.Fatalf("Validate() err=%v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestFlowMonitoringYAMLRoundTrip(t *testing.T) {
	c := validConfig()
	c.FlowMonitoring = FlowMonitoring{Enabled: true, SampleEvery: 128, MaxFlows: 65536, CIDRs: []FlowMonitorCIDR{
		{CIDR: "10.0.0.0/24", PPSThreshold: 100, MbpsThreshold: 12.5},
	}}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.FlowMonitoring, c.FlowMonitoring) {
		t.Fatalf("flow monitoring round-trip: got %+v want %+v", got.FlowMonitoring, c.FlowMonitoring)
	}
}
