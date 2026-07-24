// SPDX-License-Identifier: GPL-2.0

// Package config loads and persists /etc/xdpfilter/config.yaml.
package config

import (
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultPath    = "/etc/xdpfilter/config.yaml"
	DefaultPinDir  = "/sys/fs/bpf/xdpfilter"
	DefaultStatDir = "/var/lib/xdp_stats"
)

// Config is the on-disk configuration written by the wizard and read by the daemon.
type Config struct {
	// Ports of the transparent bridge.
	TrustedIface   string `yaml:"trusted_iface"`
	UntrustedIface string `yaml:"untrusted_iface"`

	// Datapath policy.
	Mode                string   `yaml:"mode"`                  // "monitor" | "enforce"
	OosStrict           bool     `yaml:"oos_strict"`            // false => adopt (default)
	AllowInboundServers bool     `yaml:"allow_inbound_servers"` // permit inbound SYN to allowlist
	AllowInboundSYN     bool     `yaml:"allow_inbound_syn"`     // permit inbound TCP SYN to any protected destination
	ServerAllow         []string `yaml:"server_allow"`          // "ip:port" entries
	DropFrags           bool     `yaml:"drop_frags"`            // default true
	DropBadFlags        bool     `yaml:"drop_bad_flags"`        // default true
	FilterUDP           bool     `yaml:"filter_udp"`            // stateful UDP filtering (default true)
	DropVlanDeep        bool     `yaml:"drop_vlan_deep"`        // drop frames with > 2 VLAN tags (default false)
	DropUDPFrags        bool     `yaml:"drop_udp_frags"`        // drop non-first UDP fragments (default false)
	RejectWithRST       bool     `yaml:"reject_with_rst"`       // untrusted side answers enforced TCP drops with a RST to the source (default false)

	// Flow table.
	FlowMax    uint32 `yaml:"flow_max"`     // TCP LRU capacity (entries)
	UDPFlowMax uint32 `yaml:"udp_flow_max"` // UDP LRU capacity (entries)
	L1Size     uint32 `yaml:"l1_size"`      // per-CPU L1 flow-cache slots (power of two; 0 disables)
	LRUPerCPU  bool   `yaml:"lru_percpu"`   // BPF_F_NO_COMMON_LRU on the flow tables (per-CPU LRU)
	TTLSyn     uint32 `yaml:"ttl_syn"`      // seconds
	TTLEst     uint32 `yaml:"ttl_est"`      // seconds
	TTLClosing uint32 `yaml:"ttl_closing"`  // seconds
	TTLUdp     uint32 `yaml:"ttl_udp"`      // seconds

	// Runtime.
	XDPMode          string `yaml:"xdp_mode"`          // "native" | "generic" | "auto" (native, fall back to generic)
	Tune             bool   `yaml:"tune"`              // apply perf tuning on start
	StatsDir         string `yaml:"stats_dir"`         //
	StatsInterval    int    `yaml:"stats_interval"`    // seconds
	GCInterval       int    `yaml:"gc_interval"`       // seconds
	HousekeepingCore int    `yaml:"housekeeping_core"` // -1 => auto (last core)
	PinDir           string `yaml:"pin_dir"`

	// Sampled inbound flow-volume monitoring.
	FlowMonitoring FlowMonitoring `yaml:"flow_monitoring"`

	// Tuning knobs (empty => derive from box). Overridable for expert control.
	Tuning Tuning `yaml:"tuning"`
}

// FlowMonitoring controls sampled per-flow inbound volume accounting.
type FlowMonitoring struct {
	Enabled     bool              `yaml:"enabled"`
	SampleEvery uint32            `yaml:"sample_every"` // power of two; 1 is exact
	MaxFlows    uint32            `yaml:"max_flows"`    // sampled counter-map capacity
	CIDRs       []FlowMonitorCIDR `yaml:"cidrs"`
}

// FlowMonitorCIDR applies per-flow thresholds to protected IPs in CIDR.
// A zero threshold disables that metric; at least one metric must be positive.
type FlowMonitorCIDR struct {
	CIDR          string  `yaml:"cidr"`
	PPSThreshold  uint64  `yaml:"pps_threshold"`
	MbpsThreshold float64 `yaml:"mbps_threshold"`
}

// Tuning holds NIC/kernel tuning overrides. Zero rings and softnet values
// retain the current driver/kernel setting; zero channels are auto-resolved.
type Tuning struct {
	RingSize      uint32 `yaml:"ring_size"`          // ethtool -G rx/tx (0 => retain)
	Channels      uint32 `yaml:"channels"`           // 0 => common NUMA/hardware limit
	SymmetricRSS  *bool  `yaml:"symmetric_rss"`      // nil => true
	CQECompress   *bool  `yaml:"cqe_compress"`       // nil => true
	DisableLRO    *bool  `yaml:"disable_lro"`        // nil => true
	DisableVLANHW *bool  `yaml:"disable_vlan_hw"`    // nil => true (rxvlan/txvlan off)
	DisableIRQBal *bool  `yaml:"disable_irqbalance"` // nil => true
	Governor      string `yaml:"governor"`           // "" => performance
	NetdevBacklog uint32 `yaml:"netdev_max_backlog"` // 0 => retain
	NetdevBudget  uint32 `yaml:"netdev_budget"`      // 0 => retain
}

// Default returns a config with production-sane defaults.
func Default() *Config {
	return &Config{
		Mode:             "monitor", // safe first-run default
		OosStrict:        false,
		AllowInboundSYN:  false,
		DropFrags:        true,
		DropBadFlags:     true,
		FilterUDP:        true,
		DropVlanDeep:     false,
		DropUDPFrags:     false,
		RejectWithRST:    false,
		FlowMax:          1 << 24, // 16M entries ≈ 2 GiB (~128 B/entry)
		UDPFlowMax:       1 << 22, // 4M entries ≈ 512 MiB
		L1Size:           1 << 16, // 64K slots/CPU × 24 B ≈ 1.5 MiB/CPU
		TTLSyn:           10,
		TTLEst:           300,
		TTLClosing:       10,
		TTLUdp:           30,
		XDPMode:          "native",
		Tune:             true,
		StatsDir:         DefaultStatDir,
		StatsInterval:    10,
		GCInterval:       2,
		HousekeepingCore: -1,
		PinDir:           DefaultPinDir,
		FlowMonitoring: FlowMonitoring{
			SampleEvery: 64,
			MaxFlows:    1 << 18,
			CIDRs:       []FlowMonitorCIDR{},
		},
	}
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Default()
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Save atomically writes the config file.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Validate checks required fields and value ranges.
func (c *Config) Validate() error {
	if c.TrustedIface == "" || c.UntrustedIface == "" {
		return fmt.Errorf("trusted_iface and untrusted_iface are required")
	}
	if c.TrustedIface == c.UntrustedIface {
		return fmt.Errorf("trusted and untrusted interfaces must differ")
	}
	if c.Mode != "monitor" && c.Mode != "enforce" {
		return fmt.Errorf("mode must be monitor or enforce, got %q", c.Mode)
	}
	if c.XDPMode != "native" && c.XDPMode != "generic" && c.XDPMode != "auto" {
		return fmt.Errorf("xdp_mode must be native, generic, or auto, got %q", c.XDPMode)
	}
	if c.FlowMax < 1024 {
		return fmt.Errorf("flow_max too small: %d", c.FlowMax)
	}
	if c.UDPFlowMax < 1024 {
		c.UDPFlowMax = 1 << 22
	}
	// L1 cache size must be a power of two (the BPF side masks with size-1).
	// 0 disables it. A tiny non-zero value is bumped to a sane floor.
	if c.L1Size != 0 {
		if c.L1Size < 1024 {
			c.L1Size = 1024
		}
		if c.L1Size&(c.L1Size-1) != 0 {
			return fmt.Errorf("l1_size must be a power of two or 0, got %d", c.L1Size)
		}
	}
	if c.TTLUdp == 0 {
		c.TTLUdp = 30
	}
	for _, s := range c.ServerAllow {
		if _, _, err := ParseHostPort(s); err != nil {
			return fmt.Errorf("server_allow %q: %w", s, err)
		}
	}
	if c.StatsDir == "" {
		c.StatsDir = DefaultStatDir
	}
	if c.PinDir == "" {
		c.PinDir = DefaultPinDir
	}
	if c.StatsInterval <= 0 {
		c.StatsInterval = 10
	}
	if c.GCInterval <= 0 {
		c.GCInterval = 2
	}
	if err := c.validateFlowMonitoring(); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateFlowMonitoring() error {
	f := &c.FlowMonitoring
	if f.SampleEvery == 0 {
		f.SampleEvery = 64
	}
	if f.SampleEvery > 65536 || f.SampleEvery&(f.SampleEvery-1) != 0 {
		return fmt.Errorf("flow_monitoring.sample_every must be a power of two from 1 to 65536, got %d", f.SampleEvery)
	}
	if f.MaxFlows == 0 {
		f.MaxFlows = 1 << 18
	}
	if f.MaxFlows < 1024 || f.MaxFlows > 1<<20 {
		return fmt.Errorf("flow_monitoring.max_flows must be from 1024 to 1048576, got %d", f.MaxFlows)
	}
	if len(f.CIDRs) > 4096 {
		return fmt.Errorf("flow_monitoring.cidrs has %d entries; maximum is 4096", len(f.CIDRs))
	}
	seen := make(map[string]struct{}, len(f.CIDRs))
	for i := range f.CIDRs {
		r := &f.CIDRs[i]
		ip, network, err := net.ParseCIDR(strings.TrimSpace(r.CIDR))
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("flow_monitoring.cidrs[%d].cidr must be an IPv4 CIDR, got %q", i, r.CIDR)
		}
		canonical := network.String()
		if strings.TrimSpace(r.CIDR) != canonical {
			return fmt.Errorf("flow_monitoring.cidrs[%d].cidr must be canonical %q, got %q", i, canonical, r.CIDR)
		}
		if _, ok := seen[canonical]; ok {
			return fmt.Errorf("flow_monitoring.cidrs contains duplicate %q", canonical)
		}
		seen[canonical] = struct{}{}
		if r.PPSThreshold == 0 && r.MbpsThreshold == 0 {
			return fmt.Errorf("flow_monitoring.cidrs[%d] must have a positive pps_threshold or mbps_threshold", i)
		}
		if r.MbpsThreshold < 0 || math.IsNaN(r.MbpsThreshold) || math.IsInf(r.MbpsThreshold, 0) {
			return fmt.Errorf("flow_monitoring.cidrs[%d].mbps_threshold must be finite and non-negative", i)
		}
	}
	return nil
}

// ParseHostPort parses "1.2.3.4:80" into an IPv4 and port.
func ParseHostPort(s string) (net.IP, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, 0, fmt.Errorf("not an IPv4 address: %q", host)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("bad port %q: %w", portStr, err)
	}
	return ip, uint16(p), nil
}

// Exists reports whether a config file is present.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ApplyLiveFrom copies the fields that can be changed live (no reattach): policy
// toggles, TTLs and the server allowlist. Structural fields are left untouched.
func (c *Config) ApplyLiveFrom(src *Config) {
	c.Mode = src.Mode
	c.OosStrict = src.OosStrict
	c.AllowInboundServers = src.AllowInboundServers
	c.AllowInboundSYN = src.AllowInboundSYN
	c.DropFrags = src.DropFrags
	c.DropBadFlags = src.DropBadFlags
	c.FilterUDP = src.FilterUDP
	c.DropVlanDeep = src.DropVlanDeep
	c.DropUDPFrags = src.DropUDPFrags
	c.RejectWithRST = src.RejectWithRST
	c.ServerAllow = append([]string(nil), src.ServerAllow...)
	c.TTLSyn, c.TTLEst, c.TTLClosing, c.TTLUdp = src.TTLSyn, src.TTLEst, src.TTLClosing, src.TTLUdp
	c.FlowMonitoring.Enabled = src.FlowMonitoring.Enabled
	c.FlowMonitoring.SampleEvery = src.FlowMonitoring.SampleEvery
	c.FlowMonitoring.CIDRs = append([]FlowMonitorCIDR(nil), src.FlowMonitoring.CIDRs...)
}

// StructuralDiff returns a non-empty reason if src changes a field that can only
// take effect on a full restart (interfaces, table sizes, xdp mode, pin dir).
func (c *Config) StructuralDiff(src *Config) string {
	d := Diff(c, src)
	if d.Impact < ImpactRestart {
		return ""
	}
	return d.Summary()
}

// Clone returns a deep copy suitable for staged editing.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	out := *c
	out.ServerAllow = append([]string(nil), c.ServerAllow...)
	out.FlowMonitoring.CIDRs = append([]FlowMonitorCIDR(nil), c.FlowMonitoring.CIDRs...)
	cloneBool := func(p *bool) *bool {
		if p == nil {
			return nil
		}
		v := *p
		return &v
	}
	out.Tuning.SymmetricRSS = cloneBool(c.Tuning.SymmetricRSS)
	out.Tuning.CQECompress = cloneBool(c.Tuning.CQECompress)
	out.Tuning.DisableLRO = cloneBool(c.Tuning.DisableLRO)
	out.Tuning.DisableVLANHW = cloneBool(c.Tuning.DisableVLANHW)
	out.Tuning.DisableIRQBal = cloneBool(c.Tuning.DisableIRQBal)
	return &out
}

// ChangeImpact describes the least disruptive action required by a config change.
type ChangeImpact uint8

const (
	ImpactNone ChangeImpact = iota
	ImpactLive
	ImpactRestart
	ImpactReattach
)

func (i ChangeImpact) String() string {
	switch i {
	case ImpactLive:
		return "live"
	case ImpactRestart:
		return "restart"
	case ImpactReattach:
		return "reattach"
	default:
		return "none"
	}
}

// ChangeSet is a field-level diff ordered in the same groups as Config.
type ChangeSet struct {
	Impact ChangeImpact
	Fields []string
}

func (d ChangeSet) Empty() bool { return len(d.Fields) == 0 }

func (d ChangeSet) Summary() string {
	if len(d.Fields) == 0 {
		return ""
	}
	return d.Impact.String() + " required: " + strings.Join(d.Fields, ", ")
}

// Diff classifies every persisted Config field as live, restart, or reattach.
func Diff(a, b *Config) ChangeSet {
	var out ChangeSet
	add := func(impact ChangeImpact, name string, changed bool) {
		if !changed {
			return
		}
		out.Fields = append(out.Fields, name)
		if impact > out.Impact {
			out.Impact = impact
		}
	}
	if a == nil || b == nil {
		return ChangeSet{Impact: ImpactReattach, Fields: []string{"configuration"}}
	}
	add(ImpactReattach, "trusted_iface", a.TrustedIface != b.TrustedIface)
	add(ImpactReattach, "untrusted_iface", a.UntrustedIface != b.UntrustedIface)
	add(ImpactLive, "mode", a.Mode != b.Mode)
	add(ImpactLive, "oos_strict", a.OosStrict != b.OosStrict)
	add(ImpactLive, "allow_inbound_servers", a.AllowInboundServers != b.AllowInboundServers)
	add(ImpactLive, "allow_inbound_syn", a.AllowInboundSYN != b.AllowInboundSYN)
	add(ImpactLive, "server_allow", !reflect.DeepEqual(a.ServerAllow, b.ServerAllow))
	add(ImpactLive, "drop_frags", a.DropFrags != b.DropFrags)
	add(ImpactLive, "drop_bad_flags", a.DropBadFlags != b.DropBadFlags)
	add(ImpactLive, "filter_udp", a.FilterUDP != b.FilterUDP)
	add(ImpactLive, "drop_vlan_deep", a.DropVlanDeep != b.DropVlanDeep)
	add(ImpactLive, "drop_udp_frags", a.DropUDPFrags != b.DropUDPFrags)
	add(ImpactLive, "reject_with_rst", a.RejectWithRST != b.RejectWithRST)
	add(ImpactRestart, "flow_max", a.FlowMax != b.FlowMax)
	add(ImpactRestart, "udp_flow_max", a.UDPFlowMax != b.UDPFlowMax)
	add(ImpactRestart, "l1_size", a.L1Size != b.L1Size)
	add(ImpactRestart, "lru_percpu", a.LRUPerCPU != b.LRUPerCPU)
	add(ImpactLive, "ttl_syn", a.TTLSyn != b.TTLSyn)
	add(ImpactLive, "ttl_est", a.TTLEst != b.TTLEst)
	add(ImpactLive, "ttl_closing", a.TTLClosing != b.TTLClosing)
	add(ImpactLive, "ttl_udp", a.TTLUdp != b.TTLUdp)
	add(ImpactReattach, "xdp_mode", a.XDPMode != b.XDPMode)
	add(ImpactRestart, "tune", a.Tune != b.Tune)
	add(ImpactRestart, "stats_dir", a.StatsDir != b.StatsDir)
	add(ImpactRestart, "stats_interval", a.StatsInterval != b.StatsInterval)
	add(ImpactRestart, "gc_interval", a.GCInterval != b.GCInterval)
	add(ImpactRestart, "housekeeping_core", a.HousekeepingCore != b.HousekeepingCore)
	add(ImpactReattach, "pin_dir", a.PinDir != b.PinDir)
	add(ImpactLive, "flow_monitoring.enabled", a.FlowMonitoring.Enabled != b.FlowMonitoring.Enabled)
	add(ImpactLive, "flow_monitoring.sample_every", a.FlowMonitoring.SampleEvery != b.FlowMonitoring.SampleEvery)
	add(ImpactRestart, "flow_monitoring.max_flows", a.FlowMonitoring.MaxFlows != b.FlowMonitoring.MaxFlows)
	add(ImpactLive, "flow_monitoring.cidrs", !reflect.DeepEqual(a.FlowMonitoring.CIDRs, b.FlowMonitoring.CIDRs))
	add(ImpactRestart, "tuning", !reflect.DeepEqual(a.Tuning, b.Tuning))
	return out
}
