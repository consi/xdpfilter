// SPDX-License-Identifier: GPL-2.0

// Package config loads and persists /etc/xdpfilter/config.yaml.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

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
	ServerAllow         []string `yaml:"server_allow"`          // "ip:port" entries
	DropFrags           bool     `yaml:"drop_frags"`            // default true
	DropBadFlags        bool     `yaml:"drop_bad_flags"`        // default true
	FilterUDP           bool     `yaml:"filter_udp"`            // stateful UDP filtering (default true)
	DropVlanDeep        bool     `yaml:"drop_vlan_deep"`        // drop frames with > 2 VLAN tags (default false)
	DropUDPFrags        bool     `yaml:"drop_udp_frags"`        // drop non-first UDP fragments (default false)

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

	// Tuning knobs (empty => derive from box). Overridable for expert control.
	Tuning Tuning `yaml:"tuning"`
}

// Tuning holds NIC/kernel tuning overrides. Zero values mean "derive/skip".
type Tuning struct {
	RingSize      uint32 `yaml:"ring_size"`          // ethtool -G rx/tx (0 => 8192)
	Channels      uint32 `yaml:"channels"`           // ethtool -L combined (0 => NUMA-local cores)
	SymmetricRSS  *bool  `yaml:"symmetric_rss"`      // nil => true
	CQECompress   *bool  `yaml:"cqe_compress"`       // nil => true
	DisableLRO    *bool  `yaml:"disable_lro"`        // nil => true
	DisableVLANHW *bool  `yaml:"disable_vlan_hw"`    // nil => true (rxvlan/txvlan off)
	DisableIRQBal *bool  `yaml:"disable_irqbalance"` // nil => true
	Governor      string `yaml:"governor"`           // "" => performance
	NetdevBacklog uint32 `yaml:"netdev_max_backlog"` // 0 => 250000
	NetdevBudget  uint32 `yaml:"netdev_budget"`      // 0 => 600
}

// Default returns a config with production-sane defaults.
func Default() *Config {
	return &Config{
		Mode:             "monitor", // safe first-run default
		OosStrict:        false,
		DropFrags:        true,
		DropBadFlags:     true,
		FilterUDP:        true,
		DropVlanDeep:     false,
		DropUDPFrags:     false,
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
	c.DropFrags = src.DropFrags
	c.DropBadFlags = src.DropBadFlags
	c.FilterUDP = src.FilterUDP
	c.DropVlanDeep = src.DropVlanDeep
	c.DropUDPFrags = src.DropUDPFrags
	c.ServerAllow = src.ServerAllow
	c.TTLSyn, c.TTLEst, c.TTLClosing, c.TTLUdp = src.TTLSyn, src.TTLEst, src.TTLClosing, src.TTLUdp
}

// StructuralDiff returns a non-empty reason if src changes a field that can only
// take effect on a full restart (interfaces, table sizes, xdp mode, pin dir).
func (c *Config) StructuralDiff(src *Config) string {
	switch {
	case c.TrustedIface != src.TrustedIface || c.UntrustedIface != src.UntrustedIface:
		return "interfaces"
	case c.FlowMax != src.FlowMax || c.UDPFlowMax != src.UDPFlowMax:
		return "flow-table size"
	case c.L1Size != src.L1Size:
		return "l1_size"
	case c.LRUPerCPU != src.LRUPerCPU:
		return "lru_percpu"
	case c.XDPMode != src.XDPMode:
		return "xdp_mode"
	case c.PinDir != src.PinDir:
		return "pin_dir"
	}
	return ""
}
