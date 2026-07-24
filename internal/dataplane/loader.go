// SPDX-License-Identifier: GPL-2.0

// Package dataplane loads, attaches and manages the XDP filter.
//
// The single BPF object is loaded twice — once per port — with different
// rodata constants (ROLE_TRUSTED, PEER_IDX) so the verifier prunes the other
// role's branches. Both program instances share one set of maps (the flow
// table, stats, policy) via MapReplacements. Maps and links are pinned under
// PinDir, so the datapath survives a daemon crash/restart and upgrades swap the
// program atomically via link.Update.
package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/consi/xdpfilter/internal/config"
)

// nowShift must match NOW_SHIFT in bpf/filter.h: the coarse-time unit is
// bpf_ktime_get_coarse_ns >> nowShift (1 tick ≈ 1.073741824 s). TTLs written to
// the features map and the GC clock are all in these ticks.
const nowShift = 30

// BPF_F_NO_COMMON_LRU is Linux UAPI bit 1. Keep the numeric value local so the
// control plane and its unit tests also compile on non-Linux development hosts.
const bpfFNoCommonLRU = 1 << 1

// secToTicks converts a TTL in seconds to coarse ticks, rounding up so a
// positive TTL never collapses to zero.
func secToTicks(sec uint32) uint32 {
	if sec == 0 {
		return 0
	}
	ns := uint64(sec) * 1_000_000_000
	return uint32((ns + (1 << nowShift) - 1) >> nowShift)
}

// Pinned maps are adopted across restarts only when compatible (same type, key,
// value and max-entries — see mapCompatible); an incompatible layout is wiped and
// recreated. There is no separate version tag.

// sharedMapNames are created once and referenced by both program instances.
// l1cache is shared so a flow's two directions (which normalize to the same key)
// hit the same per-CPU slot when symmetric RSS lands them on one CPU.
var sharedMapNames = []string{
	"flows", "udp_flows", "flow_monitor_cidrs", "flow_monitor_counters", "l1cache", "tx_ports", "features", "server_allow",
	"synbkt", "drop_reason", "stats_global", "stats_vlan",
}

const runtimeMapName = "runtime_state"

// SharedMaps holds the maps shared between the two program instances.
type SharedMaps struct {
	Flows               *ebpf.Map
	UDPFlows            *ebpf.Map
	FlowMonitorCIDRs    *ebpf.Map
	FlowMonitorCounters *ebpf.Map
	L1Cache             *ebpf.Map
	TxPorts             *ebpf.Map
	Features            *ebpf.Map
	ServerAllow         *ebpf.Map
	SynBkt              *ebpf.Map
	DropReason          *ebpf.Map
	StatsGlobal         *ebpf.Map
	StatsVlan           *ebpf.Map
	Runtime             *ebpf.Map

	byName map[string]*ebpf.Map
}

func (s *SharedMaps) Close() {
	for _, m := range s.byName {
		m.Close()
	}
}

// Handle owns a fully-attached datapath.
type Handle struct {
	Maps   *SharedMaps
	collT  *ebpf.Collection
	collU  *ebpf.Collection
	linkT  link.Link
	linkU  link.Link
	pinDir string
}

// featuresValue mirrors struct features (bpf/filter.h). Numeric fields only, so
// native-endian marshaling by cilium/ebpf matches the BPF side on amd64/arm64.
type featuresValue struct {
	Mode                uint8
	OosStrict           uint8
	AllowInboundServers uint8
	DropFrags           uint8
	DropBadFlags        uint8
	FilterUDP           uint8
	DropVlanDeep        uint8
	DropUDPFrags        uint8
	RejectWithRST       uint8
	AllowInboundSYN     uint8
	_                   [2]byte // pad to 4-byte alignment (matches struct features)
	// TTLs are in coarse ticks (see secToTicks / NOW_SHIFT), not seconds.
	TTLSyn     uint32
	TTLEst     uint32
	TTLClosing uint32
	TTLUdp     uint32
}

// LivePolicy is the policy currently active in the BPF features map.
type LivePolicy struct {
	Mode                string
	OosStrict           bool
	AllowInboundServers bool
	AllowInboundSYN     bool
	DropFrags           bool
	DropBadFlags        bool
	FilterUDP           bool
	DropVlanDeep        bool
	DropUDPFrags        bool
	RejectWithRST       bool
	TTLSyn              uint32
	TTLEst              uint32
	TTLClosing          uint32
	TTLUdp              uint32
}

// RuntimeState is userspace-published daemon state stored alongside BPF pins.
type RuntimeState struct {
	TCPLive             uint64
	UDPLive             uint64
	LastGCUnixNano      int64
	DaemonStartUnixNano int64
}

func featuresFrom(cfg *config.Config) featuresValue {
	b := func(v bool) uint8 {
		if v {
			return 1
		}
		return 0
	}
	mode := uint8(0)
	if cfg.Mode == "enforce" {
		mode = 1
	}
	return featuresValue{
		Mode:                mode,
		OosStrict:           b(cfg.OosStrict),
		AllowInboundServers: b(cfg.AllowInboundServers),
		DropFrags:           b(cfg.DropFrags),
		DropBadFlags:        b(cfg.DropBadFlags),
		FilterUDP:           b(cfg.FilterUDP),
		DropVlanDeep:        b(cfg.DropVlanDeep),
		DropUDPFrags:        b(cfg.DropUDPFrags),
		RejectWithRST:       b(cfg.RejectWithRST),
		AllowInboundSYN:     b(cfg.AllowInboundSYN),
		TTLSyn:              secToTicks(cfg.TTLSyn),
		TTLEst:              secToTicks(cfg.TTLEst),
		TTLClosing:          secToTicks(cfg.TTLClosing),
		TTLUdp:              secToTicks(cfg.TTLUdp),
	}
}

// srvKeyBytes builds the 8-byte struct srv_key in wire (network-order) layout,
// avoiding any host-endian ambiguity for the address/port.
func srvKeyBytes(ip net.IP, port uint16) []byte {
	k := make([]byte, 8)
	copy(k[0:4], ip.To4()) // network order, as loaded from the packet
	binary.BigEndian.PutUint16(k[4:6], port)
	return k
}

// Load creates or adopts the shared maps, loads both specialized programs, and
// attaches them to the two ports (adopting pinned links if present).
func Load(cfg *config.Config) (*Handle, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	if err := os.MkdirAll(cfg.PinDir, 0o755); err != nil {
		return nil, fmt.Errorf("pin dir: %w", err)
	}

	ifT, err := net.InterfaceByName(cfg.TrustedIface)
	if err != nil {
		return nil, fmt.Errorf("trusted iface %q: %w", cfg.TrustedIface, err)
	}
	ifU, err := net.InterfaceByName(cfg.UntrustedIface)
	if err != nil {
		return nil, fmt.Errorf("untrusted iface %q: %w", cfg.UntrustedIface, err)
	}

	spec, err := loadFilter()
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}
	spec.Maps["flows"].MaxEntries = cfg.FlowMax
	spec.Maps["udp_flows"].MaxEntries = cfg.UDPFlowMax
	spec.Maps["flow_monitor_counters"].MaxEntries = cfg.FlowMonitoring.MaxFlows
	if err := setVar(spec, "FLOW_MONITOR_ENABLED", boolU32(cfg.FlowMonitoring.Enabled)); err != nil {
		return nil, err
	}
	if err := setVar(spec, "FLOW_MONITOR_SAMPLE_MASK", cfg.FlowMonitoring.SampleEvery-1); err != nil {
		return nil, err
	}

	// L1 cache sizing: a PERCPU_ARRAY needs >= 1 entry even when disabled, so a
	// zero l1_size maps to a 1-entry map plus L1_MASK=0 (which dead-code-eliminates
	// the entire L1 fast path in the verifier).
	l1Entries, l1Mask := uint32(1), uint32(0)
	if cfg.L1Size != 0 {
		l1Entries = cfg.L1Size
		l1Mask = cfg.L1Size - 1
	}
	spec.Maps["l1cache"].MaxEntries = l1Entries

	// Optional per-CPU LRU (BPF_F_NO_COMMON_LRU): trades global capacity for zero
	// cross-CPU contention on the insert path under high connection churn.
	if cfg.LRUPerCPU {
		spec.Maps["flows"].Flags |= bpfFNoCommonLRU
		spec.Maps["udp_flows"].Flags |= bpfFNoCommonLRU
	}

	// Byte accounting for multi-buffer (jumbo) frames costs a helper call, so only
	// enable it when a port's MTU can exceed a single XDP buffer.
	multibuf := uint8(0)
	if ifT.MTU > 1500 || ifU.MTU > 1500 {
		multibuf = 1
	}

	// Create/adopt shared maps.
	shared, err := createOrAdoptShared(cfg.PinDir, spec)
	if err != nil {
		return nil, err
	}
	_ = PublishRuntimeState(shared, RuntimeState{DaemonStartUnixNano: time.Now().UnixNano()})

	// Populate control maps before attach so the first packet sees real policy.
	if err := shared.TxPorts.Put(uint32(0), uint32(ifT.Index)); err != nil {
		shared.Close()
		return nil, fmt.Errorf("tx_ports[0]=trusted: %w", err)
	}
	if err := shared.TxPorts.Put(uint32(1), uint32(ifU.Index)); err != nil {
		shared.Close()
		return nil, fmt.Errorf("tx_ports[1]=untrusted: %w", err)
	}
	if err := ApplyFeatures(shared, cfg); err != nil {
		shared.Close()
		return nil, err
	}
	// Sync (not just add) so entries removed from config don't linger in a pinned
	// map adopted from a previous run.
	if err := SyncServerAllow(shared, cfg); err != nil {
		shared.Close()
		return nil, err
	}
	if err := SyncFlowMonitorCIDRs(shared, cfg); err != nil {
		shared.Close()
		return nil, err
	}

	// Load both specialized programs, sharing the maps above.
	// index 0 = trusted port, index 1 = untrusted port.
	collT, progT, err := loadProg(spec, shared, 1 /*trusted*/, 1 /*peer=untrusted*/, l1Mask, multibuf)
	if err != nil {
		shared.Close()
		return nil, fmt.Errorf("load trusted prog: %w", err)
	}
	collU, progU, err := loadProg(spec, shared, 0 /*untrusted*/, 0 /*peer=trusted*/, l1Mask, multibuf)
	if err != nil {
		collT.Close()
		shared.Close()
		return nil, fmt.Errorf("load untrusted prog: %w", err)
	}

	// Driver-agnostic: native XDP + XDP_REDIRECT works on mlx5, Intel
	// (ice/i40e/ixgbe/igb/igc), bnxt, veth, etc. Attach mode is resolved per
	// port, so "auto" can even mix native + generic across the two ports.
	pinT := filepath.Join(cfg.PinDir, "link_trusted")
	pinU := filepath.Join(cfg.PinDir, "link_untrusted")

	lT, err := attachMode(progT, ifT.Index, pinT, cfg.XDPMode, cfg.TrustedIface)
	if err != nil {
		collU.Close()
		collT.Close()
		shared.Close()
		return nil, fmt.Errorf("attach trusted %s: %w", cfg.TrustedIface, err)
	}
	lU, err := attachMode(progU, ifU.Index, pinU, cfg.XDPMode, cfg.UntrustedIface)
	if err != nil {
		lT.Close()
		collU.Close()
		collT.Close()
		shared.Close()
		return nil, fmt.Errorf("attach untrusted %s: %w", cfg.UntrustedIface, err)
	}

	return &Handle{Maps: shared, collT: collT, collU: collU, linkT: lT, linkU: lU, pinDir: cfg.PinDir}, nil
}

func loadProg(spec *ebpf.CollectionSpec, shared *SharedMaps, roleTrusted uint8, peerIdx, l1Mask uint32, multibuf uint8) (*ebpf.Collection, *ebpf.Program, error) {
	s := spec.Copy()
	if err := setVar(s, "ROLE_TRUSTED", roleTrusted); err != nil {
		return nil, nil, err
	}
	if roleTrusted != 0 {
		// The protected-side program never performs inbound flow monitoring.
		if err := setVar(s, "FLOW_MONITOR_ENABLED", uint32(0)); err != nil {
			return nil, nil, err
		}
	}
	if err := setVar(s, "PEER_IDX", peerIdx); err != nil {
		return nil, nil, err
	}
	// L1_MASK / MULTIBUF are identical for both instances (global tunables), but
	// each collection gets its own .rodata, so set them on every copy.
	if err := setVar(s, "L1_MASK", l1Mask); err != nil {
		return nil, nil, err
	}
	if err := setVar(s, "MULTIBUF", multibuf); err != nil {
		return nil, nil, err
	}
	replacements := make(map[string]*ebpf.Map, len(sharedMapNames))
	for _, name := range sharedMapNames {
		replacements[name] = shared.byName[name]
	}
	coll, err := ebpf.NewCollectionWithOptions(s, ebpf.CollectionOptions{
		MapReplacements: replacements,
	})
	if err != nil {
		return nil, nil, err
	}
	prog := coll.Programs["xdp_filter"]
	if prog == nil {
		coll.Close()
		return nil, nil, errors.New("program xdp_filter not found in object")
	}
	return coll, prog, nil
}

func setVar(spec *ebpf.CollectionSpec, name string, val any) error {
	v := spec.Variables[name]
	if v == nil {
		return fmt.Errorf("bpf constant %q not found", name)
	}
	if err := v.Set(val); err != nil {
		return fmt.Errorf("set %s: %w", name, err)
	}
	return nil
}

// attachMode resolves the attach mode for one port: native, generic, or auto
// (native, then generic fallback).
func attachMode(prog *ebpf.Program, ifindex int, pin, mode, name string) (link.Link, error) {
	switch mode {
	case "generic":
		return attach(prog, ifindex, pin, link.XDPGenericMode)
	case "native":
		return attach(prog, ifindex, pin, link.XDPDriverMode)
	default: // auto
		l, err := attach(prog, ifindex, pin, link.XDPDriverMode)
		if err != nil {
			log.Printf("native XDP on %s failed (%v); falling back to generic mode", name, err)
			return attach(prog, ifindex, pin, link.XDPGenericMode)
		}
		return l, nil
	}
}

// attach adopts a pinned link (hitless Update) or creates + pins a new one.
func attach(prog *ebpf.Program, ifindex int, pinPath string, flags link.XDPAttachFlags) (link.Link, error) {
	if l, err := link.LoadPinnedLink(pinPath, nil); err == nil {
		if err := l.Update(prog); err != nil {
			l.Close()
			return nil, fmt.Errorf("update pinned link: %w", err)
		}
		return l, nil
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: ifindex, Flags: flags})
	if err != nil {
		return nil, err
	}
	if err := l.Pin(pinPath); err != nil {
		l.Close()
		return nil, fmt.Errorf("pin link: %w", err)
	}
	return l, nil
}

func createOrAdoptShared(pinDir string, spec *ebpf.CollectionSpec) (*SharedMaps, error) {
	byName := make(map[string]*ebpf.Map, len(sharedMapNames))
	cleanup := func() {
		for _, m := range byName {
			m.Close()
		}
	}
	for _, name := range sharedMapNames {
		ms, ok := spec.Maps[name]
		if !ok {
			cleanup()
			return nil, fmt.Errorf("map %q missing from object", name)
		}
		m, err := adoptOrCreateMap(pinDir, name, ms)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("map %q: %w", name, err)
		}
		byName[name] = m
	}
	runtime, err := adoptOrCreateMap(pinDir, runtimeMapName, &ebpf.MapSpec{
		Name: runtimeMapName, Type: ebpf.Array, KeySize: 4,
		ValueSize: uint32(binary.Size(RuntimeState{})), MaxEntries: 1,
	})
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("map %q: %w", runtimeMapName, err)
	}
	byName[runtimeMapName] = runtime
	return &SharedMaps{
		Flows:               byName["flows"],
		UDPFlows:            byName["udp_flows"],
		FlowMonitorCIDRs:    byName["flow_monitor_cidrs"],
		FlowMonitorCounters: byName["flow_monitor_counters"],
		L1Cache:             byName["l1cache"],
		TxPorts:             byName["tx_ports"],
		Features:            byName["features"],
		ServerAllow:         byName["server_allow"],
		SynBkt:              byName["synbkt"],
		DropReason:          byName["drop_reason"],
		StatsGlobal:         byName["stats_global"],
		StatsVlan:           byName["stats_vlan"], Runtime: byName[runtimeMapName],
		byName: byName,
	}, nil
}

// adoptOrCreateMap reuses a compatible pinned map (preserving flow state across
// restarts) or, if absent/incompatible (layout change), (re)creates and pins it.
func adoptOrCreateMap(pinDir, name string, ms *ebpf.MapSpec) (*ebpf.Map, error) {
	p := filepath.Join(pinDir, name)
	if m, err := ebpf.LoadPinnedMap(p, nil); err == nil {
		if mapCompatible(m, ms) {
			return m, nil
		}
		m.Close()
		_ = os.Remove(p) // unpin the stale map
	}
	msc := ms.Copy()
	msc.Pinning = ebpf.PinByName
	return ebpf.NewMapWithOptions(msc, ebpf.MapOptions{PinPath: pinDir})
}

func mapCompatible(m *ebpf.Map, ms *ebpf.MapSpec) bool {
	return m.Type() == ms.Type &&
		m.KeySize() == ms.KeySize &&
		m.ValueSize() == ms.ValueSize &&
		m.MaxEntries() == ms.MaxEntries &&
		m.Flags() == ms.Flags // so toggling lru_percpu recreates the flow tables
}

// ApplyFeatures (re)writes the live policy into the features map.
func ApplyFeatures(s *SharedMaps, cfg *config.Config) error {
	fv := featuresFrom(cfg)
	if err := s.Features.Put(uint32(0), &fv); err != nil {
		return fmt.Errorf("write features: %w", err)
	}
	return nil
}

// SyncServerAllow reconciles the allowlist map to exactly cfg.ServerAllow:
// entries no longer wanted are deleted and new ones added. Unlike a
// clear-then-repopulate it never leaves an empty window, and it removes stale
// entries adopted from a pinned map on load.
func SyncServerAllow(s *SharedMaps, cfg *config.Config) error {
	desired := make(map[[8]byte]struct{}, len(cfg.ServerAllow))
	for _, entry := range cfg.ServerAllow {
		ip, port, err := config.ParseHostPort(entry)
		if err != nil {
			return err
		}
		var k [8]byte
		copy(k[:], srvKeyBytes(ip, port))
		desired[k] = struct{}{}
	}

	var cur [8]byte
	var val uint8
	var stale [][8]byte
	it := s.ServerAllow.Iterate()
	for it.Next(&cur, &val) {
		if _, ok := desired[cur]; !ok {
			k := cur
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate server_allow: %w", err)
	}
	for i := range stale {
		if err := s.ServerAllow.Delete(stale[i][:]); err != nil {
			return fmt.Errorf("server_allow delete: %w", err)
		}
	}
	for k := range desired {
		kk := k
		if err := s.ServerAllow.Put(kk[:], uint8(1)); err != nil {
			return fmt.Errorf("server_allow put: %w", err)
		}
	}
	return nil
}

// SyncFlowMonitorCIDRs reconciles the LPM membership trie. Thresholds remain
// in userspace; the datapath only needs to know whether a protected IP belongs
// to at least one configured network before allocating/updating a counter.
func SyncFlowMonitorCIDRs(s *SharedMaps, cfg *config.Config) error {
	desired := make(map[[8]byte]struct{}, len(cfg.FlowMonitoring.CIDRs))
	for _, rule := range cfg.FlowMonitoring.CIDRs {
		ip, network, err := net.ParseCIDR(rule.CIDR)
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("flow monitor CIDR %q is invalid", rule.CIDR)
		}
		ones, _ := network.Mask.Size()
		var key [8]byte
		binary.NativeEndian.PutUint32(key[:4], uint32(ones))
		copy(key[4:], network.IP.To4())
		desired[key] = struct{}{}
	}

	var cur [8]byte
	var val uint8
	var stale [][8]byte
	it := s.FlowMonitorCIDRs.Iterate()
	for it.Next(&cur, &val) {
		if _, ok := desired[cur]; !ok {
			stale = append(stale, cur)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate flow_monitor_cidrs: %w", err)
	}
	for _, key := range stale {
		if err := s.FlowMonitorCIDRs.Delete(key[:]); err != nil {
			return fmt.Errorf("flow_monitor_cidrs delete: %w", err)
		}
	}
	for key := range desired {
		k := key
		if err := s.FlowMonitorCIDRs.Put(k[:], uint8(1)); err != nil {
			return fmt.Errorf("flow_monitor_cidrs put: %w", err)
		}
	}
	return nil
}

// ReloadPolicy re-applies the live-updatable policy (feature toggles, TTLs and
// the server allowlist) to the maps. No reattach — the datapath and flow tables
// are untouched. Used by SIGHUP / inotify config reload.
func ReloadPolicy(s *SharedMaps, cfg *config.Config) error {
	if err := ApplyFeatures(s, cfg); err != nil {
		return err
	}
	if err := SyncServerAllow(s, cfg); err != nil {
		return err
	}
	return SyncFlowMonitorCIDRs(s, cfg)
}

func boolU32(v bool) uint32 {
	if v {
		return 1
	}
	return 0
}

// ApplyFlowMonitorControl updates only the untrusted program. The trusted
// program is load-time specialized with ROLE_TRUSTED and never executes the
// monitoring path. Disabling is written first; enabling writes the sampling
// mask first so no packet observes an old sampling factor.
func (h *Handle) ApplyFlowMonitorControl(cfg *config.Config) error {
	if h == nil || h.collU == nil {
		return errors.New("flow monitor program unavailable")
	}
	enabled := boolU32(cfg.FlowMonitoring.Enabled)
	set := func(coll *ebpf.Collection, name string, value uint32) error {
		v := coll.Variables[name]
		if v == nil {
			return fmt.Errorf("BPF variable %s unavailable", name)
		}
		return v.Set(value)
	}
	if enabled == 0 {
		if err := set(h.collU, "FLOW_MONITOR_ENABLED", uint32(0)); err != nil {
			return err
		}
	}
	if err := set(h.collU, "FLOW_MONITOR_SAMPLE_MASK", cfg.FlowMonitoring.SampleEvery-1); err != nil {
		return err
	}
	if enabled != 0 {
		if err := set(h.collU, "FLOW_MONITOR_ENABLED", enabled); err != nil {
			return err
		}
	}
	return nil
}

// Close releases fds but leaves the datapath attached (pins persist), so a
// restart re-adopts without a forwarding blip. Use Detach to tear down.
func (h *Handle) Close() {
	if h.linkT != nil {
		h.linkT.Close()
	}
	if h.linkU != nil {
		h.linkU.Close()
	}
	if h.collT != nil {
		h.collT.Close()
	}
	if h.collU != nil {
		h.collU.Close()
	}
	if h.Maps != nil {
		h.Maps.Close()
	}
}

// Detach unpins and removes the datapath (the wire goes dark — the programs ARE
// the bridge). Used by `stop --detach` and package removal.
func Detach(pinDir string) error {
	var firstErr error
	for _, l := range []string{"link_trusted", "link_untrusted"} {
		p := filepath.Join(pinDir, l)
		if lnk, err := link.LoadPinnedLink(p, nil); err == nil {
			_ = lnk.Unpin()
			lnk.Close()
		}
		_ = os.Remove(p)
	}
	for _, name := range append(append([]string(nil), sharedMapNames...), runtimeMapName) {
		p := filepath.Join(pinDir, name)
		if m, err := ebpf.LoadPinnedMap(p, nil); err == nil {
			_ = m.Unpin()
			m.Close()
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// OpenPinned opens the shared maps of a running instance (for status/mode/flows/gc/stats).
func OpenPinned(pinDir string) (*SharedMaps, error) {
	byName := make(map[string]*ebpf.Map, len(sharedMapNames))
	for _, name := range sharedMapNames {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
		if err != nil {
			for _, mm := range byName {
				mm.Close()
			}
			return nil, fmt.Errorf("open pinned %q (is xdpfilter running?): %w", name, err)
		}
		byName[name] = m
	}
	// Optional for compatibility with a daemon started before runtime_state was added.
	if m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, runtimeMapName), nil); err == nil {
		byName[runtimeMapName] = m
	}
	return &SharedMaps{
		Flows: byName["flows"], UDPFlows: byName["udp_flows"], L1Cache: byName["l1cache"],
		FlowMonitorCIDRs: byName["flow_monitor_cidrs"], FlowMonitorCounters: byName["flow_monitor_counters"],
		TxPorts: byName["tx_ports"], Features: byName["features"],
		ServerAllow: byName["server_allow"], SynBkt: byName["synbkt"], DropReason: byName["drop_reason"],
		StatsGlobal: byName["stats_global"], StatsVlan: byName["stats_vlan"],
		Runtime: byName[runtimeMapName], byName: byName,
	}, nil
}

// ReadLivePolicy returns the feature values currently active in the datapath.
func ReadLivePolicy(s *SharedMaps) (LivePolicy, error) {
	var fv featuresValue
	if err := s.Features.Lookup(uint32(0), &fv); err != nil {
		return LivePolicy{}, fmt.Errorf("read features: %w", err)
	}
	b := func(v uint8) bool { return v != 0 }
	mode := "monitor"
	if fv.Mode == 1 {
		mode = "enforce"
	}
	return LivePolicy{
		Mode: mode, OosStrict: b(fv.OosStrict),
		AllowInboundServers: b(fv.AllowInboundServers), AllowInboundSYN: b(fv.AllowInboundSYN),
		DropFrags: b(fv.DropFrags), DropBadFlags: b(fv.DropBadFlags), FilterUDP: b(fv.FilterUDP),
		DropVlanDeep: b(fv.DropVlanDeep), DropUDPFrags: b(fv.DropUDPFrags), RejectWithRST: b(fv.RejectWithRST),
		TTLSyn: ticksToSec(fv.TTLSyn), TTLEst: ticksToSec(fv.TTLEst),
		TTLClosing: ticksToSec(fv.TTLClosing), TTLUdp: ticksToSec(fv.TTLUdp),
	}, nil
}

// PublishRuntimeState updates the optional userspace runtime map.
func PublishRuntimeState(s *SharedMaps, state RuntimeState) error {
	if s == nil || s.Runtime == nil {
		return nil
	}
	return s.Runtime.Put(uint32(0), &state)
}

// ReadRuntimeState reads flow occupancy and daemon timestamps.
func ReadRuntimeState(s *SharedMaps) (RuntimeState, error) {
	if s == nil || s.Runtime == nil {
		return RuntimeState{}, errors.New("runtime state unavailable")
	}
	var state RuntimeState
	if err := s.Runtime.Lookup(uint32(0), &state); err != nil {
		return state, err
	}
	return state, nil
}

// Mode returns the current datapath mode ("monitor"/"enforce") from the features map.
func Mode(s *SharedMaps) string {
	p, err := ReadLivePolicy(s)
	if err != nil {
		return "unknown"
	}
	return p.Mode
}

// SetModePinned flips monitor/enforce on a running instance without reattaching.
func SetModePinned(pinDir string, enforce bool) error {
	s, err := OpenPinned(pinDir)
	if err != nil {
		return err
	}
	defer s.Close()
	var fv featuresValue
	if err := s.Features.Lookup(uint32(0), &fv); err != nil {
		return fmt.Errorf("read features: %w", err)
	}
	if enforce {
		fv.Mode = 1
	} else {
		fv.Mode = 0
	}
	return s.Features.Put(uint32(0), &fv)
}
