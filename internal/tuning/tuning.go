// SPDX-License-Identifier: GPL-2.0

// Package tuning applies (and can revert) a performance profile: kernel
// sysctls, mlx5/ethtool settings, IRQ affinity and CPU governor. It runs as
// root from the daemon on start and snapshots originals so package removal (or
// `stop --detach --restore`) puts the box back.
package tuning

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/consi/xdpfilter/internal/config"
)

const SnapshotPath = "/var/lib/xdpfilter/tuning.orig.json"

// Snapshot records original values so tuning can be reverted.
type Snapshot struct {
	Sysctls             map[string]string            `json:"sysctls"`
	EthFeatures         map[string]map[string]string `json:"eth_features"` // iface -> feature -> on/off
	Rings               map[string][2]string         `json:"rings"`        // iface -> [rx,tx]
	Channels            map[string]string            `json:"channels"`     // iface -> combined
	PrivFlags           map[string]map[string]string `json:"priv_flags"`   // iface -> flag -> on/off
	IRQAffinity         map[string]string            `json:"irq_affinity"` // irq -> cpulist
	Governors           map[string]string            `json:"governors"`    // cpu path -> governor
	IrqbalanceWasActive bool                         `json:"irqbalance_was_active"`
}

// Tuner applies or previews the profile for one configuration.
type Tuner struct {
	cfg    *config.Config
	dryRun bool
	out    io.Writer
	snap   *Snapshot
}

func New(cfg *config.Config, dryRun bool, out io.Writer) *Tuner {
	return &Tuner{cfg: cfg, dryRun: dryRun, out: out, snap: &Snapshot{
		Sysctls: map[string]string{}, EthFeatures: map[string]map[string]string{},
		Rings: map[string][2]string{}, Channels: map[string]string{},
		PrivFlags: map[string]map[string]string{}, IRQAffinity: map[string]string{},
		Governors: map[string]string{},
	}}
}

func (t *Tuner) logf(format string, a ...any) { fmt.Fprintf(t.out, format+"\n", a...) }

// runStep runs a command and logs a warning if it fails. Tuning is best-effort
// (many steps fail expectedly on veth or non-mlx5 NICs), but a failure should be
// visible rather than silently dropped.
func (t *Tuner) runStep(desc, name string, args ...string) {
	if err := run(name, args...); err != nil {
		t.logf("warning: %s failed: %v", desc, err)
	}
}

// Apply computes and (unless dryRun) applies the profile, writing a snapshot first.
func (t *Tuner) Apply() error {
	if !t.cfg.Tune {
		t.logf("tuning disabled (tune: false)")
		return nil
	}
	ifaces := []string{t.cfg.TrustedIface, t.cfg.UntrustedIface}

	t.applySysctls()
	channels := t.commonChannels(ifaces)
	t.logf("channels: resolved common count %d", channels)
	if t.cfg.Tuning.RingSize == 0 {
		t.logf("rings: retain current driver values")
	}
	for _, ifc := range ifaces {
		t.applyEthtool(ifc, channels)
	}
	if ptrOrTrue(t.cfg.Tuning.DisableIRQBal) {
		t.applyIRQBalance()
		for _, ifc := range ifaces {
			t.applyIRQAffinity(ifc)
		}
	}
	t.applyGovernor()

	if !t.dryRun {
		if err := saveSnapshot(t.snap); err != nil {
			t.logf("warning: could not save tuning snapshot: %v", err)
		}
	}
	return nil
}

// ---- sysctls ----

func (t *Tuner) applySysctls() {
	tn := t.cfg.Tuning
	desired := [][2]string{
		{"net.core.bpf_jit_enable", "1"},
		{"net.core.bpf_jit_harden", "0"},
		{"kernel.numa_balancing", "0"},
	}
	if tn.NetdevBacklog != 0 {
		desired = append(desired, [2]string{"net.core.netdev_max_backlog", strconv.Itoa(int(tn.NetdevBacklog))})
	}
	if tn.NetdevBudget != 0 {
		desired = append(desired, [2]string{"net.core.netdev_budget", strconv.Itoa(int(tn.NetdevBudget))})
	}
	for _, kv := range desired {
		key, val := kv[0], kv[1]
		cur, _ := readSysctl(key)
		if cur == val {
			continue
		}
		t.snap.Sysctls[key] = cur
		t.logf("sysctl %s = %s (was %s)", key, val, cur)
		if !t.dryRun {
			if err := writeSysctl(key, val); err != nil {
				t.logf("  warning: %v", err)
			}
		}
	}
	if !t.dryRun {
		_ = writeSysctlPersist(desired)
	}
}

// ---- ethtool ----

func (t *Tuner) applyEthtool(ifc string, channels uint32) {
	tn := t.cfg.Tuning

	// Feature toggles: VLAN offload OFF (tags must reach XDP), LRO OFF.
	feats := map[string]string{}
	if ptrOrTrue(tn.DisableVLANHW) {
		feats["rxvlan"] = "off"
		feats["txvlan"] = "off"
	}
	if ptrOrTrue(tn.DisableLRO) {
		feats["lro"] = "off"
	}
	for f, want := range feats {
		cur := ethFeature(ifc, f)
		if cur != "" && cur != want {
			t.snapFeature(ifc, f, cur)
			t.logf("ethtool -K %s %s %s (was %s)", ifc, f, want, cur)
			if !t.dryRun {
				t.runStep("ethtool -K "+ifc+" "+f, "ethtool", "-K", ifc, f, want)
			}
		}
	}

	// A zero ring override means retain the driver's current setting.
	if tn.RingSize != 0 {
		if rings, ok := ethRingInfo(ifc); ok {
			t.snap.Rings[ifc] = [2]string{rings.currentRX, rings.currentTX}
			rx, tx := tn.RingSize, tn.RingSize
			if rings.maxRX > 0 && rx > rings.maxRX {
				rx = rings.maxRX
			}
			if rings.maxTX > 0 && tx > rings.maxTX {
				tx = rings.maxTX
			}
			wantRX, wantTX := strconv.Itoa(int(rx)), strconv.Itoa(int(tx))
			if rings.currentRX != wantRX || rings.currentTX != wantTX {
				t.logf("ethtool -G %s rx %s tx %s (was rx %s tx %s)",
					ifc, wantRX, wantTX, rings.currentRX, rings.currentTX)
				if !t.dryRun {
					t.runStep("ethtool -G "+ifc, "ethtool", "-G", ifc, "rx", wantRX, "tx", wantTX)
				}
			}
		}
	}

	// Both ports use the same hardware- and CPU-capped channel count.
	if channels > 0 {
		if info, ok := ethChannelInfo(ifc); ok {
			t.snap.Channels[ifc] = info.current
			want := strconv.Itoa(int(channels))
			if info.current != want {
				t.logf("ethtool -L %s combined %s (was %s)", ifc, want, info.current)
				if !t.dryRun {
					t.runStep("ethtool -L "+ifc+" combined", "ethtool", "-L", ifc, "combined", want)
				}
			}
		}
	}

	// mlx5 priv flag: rx_cqe_compress on (ignored on non-mlx5).
	if ptrOrTrue(tn.CQECompress) {
		if cur := ethPrivFlag(ifc, "rx_cqe_compress"); cur != "" {
			t.snapPriv(ifc, "rx_cqe_compress", cur)
			if cur != "on" {
				t.logf("ethtool --set-priv-flags %s rx_cqe_compress on (was %s)", ifc, cur)
				if !t.dryRun {
					t.runStep("ethtool --set-priv-flags "+ifc, "ethtool", "--set-priv-flags", ifc, "rx_cqe_compress", "on")
				}
			}
		}
	}

	// Symmetric RSS so a flow's two directions hash to the same queue index on
	// both ports. Try the modern xfrm knob, else fall back to a symmetric key.
	if ptrOrTrue(tn.SymmetricRSS) {
		t.logf("ethtool -X %s hfunc toeplitz xfrm symmetric-xor (RSS symmetry)", ifc)
		if !t.dryRun {
			if run("ethtool", "-X", ifc, "hfunc", "toeplitz", "xfrm", "symmetric-xor") != nil {
				t.runStep("ethtool -X "+ifc+" symmetric RSS key", "ethtool", "-X", ifc, "hkey", symmetricKey40())
			}
		}
	}
}

func (t *Tuner) commonChannels(ifaces []string) uint32 {
	limits := make([]channelLimit, 0, len(ifaces))
	for _, ifc := range ifaces {
		coreLimit := uint32(len(t.numaCores(ifc)))
		if coreLimit == 0 {
			coreLimit = 1
		}
		hardwareLimit := uint32(0)
		if info, ok := ethChannelInfo(ifc); ok {
			hardwareLimit = info.maximum
		}
		limits = append(limits, channelLimit{cpus: coreLimit, maximum: hardwareLimit})
	}
	resolved := resolveCommonChannels(t.cfg.Tuning.Channels, limits)
	if t.cfg.Tuning.Channels > 0 && resolved < t.cfg.Tuning.Channels {
		t.logf("channels clamped from %d to common hardware/CPU limit %d",
			t.cfg.Tuning.Channels, resolved)
	}
	return resolved
}

type channelLimit struct {
	cpus, maximum uint32
}

func resolveCommonChannels(requested uint32, ports []channelLimit) uint32 {
	resolved := requested
	for _, port := range ports {
		limit := port.cpus
		if limit == 0 {
			limit = 1
		}
		if port.maximum > 0 && port.maximum < limit {
			limit = port.maximum
		}
		if resolved == 0 || limit < resolved {
			resolved = limit
		}
	}
	return resolved
}

// ---- IRQ ----

func (t *Tuner) applyIRQBalance() {
	active := run("systemctl", "is-active", "--quiet", "irqbalance") == nil
	t.snap.IrqbalanceWasActive = active
	if active {
		t.logf("systemctl disable --now irqbalance")
		if !t.dryRun {
			t.runStep("systemctl disable irqbalance", "systemctl", "disable", "--now", "irqbalance")
		}
	}
}

// applyIRQAffinity pins the k-th queue IRQ of the interface to the k-th
// NUMA-local core, so queue index i on both ports lands on the same core
// (flow-direction locality).
func (t *Tuner) applyIRQAffinity(ifc string) {
	irqs := ifaceIRQs(ifc)
	cores := t.numaCores(ifc)
	if len(irqs) == 0 || len(cores) == 0 {
		return
	}
	for i, irq := range irqs {
		core := cores[i%len(cores)]
		cur := readFileTrim(fmt.Sprintf("/proc/irq/%d/smp_affinity_list", irq))
		t.snap.IRQAffinity[strconv.Itoa(irq)] = cur
		want := strconv.Itoa(core)
		if cur == want {
			continue
		}
		t.logf("irq %d (%s q%d) -> cpu %d (was %s)", irq, ifc, i, core, cur)
		if !t.dryRun {
			_ = os.WriteFile(fmt.Sprintf("/proc/irq/%d/smp_affinity_list", irq), []byte(want), 0o644)
		}
	}
}

// ---- governor ----

func (t *Tuner) applyGovernor() {
	want := t.cfg.Tuning.Governor
	if want == "" {
		want = "performance"
	}
	paths, _ := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor")
	for _, p := range paths {
		cur := readFileTrim(p)
		if cur == "" || cur == want {
			continue
		}
		t.snap.Governors[p] = cur
		if !t.dryRun {
			_ = os.WriteFile(p, []byte(want), 0o644)
		}
	}
	if len(t.snap.Governors) > 0 {
		t.logf("cpufreq governor -> %s on %d cpus", want, len(t.snap.Governors))
	}
}

// numaCores returns the CPU list local to the NIC's NUMA node, minus the
// housekeeping core.
func (t *Tuner) numaCores(ifc string) []int {
	node := readFileTrim(fmt.Sprintf("/sys/class/net/%s/device/numa_node", ifc))
	var cpus []int
	if node != "" && node != "-1" {
		cpus = parseCPUList(readFileTrim(fmt.Sprintf("/sys/devices/system/node/node%s/cpulist", node)))
	}
	if len(cpus) == 0 {
		cpus = parseCPUList(readFileTrim("/sys/devices/system/cpu/online"))
	}
	cpus = intersectCPUs(cpus,
		parseCPUList(readFileTrim("/sys/devices/system/cpu/online")),
		processAllowedCPUs())
	hk := t.cfg.HousekeepingCore
	if hk < 0 && len(cpus) > 0 {
		hk = cpus[len(cpus)-1] // auto: last core
	}
	out := cpus[:0:0]
	for _, c := range cpus {
		if c != hk {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return cpus
	}
	return out
}

func processAllowedCPUs() []int {
	for _, line := range strings.Split(readFileTrim("/proc/self/status"), "\n") {
		if strings.HasPrefix(line, "Cpus_allowed_list:") {
			return parseCPUList(strings.TrimSpace(strings.TrimPrefix(line, "Cpus_allowed_list:")))
		}
	}
	return nil
}

// Empty constraints are ignored, which keeps dry-run previews useful on
// systems where a topology file is unavailable.
func intersectCPUs(base []int, constraints ...[]int) []int {
	out := append([]int(nil), base...)
	for _, constraint := range constraints {
		if len(constraint) == 0 {
			continue
		}
		set := make(map[int]struct{}, len(constraint))
		for _, cpu := range constraint {
			set[cpu] = struct{}{}
		}
		filtered := out[:0]
		for _, cpu := range out {
			if _, ok := set[cpu]; ok {
				filtered = append(filtered, cpu)
			}
		}
		out = filtered
	}
	return out
}

// ---- snapshot restore ----

// Restore reverts everything captured in the snapshot file.
func Restore(out io.Writer) error {
	b, err := os.ReadFile(SnapshotPath)
	if err != nil {
		return err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	for k, v := range s.Sysctls {
		_ = writeSysctl(k, v)
	}
	for ifc, feats := range s.EthFeatures {
		for f, v := range feats {
			run("ethtool", "-K", ifc, f, v)
		}
	}
	for ifc, rt := range s.Rings {
		run("ethtool", "-G", ifc, "rx", rt[0], "tx", rt[1])
	}
	for ifc, c := range s.Channels {
		run("ethtool", "-L", ifc, "combined", c)
	}
	for ifc, flags := range s.PrivFlags {
		for f, v := range flags {
			run("ethtool", "--set-priv-flags", ifc, f, v)
		}
	}
	for irq, cpul := range s.IRQAffinity {
		_ = os.WriteFile(fmt.Sprintf("/proc/irq/%s/smp_affinity_list", irq), []byte(cpul), 0o644)
	}
	for p, g := range s.Governors {
		_ = os.WriteFile(p, []byte(g), 0o644)
	}
	if s.IrqbalanceWasActive {
		run("systemctl", "enable", "--now", "irqbalance")
	}
	fmt.Fprintln(out, "tuning restored from snapshot")
	_ = os.Remove(SnapshotPath)
	return nil
}

func (t *Tuner) snapFeature(ifc, f, v string) {
	if t.snap.EthFeatures[ifc] == nil {
		t.snap.EthFeatures[ifc] = map[string]string{}
	}
	t.snap.EthFeatures[ifc][f] = v
}

func (t *Tuner) snapPriv(ifc, f, v string) {
	if t.snap.PrivFlags[ifc] == nil {
		t.snap.PrivFlags[ifc] = map[string]string{}
	}
	t.snap.PrivFlags[ifc][f] = v
}

func saveSnapshot(s *Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(SnapshotPath), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(SnapshotPath, b, 0o644)
}

// ---- low-level helpers ----

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func output(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func readSysctl(key string) (string, error) {
	p := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	return readFileTrim(p), nil
}

func writeSysctl(key, val string) error {
	p := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	return os.WriteFile(p, []byte(val), 0o644)
}

func writeSysctlPersist(kv [][2]string) error {
	var b strings.Builder
	b.WriteString("# written by xdpfilter\n")
	for _, e := range kv {
		fmt.Fprintf(&b, "%s = %s\n", e[0], e[1])
	}
	return os.WriteFile("/etc/sysctl.d/99-xdpfilter.conf", []byte(b.String()), 0o644)
}

func ethFeature(ifc, short string) string {
	// map short ethtool -K name to the -k display name
	name := map[string]string{
		"rxvlan": "rx-vlan-offload",
		"txvlan": "tx-vlan-offload",
		"lro":    "large-receive-offload",
	}[short]
	sc := bufio.NewScanner(strings.NewReader(output("ethtool", "-k", ifc)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, name+":") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				return strings.TrimSuffix(f[1], "]")
			}
		}
	}
	return ""
}

type ringInfo struct {
	maxRX, maxTX         uint32
	currentRX, currentTX string
}

func ethRingInfo(ifc string) (ringInfo, bool) {
	return parseRingInfo(output("ethtool", "-g", ifc))
}

func parseRingInfo(out string) (ringInfo, bool) {
	var r ringInfo
	current := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch line {
		case "Pre-set maximums:":
			current = false
			continue
		case "Current hardware settings:":
			current = true
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 32)
		if err != nil {
			continue
		}
		switch {
		case !current && f[0] == "RX:":
			r.maxRX = uint32(v)
		case !current && f[0] == "TX:":
			r.maxTX = uint32(v)
		case current && f[0] == "RX:":
			r.currentRX = f[1]
		case current && f[0] == "TX:":
			r.currentTX = f[1]
		}
	}
	return r, r.currentRX != "" && r.currentTX != ""
}

type channelInfo struct {
	maximum uint32
	current string
}

func ethChannelInfo(ifc string) (channelInfo, bool) {
	return parseChannelInfo(output("ethtool", "-l", ifc))
}

func parseChannelInfo(out string) (channelInfo, bool) {
	var c channelInfo
	current := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch line {
		case "Pre-set maximums:":
			current = false
			continue
		case "Current hardware settings:":
			current = true
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 || f[0] != "Combined:" {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 32)
		if err != nil {
			continue
		}
		if current {
			c.current = f[1]
		} else {
			c.maximum = uint32(v)
		}
	}
	return c, c.current != ""
}

func ethPrivFlag(ifc, flag string) string {
	sc := bufio.NewScanner(strings.NewReader(output("ethtool", "--show-priv-flags", ifc)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, flag) {
			f := strings.Fields(line)
			return f[len(f)-1] // "on"/"off"
		}
	}
	return ""
}

func ifaceIRQs(ifc string) []int {
	dir := fmt.Sprintf("/sys/class/net/%s/device/msi_irqs", ifc)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var irqs []int
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			irqs = append(irqs, n)
		}
	}
	sort.Ints(irqs)
	return irqs
}

func parseCPUList(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, _ := strconv.Atoi(lo)
			b, _ := strconv.Atoi(hi)
			for i := a; i <= b; i++ {
				out = append(out, i)
			}
		} else if n, err := strconv.Atoi(part); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func readFileTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func ptrOrTrue(p *bool) bool { return p == nil || *p }

// symmetricKey40 returns a 40-byte RSS key of repeating 6D:5A (Woo et al.),
// which makes a Toeplitz hash symmetric for swapped src/dst.
func symmetricKey40() string {
	parts := make([]string, 40)
	for i := range parts {
		if i%2 == 0 {
			parts[i] = "6D"
		} else {
			parts[i] = "5A"
		}
	}
	return strings.Join(parts, ":")
}
