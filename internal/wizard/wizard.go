// SPDX-License-Identifier: GPL-2.0

// Package wizard implements the first-run interactive setup.
package wizard

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/consi/xdpfilter/internal/config"
	"github.com/consi/xdpfilter/internal/dataplane"
	"github.com/consi/xdpfilter/internal/tuning"
)

type nic struct {
	Name   string
	Driver string
	Up     bool
	Speed  string
	XDP    string // probed: native / generic / busy / none
}

// Run drives the interactive setup and writes the config file.
func Run(cfgPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("setup must run as root")
	}
	in := bufio.NewReader(os.Stdin)

	fmt.Println("== xdpfilter setup ==")
	fmt.Println("Transparent bump-in-the-wire filter across two NIC ports.")
	fmt.Println()

	nics := listNICs()
	if len(nics) < 2 {
		return fmt.Errorf("need at least two physical NICs, found %d", len(nics))
	}
	printNICs(nics)
	capOf := map[string]string{}
	for _, n := range nics {
		capOf[n.Name] = n.XDP
	}

	trusted := pickIface(in, nics, "TRUSTED port (faces the protected host/network)")
	untrusted := pickIface(in, nics, "UNTRUSTED port (faces the internet)")
	if trusted == untrusted {
		return fmt.Errorf("trusted and untrusted must differ")
	}

	// Choose xdp_mode from the *probed* capability of the two chosen ports.
	capT, capU := capOf[trusted], capOf[untrusted]
	for _, p := range []struct{ n, c string }{{trusted, capT}, {untrusted, capU}} {
		switch p.c {
		case "native":
			fmt.Printf("  %s: native XDP supported (driver %q)\n", p.n, driverOf(p.n))
		case "generic":
			fmt.Printf("  %s: only generic/SKB XDP (driver %q) — works, reduced performance\n", p.n, driverOf(p.n))
		case "busy":
			fmt.Printf("  note: %s already has an XDP program attached — detach it before starting.\n", p.n)
		default:
			fmt.Printf("  WARNING: %s is not XDP-capable (driver %q) — the filter may fail to attach.\n", p.n, driverOf(p.n))
		}
	}

	cfg := config.Default()
	cfg.TrustedIface = trusted
	cfg.UntrustedIface = untrusted
	switch {
	case capT == "native" && capU == "native":
		cfg.XDPMode = "native"
	default:
		cfg.XDPMode = "auto" // native where possible, generic fallback per port
		fmt.Println("  -> xdp_mode: auto (native with generic fallback)")
	}

	// Policy.
	if promptYN(in, "Start in MONITOR mode (count would-drops, forward everything)?", true) {
		cfg.Mode = "monitor"
	} else {
		cfg.Mode = "enforce"
	}
	cfg.OosStrict = !promptYN(in, "Adopt pre-existing flows on insertion (recommended for a live network)?", true)
	cfg.FilterUDP = promptYN(in, "Statefully filter UDP too (drop unsolicited inbound UDP; protects downstream conntrack)?", true)
	cfg.RejectWithRST = promptYN(in, "Answer dropped inbound TCP with a RST to the source (like iptables REJECT; the source may be spoofed)?", false)
	if promptYN(in, "Allow inbound connections to servers behind the box (TCP or UDP)?", false) {
		cfg.AllowInboundServers = true
		fmt.Println("  Enter allowlisted servers as ip:port (covers TCP+UDP), blank to finish:")
		for {
			e := prompt(in, "  server", "")
			if e == "" {
				break
			}
			if _, _, err := config.ParseHostPort(e); err != nil {
				fmt.Printf("    invalid: %v\n", err)
				continue
			}
			cfg.ServerAllow = append(cfg.ServerAllow, e)
		}
	}

	// Flow table sizing.
	sugg := suggestFlowMax()
	fm := prompt(in, fmt.Sprintf("Flow table capacity (entries) [%d ~ %s]", sugg, humanBytes(uint64(sugg)*128)), strconv.Itoa(int(sugg)))
	if v, err := strconv.Atoi(fm); err == nil && v >= 1024 {
		cfg.FlowMax = uint32(v)
	} else {
		cfg.FlowMax = sugg
	}

	// Tuning preview.
	if promptYN(in, "Apply performance tuning (sysctls, NIC, IRQ pinning) on start?", true) {
		cfg.Tune = true
		fmt.Println("\n-- tuning profile (preview) --")
		_ = tuning.New(cfg, true, os.Stdout).Apply()
		fmt.Println("-- end preview --")
	} else {
		cfg.Tune = false
	}

	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := cfg.Save(cfgPath); err != nil {
		return err
	}
	fmt.Printf("\nWrote %s\n", cfgPath)

	enableBoot := promptYN(in, "Enable xdpfilter to start automatically on boot?", true)
	startNow := promptYN(in, "Start xdpfilter now?", true)
	if enableBoot || startNow {
		_ = runVisible("systemctl", "daemon-reload") // pick up the (possibly updated) unit
	}
	if enableBoot {
		if err := runVisible("systemctl", "enable", "xdpfilter"); err != nil {
			return fmt.Errorf("systemctl enable: %w", err)
		}
		fmt.Println("Enabled on boot.")
	}
	if startNow {
		if err := runVisible("systemctl", "start", "xdpfilter"); err != nil {
			return fmt.Errorf("systemctl start: %w", err)
		}
		fmt.Println("Started. Watch:  xdpfilter status   |   cat", filepath.Join(cfg.StatsDir, "stats.txt"))
		if cfg.Mode == "monitor" {
			fmt.Println("Running in MONITOR mode — verify only attack traffic is flagged, then:  xdpfilter mode enforce")
		}
	}
	if !enableBoot && !startNow {
		fmt.Println("Later:  sudo systemctl enable --now xdpfilter")
	}
	return nil
}

func listNICs() []nic {
	ifs, _ := net.Interfaces()
	var out []nic
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		out = append(out, nic{
			Name:   i.Name,
			Driver: driverOf(i.Name),
			Up:     i.Flags&net.FlagUp != 0,
			Speed:  readTrim(fmt.Sprintf("/sys/class/net/%s/speed", i.Name)),
			XDP:    dataplane.ProbeXDP(i.Name), // actually test XDP support
		})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

func printNICs(nics []nic) {
	fmt.Printf("%-4s %-12s %-10s %-6s %-9s %-8s\n", "#", "iface", "driver", "up", "xdp", "speed")
	for idx, n := range nics {
		sp := n.Speed
		if sp != "" {
			sp += "Mb/s"
		}
		fmt.Printf("%-4d %-12s %-10s %-6v %-9s %-8s\n", idx, n.Name, n.Driver, n.Up, n.XDP, sp)
	}
	fmt.Println()
}

func pickIface(in *bufio.Reader, nics []nic, role string) string {
	for {
		s := prompt(in, role+" [# or name, 'b<#>' to blink]", "")
		if strings.HasPrefix(s, "b") {
			if idx, err := strconv.Atoi(strings.TrimPrefix(s, "b")); err == nil && idx >= 0 && idx < len(nics) {
				fmt.Printf("  blinking %s for 5s...\n", nics[idx].Name)
				_ = exec.Command("ethtool", "--identify", nics[idx].Name, "5").Run()
			}
			continue
		}
		if idx, err := strconv.Atoi(s); err == nil && idx >= 0 && idx < len(nics) {
			return nics[idx].Name
		}
		for _, n := range nics {
			if n.Name == s {
				return s
			}
		}
		fmt.Println("  not a valid selection")
	}
}

func driverOf(ifc string) string {
	link, err := os.Readlink(fmt.Sprintf("/sys/class/net/%s/device/driver", ifc))
	if err != nil {
		return "none"
	}
	return filepath.Base(link)
}

func suggestFlowMax() uint32 {
	memKB := 0
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "MemTotal:") {
				fields := strings.Fields(sc.Text())
				if len(fields) >= 2 {
					memKB, _ = strconv.Atoi(fields[1])
				}
				break
			}
		}
	}
	gb := memKB / 1024 / 1024
	switch {
	case gb >= 8:
		return 1 << 24 // 16M ≈ 2 GiB (default)
	case gb >= 2:
		return 1 << 22 // 4M ≈ 512 MiB
	default:
		return 1 << 20 // 1M ≈ 128 MiB
	}
}

// ---- prompt helpers ----

func prompt(in *bufio.Reader, q, def string) string {
	if def != "" {
		fmt.Printf("%s (%s): ", q, def)
	} else {
		fmt.Printf("%s: ", q)
	}
	line, _ := in.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func promptYN(in *bufio.Reader, q string, def bool) bool {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	fmt.Printf("%s [%s]: ", q, d)
	line, _ := in.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return def
	}
	return line == "y" || line == "yes"
}

func runVisible(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
