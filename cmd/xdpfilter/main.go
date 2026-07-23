// SPDX-License-Identifier: GPL-2.0

// Command xdpfilter is a transparent bump-in-the-wire XDP TCP/UDP filter:
// data plane + control plane in one static binary.
//
// Author: Marek Wajdzik <marek@jest.pro> (C) 2026.
// Licensed under the GNU General Public License v2.0 (see LICENSE).
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	osexec "os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/consi/xdpfilter/internal/config"
	"github.com/consi/xdpfilter/internal/dataplane"
	"github.com/consi/xdpfilter/internal/meta"
	"github.com/consi/xdpfilter/internal/stats"
	"github.com/consi/xdpfilter/internal/tuning"
	"github.com/consi/xdpfilter/internal/wizard"
)

// set via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "run":
		err = cmdRunSvc(os.Args[2:])
	case "daemon":
		err = cmdDaemon(os.Args[2:])
	case "reload":
		err = cmdReload(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "mode":
		err = cmdMode(os.Args[2:])
	case "flows":
		err = cmdFlows(os.Args[2:])
	case "tune":
		err = cmdTune(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "stop":
		err = cmdStop(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("xdpfilter %s\n%s\n", version, meta.Copyright)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("xdpfilter %s: %v", os.Args[1], err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `xdpfilter — transparent XDP spoofed-TCP filter

usage:
  xdpfilter setup                 interactive first-run wizard
  xdpfilter run                   start the systemd service (runs in background)
  xdpfilter daemon [--config P]   run the datapath in the foreground (systemd ExecStart)
  xdpfilter status [--watch]      show live counters
  xdpfilter reload                reload config live (allowlist / policy / TTLs)
  xdpfilter mode monitor|enforce  flip mode live (no reattach)
  xdpfilter flows [--limit N]     sample the flow table
  xdpfilter tune [--dry-run]      apply/preview performance tuning
  xdpfilter check                 preflight the environment
  xdpfilter stop [--detach] [--restore] [--yes]
  xdpfilter version
`)
	fmt.Fprintf(os.Stderr, "\n%s\n", meta.Copyright)
}

func loadCfg(fs *flag.FlagSet, args []string) (*config.Config, error) {
	path := fs.String("config", config.DefaultPath, "config file path")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	path := fs.String("config", config.DefaultPath, "config file path")
	_ = fs.Parse(args)
	if config.Exists(*path) {
		fmt.Printf("Config %s already exists; re-running setup will overwrite it.\n", *path)
	}
	return wizard.Run(*path)
}

// cmdRunSvc starts the systemd service in the background.
func cmdRunSvc(args []string) error {
	_ = runCmd("systemctl", "daemon-reload") // ensure any updated unit is loaded
	if err := runCmd("systemctl", "start", "xdpfilter"); err != nil {
		return fmt.Errorf("systemctl start xdpfilter failed (run `xdpfilter setup` first?): %w", err)
	}
	fmt.Println("xdpfilter service started. Watch:  xdpfilter status")
	return nil
}

// cmdReload asks the running service to re-read its config live.
func cmdReload(args []string) error {
	if err := runCmd("systemctl", "reload", "xdpfilter"); err != nil {
		return fmt.Errorf("systemctl reload failed (is the service running?): %w", err)
	}
	fmt.Println("reloaded")
	return nil
}

// cmdDaemon runs the datapath in the foreground (the systemd ExecStart target).
func cmdDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("daemon must be root")
	}

	// 1. Performance tuning (best-effort; logged).
	if err := tuning.New(cfg, false, os.Stderr).Apply(); err != nil {
		log.Printf("tuning: %v", err)
	}

	// 2. Load + attach the datapath.
	h, err := dataplane.Load(cfg)
	if err != nil {
		return err
	}
	defer h.Close() // keep datapath attached across restarts (pins persist)

	log.Printf("xdpfilter %s attached: %s(trusted) <-> %s(untrusted), mode=%s, flow_max=%d",
		version, cfg.TrustedIface, cfg.UntrustedIface, cfg.Mode, cfg.FlowMax)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var live int64
	// cfgPtr publishes an immutable config snapshot; the GC goroutine reads it and
	// reload swaps in a new one — no shared mutable Config, no data race.
	cfgPtr := &atomic.Pointer[config.Config]{}
	cfgPtr.Store(cfg)
	occ := func() (int, int) {
		return int(atomic.LoadInt64(&live)), int(h.Maps.Flows.MaxEntries() + h.Maps.UDPFlows.MaxEntries())
	}
	ports := fmt.Sprintf("%s (trusted) <-> %s (untrusted)", cfg.TrustedIface, cfg.UntrustedIface)
	reporter := stats.NewReporter(version, cfg.StatsDir, ports, occ)

	// Workers are tracked in a WaitGroup so shutdown waits for them to stop
	// before the deferred h.Close frees the maps they read.
	var wg sync.WaitGroup
	spawn := func(d time.Duration, fn func()) {
		wg.Add(1)
		go func() { defer wg.Done(); loop(ctx, d, fn) }()
	}

	// GC — sweep both the TCP and UDP flow tables.
	spawn(time.Duration(cfg.GCInterval)*time.Second, func() {
		c := cfgPtr.Load()
		lt, _ := dataplane.GCOnce(h.Maps.Flows, c)
		lu, _ := dataplane.GCOnce(h.Maps.UDPFlows, c)
		atomic.StoreInt64(&live, int64(lt+lu))
	})

	// Stats.
	spawn(time.Duration(cfg.StatsInterval)*time.Second, func() {
		warn, err := reporter.Tick(h.Maps, dataplane.Mode(h.Maps))
		if err != nil {
			log.Printf("stats: %v", err)
		}
		if warn != "" {
			log.Printf("ALERT %s", warn)
		}
	})

	// systemd readiness + watchdog.
	sdNotify("READY=1")
	if wd := watchdogInterval(); wd > 0 {
		spawn(wd, func() { sdNotify("WATCHDOG=1") })
	}

	// Live config reload: applies the updatable subset (policy toggles, TTLs,
	// server allowlist) to the maps with no reattach. Runs only on this goroutine
	// (SIGHUP or a debounced file-change event), so map updates never overlap.
	reload := func() {
		newCfg, err := config.Load(*cfgPath)
		if err != nil {
			log.Printf("reload: %v (keeping running config)", err)
			return
		}
		cur := cfgPtr.Load()
		if d := cur.StructuralDiff(newCfg); d != "" {
			log.Printf("reload: %s changed — needs a restart; applying live subset only", d)
		}
		merged := *cur // snapshot; publish atomically before touching the maps
		merged.ApplyLiveFrom(newCfg)
		cfgPtr.Store(&merged)
		if err := dataplane.ReloadPolicy(h.Maps, &merged); err != nil {
			log.Printf("reload: %v", err)
			return
		}
		log.Printf("reload: applied — mode=%s, filter_udp=%v, allowlist=%d servers",
			merged.Mode, merged.FilterUDP, len(merged.ServerAllow))
	}

	reloadCh := make(chan struct{}, 1)
	go watchConfig(ctx, *cfgPath, reloadCh)

	// Wait for termination; reload on SIGHUP or a config-file change.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	for stop := false; !stop; {
		select {
		case s := <-sig:
			if s == syscall.SIGHUP {
				log.Printf("SIGHUP: reloading config")
				reload()
			} else {
				stop = true
			}
		case <-reloadCh:
			log.Printf("config file changed; reloading")
			reload()
		}
	}
	sdNotify("STOPPING=1")
	cancel() // stop the workers, then wait before the deferred h.Close frees the maps
	wg.Wait()
	log.Printf("shutting down (datapath stays attached; use `xdpfilter stop --detach` to remove)")
	return nil
}

// watchConfig posts a (debounced) request to reloadCh whenever the config file is
// written or replaced. A single save can emit several inotify events (temp write +
// rename + close); debouncing coalesces them into one reload. Best-effort: if
// inotify is unavailable, SIGHUP / `systemctl reload` still work.
func watchConfig(ctx context.Context, path string, reloadCh chan<- struct{}) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		log.Printf("config watch disabled (inotify: %v); use `xdpfilter reload`", err)
		return
	}
	if _, err := unix.InotifyAddWatch(fd, filepath.Dir(path),
		unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO|unix.IN_CREATE); err != nil {
		log.Printf("config watch disabled (%v); use `xdpfilter reload`", err)
		unix.Close(fd)
		return
	}
	go func() { <-ctx.Done(); unix.Close(fd) }() // unblock Read on shutdown

	fire := func() { // non-blocking, coalescing send
		select {
		case reloadCh <- struct{}{}:
		default:
		}
	}
	base := filepath.Base(path)
	buf := make([]byte, 4096)
	var debounce *time.Timer
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			return // fd closed on shutdown
		}
		changed := false
		for off := 0; off+unix.SizeofInotifyEvent <= n; {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
			start := off + unix.SizeofInotifyEvent
			nameLen := int(ev.Len)
			if nameLen > 0 && start+nameLen <= n {
				if string(bytes.TrimRight(buf[start:start+nameLen], "\x00")) == base {
					changed = true
				}
			}
			off = start + nameLen
		}
		if changed {
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(150*time.Millisecond, fire)
		}
	}
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	watch := fs.Bool("watch", false, "refresh every 2s")
	path := fs.String("config", config.DefaultPath, "config file path")
	_ = fs.Parse(args)

	pinDir, ports := config.DefaultPinDir, "?"
	if cfg, err := config.Load(*path); err == nil {
		pinDir = cfg.PinDir
		ports = fmt.Sprintf("%s (trusted) <-> %s (untrusted)", cfg.TrustedIface, cfg.UntrustedIface)
	}
	m, err := dataplane.OpenPinned(pinDir)
	if err != nil {
		return err
	}
	defer m.Close()

	render := func() {
		fmt.Print(stats.PrintStatus(m, version, ports, func() (int, int) {
			return 0, int(m.Flows.MaxEntries() + m.UDPFlows.MaxEntries())
		}))
	}
	if !*watch {
		render()
		return nil
	}
	for {
		fmt.Print("\033[H\033[2J") // clear
		render()
		time.Sleep(2 * time.Second)
	}
}

func cmdMode(args []string) error {
	// Extract the positional (monitor|enforce) so flags may appear in any order
	// — Go's flag package otherwise stops parsing at the first positional.
	var mode string
	var flagArgs []string
	for _, a := range args {
		if a == "monitor" || a == "enforce" {
			mode = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}
	fs := flag.NewFlagSet("mode", flag.ExitOnError)
	path := fs.String("config", config.DefaultPath, "config file path")
	_ = fs.Parse(flagArgs)
	if mode == "" {
		return fmt.Errorf("usage: xdpfilter mode monitor|enforce")
	}
	rest := []string{mode}
	pinDir := config.DefaultPinDir
	if cfg, err := config.Load(*path); err == nil {
		pinDir = cfg.PinDir
	}
	if err := dataplane.SetModePinned(pinDir, rest[0] == "enforce"); err != nil {
		return err
	}
	// persist to config so the mode survives a restart
	if cfg, err := config.Load(*path); err == nil {
		cfg.Mode = rest[0]
		if err := cfg.Save(*path); err != nil {
			log.Printf("warning: mode changed in kernel but not saved to %s: %v", *path, err)
		}
	}
	fmt.Printf("mode set to %s\n", rest[0])
	return nil
}

func cmdFlows(args []string) error {
	fs := flag.NewFlagSet("flows", flag.ExitOnError)
	limit := fs.Int("limit", 50, "max rows (0 = all)")
	path := fs.String("config", config.DefaultPath, "config file path")
	vlan := fs.Int("vlan", -1, "filter by outer VID")
	_ = fs.Parse(args)

	pinDir := config.DefaultPinDir
	if cfg, err := config.Load(*path); err == nil {
		pinDir = cfg.PinDir
	}
	m, err := dataplane.OpenPinned(pinDir)
	if err != nil {
		return err
	}
	defer m.Close()

	rows := append(dataplane.DumpFlows(m.Flows, "TCP", 0), dataplane.DumpFlows(m.UDPFlows, "UDP", 0)...)
	fmt.Printf("%-5s %-21s %-21s %-6s %-9s %-6s\n", "proto", "host", "internet", "vid", "state", "age")
	n := 0
	for _, f := range rows {
		if *vlan >= 0 && int(f.OuterVID) != *vlan {
			continue
		}
		fmt.Printf("%-5s %-21s %-21s %-6d %-9s %ds\n",
			f.Proto,
			net.JoinHostPort(f.HostIP.String(), strconv.Itoa(int(f.HostPort))),
			net.JoinHostPort(f.InetIP.String(), strconv.Itoa(int(f.InetPort))),
			f.OuterVID, f.State, f.AgeSec)
		n++
		if *limit > 0 && n >= *limit {
			break
		}
	}
	fmt.Printf("(%d shown)\n", n)
	return nil
}

func cmdTune(args []string) error {
	fs := flag.NewFlagSet("tune", flag.ExitOnError)
	dry := fs.Bool("dry-run", false, "preview only")
	cfg, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	return tuning.New(cfg, *dry, os.Stdout).Apply()
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	path := fs.String("config", config.DefaultPath, "config file path")
	_ = fs.Parse(args)

	ok := true
	pass := func(cond bool, label string, detail string) {
		mark := "PASS"
		if !cond {
			mark, ok = "FAIL", false
		}
		fmt.Printf("[%s] %-28s %s\n", mark, label, detail)
	}

	cfg, err := config.Load(*path)
	pass(err == nil, "config", cond(err == nil, *path, fmt.Sprint(err)))
	if err == nil {
		for _, ifc := range []string{cfg.TrustedIface, cfg.UntrustedIface} {
			_, e := net.InterfaceByName(ifc)
			pass(e == nil, "interface "+ifc, cond(e == nil, "present", "missing"))
		}
	}
	bpffs := mountsContain("/sys/fs/bpf")
	pass(bpffs, "bpffs mounted", cond(bpffs, "/sys/fs/bpf", "mount -t bpf bpf /sys/fs/bpf"))
	memlockErr := rlimit.RemoveMemlock()
	pass(memlockErr == nil, "memlock", cond(memlockErr == nil, "ok", fmt.Sprint(memlockErr)))
	pass(os.Geteuid() == 0, "root", cond(os.Geteuid() == 0, "yes", "run as root"))

	if !ok {
		return fmt.Errorf("preflight failed")
	}
	fmt.Println("all checks passed")
	return nil
}

func cmdStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	detach := fs.Bool("detach", false, "remove the XDP datapath (WARNING: the wire goes dark)")
	restore := fs.Bool("restore", false, "restore tuning snapshot")
	yes := fs.Bool("yes", false, "skip confirmation")
	path := fs.String("config", config.DefaultPath, "config file path")
	_ = fs.Parse(args)

	pinDir := config.DefaultPinDir
	if cfg, err := config.Load(*path); err == nil {
		pinDir = cfg.PinDir
	}

	// Stop the daemon (leaves the datapath attached via pins).
	_ = runCmd("systemctl", "stop", "xdpfilter")

	if *detach {
		if !*yes {
			fmt.Print("Detaching removes the transparent bridge — traffic between the two ports STOPS. Continue? [y/N]: ")
			var r string
			fmt.Scanln(&r)
			if strings.ToLower(strings.TrimSpace(r)) != "y" {
				return fmt.Errorf("aborted")
			}
		}
		if err := dataplane.Detach(pinDir); err != nil {
			log.Printf("detach: %v", err)
		} else {
			fmt.Println("datapath detached, pins removed")
		}
	}
	if *restore {
		if err := tuning.Restore(os.Stdout); err != nil {
			log.Printf("restore: %v", err)
		}
	}
	return nil
}

// ---- helpers ----

func loop(ctx context.Context, d time.Duration, fn func()) {
	if d <= 0 {
		d = time.Second
	}
	fn() // run once immediately
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}

func sdNotify(state string) {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return
	}
	if sock[0] == '@' { // abstract namespace
		sock = "\x00" + sock[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		return
	}
	defer c.Close()
	_, _ = c.Write([]byte(state))
}

func watchdogInterval() time.Duration {
	usec, err := strconv.Atoi(os.Getenv("WATCHDOG_USEC"))
	if err != nil || usec <= 0 {
		return 0
	}
	return time.Duration(usec/2) * time.Microsecond
}

func mountsContain(path string) bool {
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == path && strings.HasPrefix(f[2], "bpf") {
			return true
		}
	}
	return false
}

func cond(b bool, a, c string) string {
	if b {
		return a
	}
	return c
}

func runCmd(name string, args ...string) error {
	c := osexec.Command(name, args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}
