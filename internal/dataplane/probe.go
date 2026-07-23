// SPDX-License-Identifier: GPL-2.0

package dataplane

import (
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

var memlockOnce sync.Once

// ProbeXDP reports the best XDP attach mode an interface actually supports:
//
//	"native"  — driver/native XDP works (mlx5, Intel ice/i40e/ixgbe, veth, ...)
//	"generic" — only SKB/generic XDP works
//	"busy"    — an XDP program is already attached (so it IS XDP-capable)
//	"none"    — neither mode attaches
//
// It works by briefly attaching a harmless XDP_PASS program and detaching it —
// far more reliable than guessing from the driver name.
func ProbeXDP(ifname string) string {
	memlockOnce.Do(func() { _ = rlimit.RemoveMemlock() })

	iff, err := net.InterfaceByName(ifname)
	if err != nil {
		return "none"
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:    "xdp_probe",
		Type:    ebpf.XDP,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 2), // XDP_PASS
			asm.Return(),
		},
	})
	if err != nil {
		return "none"
	}
	defer prog.Close()

	try := func(flags link.XDPAttachFlags) (bool, bool) { // (ok, busy)
		l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: iff.Index, Flags: flags})
		if err == nil {
			l.Close()
			return true, false
		}
		return false, isBusy(err)
	}

	if ok, busy := try(link.XDPDriverMode); ok {
		return "native"
	} else if busy {
		return "busy"
	}
	if ok, busy := try(link.XDPGenericMode); ok {
		return "generic"
	} else if busy {
		return "busy"
	}
	return "none"
}

func isBusy(err error) bool {
	if errors.Is(err, unix.EBUSY) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "busy") || strings.Contains(s, "already")
}
