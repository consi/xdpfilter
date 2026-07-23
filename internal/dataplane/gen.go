// SPDX-License-Identifier: GPL-2.0

package dataplane

// Compile bpf/filter.bpf.c with clang and embed the resulting object + a spec
// loader (loadFilter) into this package. Requires clang + libbpf headers at
// build time only; the produced Go binary is self-contained.
//
// Default targets are bpfel + bpfeb (endianness). amd64 (the ship target) and
// arm64 (the dev VM) are both little-endian, so filter_bpfel.o serves both.
//
// The -I flags for the arch asm/ headers cover Debian's multiarch layout
// (clang -target bpf does not add them); the absent one is silently ignored.
//
// -mcpu=v3 enables the alu32 / jmp32 BPF ISA (kernel >= 5.1; our SEC("xdp.frags")
// floor is already 5.18), which lets LLVM emit 32-bit ops without zero-extension
// padding — fewer instructions on the hot path.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -mcpu=v3 -Wall -Werror -I../../bpf -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu" filter ../../bpf/filter.bpf.c
