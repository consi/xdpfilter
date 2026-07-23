// SPDX-License-Identifier: GPL-2.0
// Minimal XDP_PASS program. In the veth harness this is attached to the two
// netns-side endpoints so that frames redirected *to* their peer (the box side)
// are accepted into the netns — veth requires the receiving peer to have a
// native XDP program loaded, mirroring the mlx5 TX-SQ rule on real hardware.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
