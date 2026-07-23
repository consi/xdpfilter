#!/bin/sh
set -e

systemctl disable --now xdpfilter 2>/dev/null || true

# Remove the XDP datapath (the transparent bridge) and revert tuning.
# Best-effort: the binary is still present at preremove time.
if [ -x /usr/sbin/xdpfilter ]; then
	/usr/sbin/xdpfilter stop --detach --restore --yes 2>/dev/null || true
fi
