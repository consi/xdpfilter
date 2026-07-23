#!/bin/sh
set -e

# Ensure the BPF filesystem is mounted (needed for pinned maps/links).
if ! grep -qs '/sys/fs/bpf ' /proc/mounts; then
	mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
fi

systemctl daemon-reload 2>/dev/null || true

cat <<'EOF'

xdpfilter installed.

  Next step:   sudo xdpfilter setup

The service is intentionally NOT started until you complete setup (it needs to
know which two ports form the bridge). setup picks the ports, sets policy,
previews the tuning profile, and enables the service.

EOF
