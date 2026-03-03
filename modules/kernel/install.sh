#!/bin/bash
# =============================================================================
# Module: kernel — Kernel/sysctl hardening
# =============================================================================
# Hardens TCP stack, prevents IP spoofing, SYN flood protection,
# disables unnecessary protocols, and limits information leakage.
# =============================================================================

set -euo pipefail
source /etc/orca/orca.conf 2>/dev/null || true

SYSCTL_CONF="/etc/sysctl.d/99-orca-hardening.conf"

log()  { echo -e "\033[0;32m[ORCA:kernel]\033[0m $*"; }

cat > "$SYSCTL_CONF" << 'EOF'
# =============================================================================
# ORCA Kernel Hardening — sysctl settings
# =============================================================================

# ── TCP/IP Stack Hardening ───────────────────────────────────────────────────
# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects (prevents MITM)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Don't act as a router
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Ignore broadcast ICMP (smurf attack prevention)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log martian packets (impossible addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ── Memory & Process Hardening ───────────────────────────────────────────────
# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointers
kernel.kptr_restrict = 2

# Restrict ptrace (prevents process snooping)
kernel.yama.ptrace_scope = 1

# Randomize memory layout (ASLR)
kernel.randomize_va_space = 2

# ── File System ──────────────────────────────────────────────────────────────
# Restrict access to kernel logs
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# ── inotify (for Syncthing/file watchers) ────────────────────────────────────
fs.inotify.max_user_watches = 1048576
fs.inotify.max_user_instances = 512
EOF

# Optional: disable IPv6 entirely
if [ "${DISABLE_IPV6:-false}" = "true" ]; then
    cat >> "$SYSCTL_CONF" << 'EOF'

# ── Disable IPv6 ─────────────────────────────────────────────────────────────
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    log "IPv6 disabled"
fi

# Apply
sysctl -p "$SYSCTL_CONF" > /dev/null 2>&1
log "✅ Kernel hardening applied ($(grep -c '=' "$SYSCTL_CONF") settings)"
