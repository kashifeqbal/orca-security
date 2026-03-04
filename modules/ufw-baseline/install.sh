#!/bin/bash
# =============================================================================
# Module: ufw-baseline — Firewall hardening with UFW
# =============================================================================

set -euo pipefail
source /etc/watchclaw/watchclaw.conf 2>/dev/null || true

SSH_PORT="${SSH_PORT:-2222}"
UFW="/usr/sbin/ufw"

log()  { echo -e "\033[0;32m[WatchClaw:ufw]\033[0m $*"; }

# Install UFW if missing
if ! command -v ufw &>/dev/null; then
    log "Installing UFW..."
    apt-get update -qq && apt-get install -y -qq ufw 2>/dev/null || dnf install -y ufw 2>/dev/null
fi

# Reset to clean state (non-interactive)
log "Setting UFW defaults..."
$UFW --force reset 2>/dev/null || true
$UFW default deny incoming
$UFW default allow outgoing

# Allow honeypot (port 22) — this is the trap
$UFW allow 22/tcp comment "Cowrie honeypot"
$UFW deny 22/udp

# Real SSH — loopback only
$UFW allow from 127.0.0.1 to any port "$SSH_PORT" comment "SSH real - loopback only"
$UFW deny "$SSH_PORT" comment "Block external real SSH"

# Rate limit Syncthing if present
if command -v syncthing &>/dev/null || ss -tlnp | grep -q 22000; then
    $UFW allow 22000/tcp comment "Syncthing TCP"
    $UFW allow 22000/udp comment "Syncthing UDP"
    log "Syncthing ports allowed"
fi

# Extra allowed ports from config
for port in ${UFW_EXTRA_ALLOW:-}; do
    $UFW allow "$port" comment "WatchClaw extra allow"
    log "Allowed extra port: $port"
done

# Rate-limited ports
for port in ${UFW_RATE_LIMIT_PORTS:-}; do
    $UFW limit "$port" comment "WatchClaw rate-limited"
    log "Rate-limited port: $port"
done

# Enable
$UFW --force enable
log "✅ UFW firewall configured and enabled"
$UFW status verbose
