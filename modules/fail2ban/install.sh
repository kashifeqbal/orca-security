#!/bin/bash
# =============================================================================
# Module: fail2ban — Brute-force protection
# =============================================================================

set -euo pipefail
source /etc/orca/orca.conf 2>/dev/null || true

log()  { echo -e "\033[0;32m[ORCA:fail2ban]\033[0m $*"; }

# Install fail2ban if missing
if ! command -v fail2ban-client &>/dev/null; then
    log "Installing fail2ban..."
    apt-get update -qq && apt-get install -y -qq fail2ban 2>/dev/null || dnf install -y fail2ban 2>/dev/null
fi

# Configure jail
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = ${F2B_BANTIME:--1}
findtime = ${F2B_FINDTIME:-600}
maxretry = ${F2B_MAXRETRY:-3}
backend  = systemd

[sshd]
enabled  = true
port     = ssh
maxretry = ${F2B_MAXRETRY:-3}
EOF

log "fail2ban jail configured"

# Enable and start
systemctl enable fail2ban
systemctl restart fail2ban
log "✅ fail2ban installed and running"
fail2ban-client status sshd 2>/dev/null || true
