#!/bin/bash
# =============================================================================
# Module: ssh-harden — SSH hardening
# =============================================================================
# - Moves SSH to custom port
# - Disables password auth
# - Disables root password login (key-only)
# - Installs public key if provided
# =============================================================================

set -euo pipefail
source /etc/watchclaw/watchclaw.conf 2>/dev/null || true

SSH_PORT="${SSH_PORT:-2222}"
SSH_CONF="/etc/ssh/sshd_config"
SSH_CONF_BACKUP="${SSH_CONF}.watchclaw-backup"

log()  { echo -e "\033[0;32m[WatchClaw:ssh-harden]\033[0m $*"; }
warn() { echo -e "\033[0;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; }

# Backup original config
if [ ! -f "$SSH_CONF_BACKUP" ]; then
    cp "$SSH_CONF" "$SSH_CONF_BACKUP"
    log "Backed up sshd_config"
fi

# Set port
if grep -q "^Port " "$SSH_CONF"; then
    sed -i "s/^Port .*/Port ${SSH_PORT}/" "$SSH_CONF"
else
    echo "Port ${SSH_PORT}" >> "$SSH_CONF"
fi
log "SSH port set to ${SSH_PORT}"

# Listen on loopback only (external access via tunnel)
if grep -q "^ListenAddress " "$SSH_CONF"; then
    sed -i "s/^ListenAddress .*/ListenAddress 127.0.0.1\nListenAddress ::1/" "$SSH_CONF"
else
    echo -e "ListenAddress 127.0.0.1\nListenAddress ::1" >> "$SSH_CONF"
fi
log "SSH bound to loopback only"

# Disable password auth
sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' "$SSH_CONF"
sed -i 's/^#*ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' "$SSH_CONF"
sed -i 's/^#*UsePAM .*/UsePAM yes/' "$SSH_CONF"
log "Password authentication disabled"

# Disable root password login (allow key)
sed -i 's/^#*PermitRootLogin .*/PermitRootLogin prohibit-password/' "$SSH_CONF"
log "Root login: key-only"

# Harden settings
grep -q "^MaxAuthTries" "$SSH_CONF" || echo "MaxAuthTries 3" >> "$SSH_CONF"
grep -q "^LoginGraceTime" "$SSH_CONF" || echo "LoginGraceTime 30" >> "$SSH_CONF"
grep -q "^ClientAliveInterval" "$SSH_CONF" || echo "ClientAliveInterval 300" >> "$SSH_CONF"
grep -q "^ClientAliveCountMax" "$SSH_CONF" || echo "ClientAliveCountMax 2" >> "$SSH_CONF"
log "Hardening settings applied"

# Install SSH key if provided
if [ -n "${SSH_PUBKEY:-}" ]; then
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    if ! grep -qF "$SSH_PUBKEY" /root/.ssh/authorized_keys 2>/dev/null; then
        echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
        log "Public key installed"
    fi
fi

# Test config before restart
if sshd -t 2>/dev/null; then
    systemctl restart sshd
    log "sshd restarted on port ${SSH_PORT}"
else
    err "sshd config test failed! Restoring backup."
    cp "$SSH_CONF_BACKUP" "$SSH_CONF"
    systemctl restart sshd
    exit 1
fi

log "✅ SSH hardening complete"
