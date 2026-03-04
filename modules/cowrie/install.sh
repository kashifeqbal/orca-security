#!/bin/bash
# =============================================================================
# Module: cowrie — SSH Honeypot on port 22
# =============================================================================
# Installs Cowrie as a system service, listening on port 22.
# Real SSH should already be moved to a different port (ssh-harden module).
# =============================================================================

set -euo pipefail
source /etc/watchclaw/watchclaw.conf 2>/dev/null || true

COWRIE_USER="${COWRIE_USER:-cowrie}"
COWRIE_DIR="${COWRIE_DIR:-/home/${COWRIE_USER}/cowrie}"
COWRIE_REPO="https://github.com/cowrie/cowrie.git"

log()  { echo -e "\033[0;32m[WatchClaw:cowrie]\033[0m $*"; }
warn() { echo -e "\033[0;33m[WARN]\033[0m $*"; }

# Check if Cowrie already installed
if [ -d "$COWRIE_DIR" ] && [ -f "${COWRIE_DIR}/bin/cowrie" ]; then
    log "Cowrie already installed at ${COWRIE_DIR}"
    if systemctl is-active --quiet cowrie 2>/dev/null; then
        log "Cowrie is running ✅"
        exit 0
    fi
fi

# Install dependencies
log "Installing Cowrie dependencies..."
apt-get update -qq
apt-get install -y -qq \
    git python3-virtualenv libssl-dev libffi-dev build-essential \
    libpython3-dev python3-minimal authbind virtualenv \
    2>/dev/null || true

# Create cowrie user
if ! id "$COWRIE_USER" &>/dev/null; then
    adduser --disabled-password --gecos "Cowrie Honeypot" "$COWRIE_USER"
    log "Created user: $COWRIE_USER"
fi

# Clone Cowrie
if [ ! -d "$COWRIE_DIR" ]; then
    sudo -u "$COWRIE_USER" git clone "$COWRIE_REPO" "$COWRIE_DIR"
    log "Cloned Cowrie repo"
fi

# Setup virtualenv
cd "$COWRIE_DIR"
if [ ! -d "cowrie-env" ]; then
    sudo -u "$COWRIE_USER" python3 -m virtualenv cowrie-env
fi
sudo -u "$COWRIE_USER" bash -c "source cowrie-env/bin/activate && pip install --quiet --upgrade pip && pip install --quiet -r requirements.txt"
log "Cowrie virtualenv ready"

# Configure Cowrie
sudo -u "$COWRIE_USER" cp etc/cowrie.cfg.dist etc/cowrie.cfg 2>/dev/null || true
cat > etc/cowrie.cfg.local << 'CFGEOF'
[ssh]
listen_endpoints = tcp:22:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json

[honeypot]
hostname = server01
timezone = UTC
CFGEOF
chown "$COWRIE_USER:$COWRIE_USER" etc/cowrie.cfg.local
log "Cowrie configured on port 22"

# Authbind for port 22 (allows non-root to bind)
touch /etc/authbind/byport/22
chown "$COWRIE_USER:$COWRIE_USER" /etc/authbind/byport/22
chmod 770 /etc/authbind/byport/22

# Systemd service
cat > /etc/systemd/system/cowrie.service << EOF
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
Type=forking
User=${COWRIE_USER}
Group=${COWRIE_USER}
WorkingDirectory=${COWRIE_DIR}
ExecStart=${COWRIE_DIR}/bin/cowrie start
ExecStop=${COWRIE_DIR}/bin/cowrie stop
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cowrie
systemctl start cowrie

log "✅ Cowrie honeypot installed and running on port 22"
