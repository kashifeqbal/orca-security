#!/bin/bash
# =============================================================================
# Module: canary — Tripwire canary tokens
# =============================================================================
# Creates fake sensitive files. If anyone reads/modifies them, WatchClaw alerts.
# These are files an attacker would look for: SSH keys, wallet, .env, etc.
# =============================================================================

set -euo pipefail
source /etc/watchclaw/watchclaw.conf 2>/dev/null || true

CANARY_STATE="/var/lib/watchclaw/canary"
CANARY_LOG="/var/log/watchclaw/canary.log"

log()  { echo -e "\033[0;32m[WatchClaw:canary]\033[0m $*"; }

mkdir -p "$CANARY_STATE"

# Default canary paths
CANARY_PATHS=("${CANARY_PATHS[@]:-
    /root/.ssh/id_rsa_canary
    /etc/shadow.bak
    /root/.bitcoin/wallet.dat
    /var/www/.env
    /root/.aws/credentials_backup
    /home/admin/.bash_history_backup
}")

# Create canary files with realistic-looking content
create_canary() {
    local path="$1"
    local dir
    dir=$(dirname "$path")
    mkdir -p "$dir"

    case "$path" in
        *id_rsa*)
            cat > "$path" << 'CANARY'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
WatchClaw-CANARY-TOKEN-DO-NOT-USE
QyNTUxOQAAACCUkTc5RqHOxGzMaOAaHG7dCMORCA0CANARY0TOKEN00000000
-----END OPENSSH PRIVATE KEY-----
CANARY
            ;;
        *wallet*)
            echo '{"version":1,"addr":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","balance":"0.00000001"}' > "$path"
            ;;
        *.env*)
            cat > "$path" << 'CANARY'
DATABASE_URL=postgres://admin:orca_canary_not_real@db.internal:5432/prod
AWS_SECRET_ACCESS_KEY=WatchClaw/CANARY/TOKEN/NOT/REAL/KEY
STRIPE_SECRET_KEY=sk_live_orca_canary_not_real_key
CANARY
            ;;
        *credentials*)
            cat > "$path" << 'CANARY'
[default]
aws_access_key_id = AKIAORCA0CANARY0TOKEN
aws_secret_access_key = WatchClaw/CANARY/NOT/REAL/wJalrXUtnFEMI
CANARY
            ;;
        *shadow*)
            echo 'root:$6$watchclaw.canary$NOT.A.REAL.HASH.THIS.IS.A.CANARY.TOKEN:19000:0:99999:7:::' > "$path"
            ;;
        *)
            echo "WATCHCLAW_CANARY_TOKEN=$(date +%s)" > "$path"
            ;;
    esac

    chmod 600 "$path"

    # Record initial checksum
    local hash
    hash=$(sha256sum "$path" | awk '{print $1}')
    echo "${path}|${hash}|$(date -Iseconds)" >> "${CANARY_STATE}/checksums"

    log "Planted canary: $path"
}

# Create monitoring script
cat > /opt/watchclaw/scripts/canary-check.sh << 'CHECKEOF'
#!/bin/bash
# Canary token checker — runs via cron
set -euo pipefail
source /etc/watchclaw/watchclaw.conf 2>/dev/null || true
CANARY_STATE="/var/lib/watchclaw/canary"
CANARY_LOG="/var/log/watchclaw/canary.log"
ALERT_FUNC="/opt/watchclaw/lib/watchclaw-alert.sh"
[ -f "$ALERT_FUNC" ] && source "$ALERT_FUNC"

[ ! -f "${CANARY_STATE}/checksums" ] && exit 0

TRIGGERED=()
while IFS='|' read -r path orig_hash planted_at; do
    [ -z "$path" ] && continue
    if [ ! -f "$path" ]; then
        # File deleted — that's suspicious too
        TRIGGERED+=("DELETED: $path (planted: $planted_at)")
        continue
    fi
    current_hash=$(sha256sum "$path" 2>/dev/null | awk '{print $1}')
    if [ "$current_hash" != "$orig_hash" ]; then
        TRIGGERED+=("MODIFIED: $path (planted: $planted_at)")
    fi
    # Check access time (if filesystem supports it)
    atime=$(stat -c %X "$path" 2>/dev/null || echo 0)
    plant_ts=$(date -d "$planted_at" +%s 2>/dev/null || echo 0)
    if [ "$atime" -gt "$plant_ts" ] 2>/dev/null; then
        TRIGGERED+=("ACCESSED: $path (at: $(date -d @$atime -Iseconds))")
    fi
done < "${CANARY_STATE}/checksums"

if [ ${#TRIGGERED[@]} -gt 0 ]; then
    MSG="🚨🐦 CANARY ALERT — Potential Intrusion Detected!\n\n"
    for t in "${TRIGGERED[@]}"; do
        MSG="${MSG}⚠️ ${t}\n"
    done
    MSG="${MSG}\nThis means someone accessed files that should never be touched."
    MSG="${MSG}\nInvestigate immediately."
    echo -e "$MSG" >> "$CANARY_LOG"
    # Send alert
    if type watchclaw_alert &>/dev/null; then
        watchclaw_alert "$MSG"
    fi
    echo -e "$MSG"
fi
CHECKEOF
chmod +x /opt/watchclaw/scripts/canary-check.sh

# Plant canaries
> "${CANARY_STATE}/checksums"  # Reset
for path in "${CANARY_PATHS[@]}"; do
    path=$(echo "$path" | xargs)  # trim whitespace
    [ -z "$path" ] && continue
    create_canary "$path"
done

# Add to cron
if [ -f /etc/cron.d/watchclaw ]; then
    grep -q "canary-check" /etc/cron.d/watchclaw || \
        echo "*/5 * * * *  root /opt/watchclaw/scripts/canary-check.sh >> /var/log/watchclaw/canary.log 2>&1" >> /etc/cron.d/watchclaw
fi

log "✅ Canary tokens planted (${#CANARY_PATHS[@]} files). Checked every 5 minutes."
