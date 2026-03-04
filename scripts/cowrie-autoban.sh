#!/bin/bash
# WatchClaw — https://github.com/kashifeqbal/watchclaw
# =============================================================================
# cowrie-autoban.sh — Cowrie Connection-Count Auto-Ban + WatchClaw Threat Feeder
# =============================================================================
# Original behaviour: ban IPs with >= 20 connections today via UFW.
# Added: feed counted connections into WatchClaw threat DB for stateful scoring,
# and apply score-based escalation bans on top of raw connection bans.
#
# This script does NOT remove existing bans or replace service-healthcheck.
# =============================================================================

# Load WatchClaw config
WATCHCLAW_CONF="${WATCHCLAW_CONF:-/etc/watchclaw/watchclaw.conf}"
# shellcheck source=/etc/watchclaw/watchclaw.conf
[ -f "$WATCHCLAW_CONF" ] && source "$WATCHCLAW_CONF"

# Telegram credentials (accept WATCHCLAW_ prefix or ALERT_ prefix from config)
WATCHCLAW_TELEGRAM_TOKEN="${WATCHCLAW_TELEGRAM_TOKEN:-${ALERT_TELEGRAM_TOKEN:-}}"
WATCHCLAW_ALERT_CHAT_ID="${WATCHCLAW_ALERT_CHAT_ID:-${ALERT_TELEGRAM_CHAT:-}}"
# Bridge for watchclaw-lib.sh (uses OPS_ALERTS_BOT_TOKEN / ALERTS_TELEGRAM_CHAT)
OPS_ALERTS_BOT_TOKEN="${WATCHCLAW_TELEGRAM_TOKEN:-}"
ALERTS_TELEGRAM_CHAT="${WATCHCLAW_ALERT_CHAT_ID:-}"

LOGFILE="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
BAN_LOG="/var/log/watchclaw/cowrie-bans.log"
THRESHOLD=20
UFW="/usr/sbin/ufw"
TELEGRAM_BOT="${WATCHCLAW_TELEGRAM_TOKEN:-}"
TELEGRAM_CHAT="${WATCHCLAW_ALERT_CHAT_ID:-}"

# Source WatchClaw library
LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)/lib"
# shellcheck source=lib/watchclaw-lib.sh
source "${LIB_DIR}/watchclaw-lib.sh"

mkdir -p "$(dirname "$BAN_LOG")"

BANNED_NEW=""
watchclaw_init

# ── Get IPs over connection threshold today ───────────────────────────────────
FLAGGED=$(python3 - <<'PYEOF'
import json
from collections import Counter
import datetime

counter = Counter()
today = datetime.date.today().isoformat()
try:
    with open('/home/cowrie/cowrie/var/log/cowrie/cowrie.json') as f:
        for line in f:
            try:
                e = json.loads(line)
                if e.get('eventid') == 'cowrie.session.connect' and \
                   e.get('timestamp', '').startswith(today):
                    counter[e['src_ip']] += 1
            except Exception:
                pass
except Exception:
    pass

for ip, count in counter.items():
    if count >= 20:
        print(f"{ip}|{count}")
PYEOF
)

# ── Process each flagged IP ───────────────────────────────────────────────────
for ENTRY in $FLAGGED; do
    IP=$(echo "$ENTRY" | cut -d'|' -f1)
    COUNT=$(echo "$ENTRY" | cut -d'|' -f2)

    # Feed bulk connection events into threat DB
    # Each connect beyond threshold counts as multiple failed_login events
    # We record a recon_fingerprint to represent the high-volume activity
    EXTRA="bulk_connections_${COUNT}"
    watchclaw_record_event "$IP" "recon_fingerprint" "$EXTRA" > /dev/null 2>&1 || true

    # Also record individual failed_login for the connection count
    # (batched: record once per threshold unit to avoid inflating score)
    if [ "$COUNT" -ge "$((THRESHOLD * 5))" ]; then
        # Very high volume — record additional score events
        watchclaw_record_event "$IP" "recon_fingerprint" "high_volume" > /dev/null 2>&1 || true
    fi

    # Apply score-based ban via WatchClaw (handles escalation, double-penalty)
    BAN_TYPE=$(watchclaw_check_and_ban "$IP" 2>/dev/null || echo "none")

    # Legacy: also apply raw UFW ban if not already present (original behaviour)
    if ! $UFW status | grep -q "$IP"; then
        $UFW deny from "$IP" to any comment "cowrie-autoban" 2>/dev/null || true
        TS=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$TS] BANNED: $IP (connections: $COUNT, watchclaw_ban: $BAN_TYPE)" >> "$BAN_LOG"
        BANNED_NEW="${BANNED_NEW}
🚫 ${IP} (${COUNT} connections, score-ban: ${BAN_TYPE}, connection-ban: applied)"
    fi
done

# ── Telegram alert for new connection-count bans ──────────────────────────────
if [ -n "$BANNED_NEW" ] && [ -n "$TELEGRAM_BOT" ]; then
    MSG="🛡️ Cowrie Auto-Ban${BANNED_NEW}"
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT}/sendMessage" \
        --data-urlencode "chat_id=${TELEGRAM_CHAT}" \
        --data-urlencode "text=${MSG}" > /dev/null
fi

# ── Also verify existing bans are still effective ────────────────────────────
INEFFECTIVE=$(orca_verify_bans 2>/dev/null || true)
if [ -n "$INEFFECTIVE" ]; then
    # Re-apply missing UFW rules silently
    while IFS='|' read -r bip btype breason; do
        if [ -n "$bip" ]; then
            $UFW deny from "$bip" to any comment "watchclaw-reapplied" 2>/dev/null || true
            TS=$(date '+%Y-%m-%d %H:%M:%S')
            echo "[$TS] REAPPLIED BAN: $bip ($btype) reason: $breason" >> "$BAN_LOG"
        fi
    done <<< "$INEFFECTIVE"
fi

# ── WatchClaw post-batch: cluster detection + geo anomaly check ───────────────
watchclaw_post_batch 2>/dev/null || true
