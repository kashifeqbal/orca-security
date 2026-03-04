#!/bin/bash
# =============================================================================
# cowrie-autoban.sh — Cowrie Connection-Count Auto-Ban + Argus Threat Feeder
# =============================================================================
# Original behaviour: ban IPs with >= 20 connections today via UFW.
# Added: feed counted connections into Argus threat DB for stateful scoring,
# and apply score-based escalation bans on top of raw connection bans.
#
# This script does NOT remove existing bans or replace service-healthcheck.
# =============================================================================

ENV_FILE="/root/.openclaw/.env"
[ -f "$ENV_FILE" ] && set -a && source "$ENV_FILE" && set +a

LOGFILE="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
BAN_LOG="/root/.openclaw/workspace/agents/ops/logs/cowrie-bans.log"
THRESHOLD=20
UFW="/usr/sbin/ufw"
TELEGRAM_BOT="${OPS_ALERTS_BOT_TOKEN:-}"
TELEGRAM_CHAT="${ALERTS_TELEGRAM_CHAT:--5206059645}"

# Source WatchClaw library (threat-db.sh is now a compat shim → watchclaw-lib.sh)
LIB_DIR="$(dirname "$0")/lib"
# shellcheck source=scripts/lib/threat-db.sh
source "${LIB_DIR}/threat-db.sh"

mkdir -p "$(dirname "$BAN_LOG")"

BANNED_NEW=""
argus_init

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
    threat_record_event "$IP" "recon_fingerprint" "$EXTRA" > /dev/null 2>&1 || true

    # Also record individual failed_login for the connection count
    # (batched: record once per threshold unit to avoid inflating score)
    if [ "$COUNT" -ge "$((THRESHOLD * 5))" ]; then
        # Very high volume — record additional score events
        threat_record_event "$IP" "recon_fingerprint" "high_volume" > /dev/null 2>&1 || true
    fi

    # Apply score-based ban via Argus (handles escalation, double-penalty)
    BAN_TYPE=$(threat_check_and_ban "$IP" 2>/dev/null || echo "none")

    # Legacy: also apply raw UFW ban if not already present (original behaviour)
    if ! $UFW status | grep -q "$IP"; then
        $UFW deny from "$IP" to any comment "cowrie-autoban" 2>/dev/null || true
        TS=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$TS] BANNED: $IP (connections: $COUNT, argus_ban: $BAN_TYPE)" >> "$BAN_LOG"
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
INEFFECTIVE=$(threat_verify_bans 2>/dev/null || true)
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

# ── WatchClaw post-batch: cluster detection + geo anomaly check ────────────────────
watchclaw_post_batch 2>/dev/null || true
