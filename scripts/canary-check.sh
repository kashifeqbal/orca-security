#!/bin/bash
# WatchClaw — https://github.com/kashifeqbal/watchclaw
# =============================================================================
# canary-check.sh — Tripwire canary token checker
# =============================================================================
# Checks if any planted fake files were accessed, modified, or deleted.
# If triggered: IMMEDIATE critical alert — someone is poking around.
# =============================================================================

set -euo pipefail

# Load WatchClaw config
WATCHCLAW_CONF="${WATCHCLAW_CONF:-/etc/watchclaw/watchclaw.conf}"
# shellcheck source=/etc/watchclaw/watchclaw.conf
[ -f "$WATCHCLAW_CONF" ] && source "$WATCHCLAW_CONF"

# Telegram credentials (accept WATCHCLAW_ prefix or ALERT_ prefix from config)
WATCHCLAW_TELEGRAM_TOKEN="${WATCHCLAW_TELEGRAM_TOKEN:-${ALERT_TELEGRAM_TOKEN:-}}"
WATCHCLAW_ALERT_CHAT_ID="${WATCHCLAW_ALERT_CHAT_ID:-${ALERT_TELEGRAM_CHAT:-}}"

CANARY_STATE="/var/lib/watchclaw/canary/checksums"
CANARY_LOG="/var/log/watchclaw/canary.log"
TELEGRAM_BOT="${WATCHCLAW_TELEGRAM_TOKEN:-}"
TELEGRAM_CHAT="${WATCHCLAW_ALERT_CHAT_ID:-}"

mkdir -p /var/log/watchclaw

[ ! -f "$CANARY_STATE" ] && exit 0

TRIGGERED=()

while IFS='|' read -r orig_hash path planted_at; do
    [ -z "$path" ] && continue

    if [ ! -f "$path" ]; then
        TRIGGERED+=("🗑️ DELETED: $path")
        continue
    fi

    current_hash=$(sha256sum "$path" 2>/dev/null | awk '{print $1}')
    if [ "$current_hash" != "$orig_hash" ]; then
        TRIGGERED+=("✏️ MODIFIED: $path")
    fi
done < "$CANARY_STATE"

if [ ${#TRIGGERED[@]} -gt 0 ]; then
    MSG="🚨🐦 CANARY ALERT — Potential Intrusion!

Someone touched files that should NEVER be accessed.
This could indicate an active breach.

"
    for t in "${TRIGGERED[@]}"; do
        MSG="${MSG}${t}
"
    done
    MSG="${MSG}
⚠️ Investigate immediately."

    echo "[$(date -Iseconds)] $MSG" >> "$CANARY_LOG"

    # Send critical alert
    if [ -n "$TELEGRAM_BOT" ]; then
        curl -s --max-time 10 -X POST \
            "https://api.telegram.org/bot${TELEGRAM_BOT}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT}" \
            --data-urlencode "text=${MSG}" > /dev/null
    fi
fi
