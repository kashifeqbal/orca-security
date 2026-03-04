#!/bin/bash
# =============================================================================
# WatchClaw Alert Library — multi-channel alert dispatcher
# =============================================================================

source /etc/watchclaw/watchclaw.conf 2>/dev/null || true

watchclaw_alert() {
    local msg="$1"
    local priority="${2:-normal}"  # normal, critical

    # Telegram
    if [ -n "${ALERT_TELEGRAM_TOKEN:-}" ] && [ -n "${ALERT_TELEGRAM_CHAT:-}" ]; then
        curl -s --max-time 10 -X POST \
            "https://api.telegram.org/bot${ALERT_TELEGRAM_TOKEN}/sendMessage" \
            -d "chat_id=${ALERT_TELEGRAM_CHAT}" \
            --data-urlencode "text=${msg}" > /dev/null 2>&1
    fi

    # Discord
    if [ -n "${ALERT_DISCORD_WEBHOOK:-}" ]; then
        local json
        json=$(python3 -c "import json; print(json.dumps({'content': '''$msg'''}))" 2>/dev/null)
        curl -s --max-time 10 -X POST "$ALERT_DISCORD_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$json" > /dev/null 2>&1
    fi

    # Slack
    if [ -n "${ALERT_SLACK_WEBHOOK:-}" ]; then
        local json
        json=$(python3 -c "import json; print(json.dumps({'text': '''$msg'''}))" 2>/dev/null)
        curl -s --max-time 10 -X POST "$ALERT_SLACK_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$json" > /dev/null 2>&1
    fi

    # Generic webhook
    if [ -n "${ALERT_WEBHOOK_URL:-}" ]; then
        local json
        json=$(python3 -c "
import json, datetime
print(json.dumps({
    'source': 'watchclaw',
    'priority': '$priority',
    'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
    'message': '''$msg'''
}))" 2>/dev/null)
        curl -s --max-time 10 -X POST "$ALERT_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            ${ALERT_WEBHOOK_HEADERS:+-H "$ALERT_WEBHOOK_HEADERS"} \
            -d "$json" > /dev/null 2>&1
    fi
}
