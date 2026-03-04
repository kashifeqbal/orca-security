#!/bin/bash
# WatchClaw — https://github.com/kashifeqbal/watchclaw
# WatchClaw preflight: syntax + warning guard for ops scripts
# - fails fast when parser warnings/errors are detected
# - emits at most one alert per unique warning signature per hour

set -euo pipefail

# Load WatchClaw config
WATCHCLAW_CONF="${WATCHCLAW_CONF:-/etc/watchclaw/watchclaw.conf}"
# shellcheck source=/etc/watchclaw/watchclaw.conf
[ -f "$WATCHCLAW_CONF" ] && source "$WATCHCLAW_CONF"

# Telegram credentials (accept WATCHCLAW_ prefix or ALERT_ prefix from config)
WATCHCLAW_TELEGRAM_TOKEN="${WATCHCLAW_TELEGRAM_TOKEN:-${ALERT_TELEGRAM_TOKEN:-}}"
WATCHCLAW_ALERT_CHAT_ID="${WATCHCLAW_ALERT_CHAT_ID:-${ALERT_TELEGRAM_CHAT:-}}"

BOT="${WATCHCLAW_TELEGRAM_TOKEN:-}"
CHAT_ID="${WATCHCLAW_ALERT_CHAT_ID:-}"
STATE_FILE="/var/lib/watchclaw/preflight-state.json"
SCRIPTS_DIR="${WATCHCLAW_INSTALL_DIR:-/opt/watchclaw}/scripts"

mkdir -p "$(dirname "$STATE_FILE")"
[ -f "$STATE_FILE" ] || echo '{"last_alert_ts":0,"last_signature":""}' > "$STATE_FILE"

send_alert() {
  local msg="$1"
  [ -z "$BOT" ] && return 0
  curl -s --max-time 10 -X POST "https://api.telegram.org/bot${BOT}/sendMessage" \
    --data-urlencode "chat_id=${CHAT_ID}" \
    --data-urlencode "text=$msg" > /dev/null || true
}

warnings=""
while IFS= read -r f; do
  [ -f "$f" ] || continue
  out=$(bash -n "$f" 2>&1 || true)
  if [ -n "$out" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      warnings+="$(basename "$f"): $line"$'\n'
    done <<< "$out"
  fi
done < <(find "$SCRIPTS_DIR" -type f -name "*.sh" 2>/dev/null | sort)

# Runtime smoke test: ensure WatchClaw lib loads correctly
LIB_DIR="${WATCHCLAW_INSTALL_DIR:-/opt/watchclaw}/lib"
RUNTIME_OUT=$(bash -c "source '${LIB_DIR}/watchclaw-lib.sh' && watchclaw_init && echo ok" 2>&1 || true)
if ! echo "$RUNTIME_OUT" | grep -q '^ok$'; then
  warnings+="runtime: watchclaw_init failed: ${RUNTIME_OUT}"$'\n'
fi

if [ -z "$warnings" ]; then
  echo '{"status":"ok","warnings":0}'
  exit 0
fi

sig=$(printf '%s' "$warnings" | sha256sum | awk '{print $1}')
now=$(date +%s)
last_ts=$(jq -r '.last_alert_ts // 0' "$STATE_FILE" 2>/dev/null || echo 0)
last_sig=$(jq -r '.last_signature // ""' "$STATE_FILE" 2>/dev/null || echo "")

# Alert only if signature changed OR >1h since last alert
if [ "$sig" != "$last_sig" ] || [ $((now - last_ts)) -ge 3600 ]; then
  msg="🚨 WatchClaw Preflight failed

$(printf '%s' "$warnings" | head -n 12)"
  send_alert "$msg"
  jq -n --argjson ts "$now" --arg sig "$sig" '{last_alert_ts:$ts,last_signature:$sig}' > "$STATE_FILE"
fi

echo "{\"status\":\"failed\",\"warnings\":$(printf '%s' "$warnings" | grep -c .),\"signature\":\"$sig\"}"
exit 1
