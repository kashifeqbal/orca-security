#!/bin/bash
# WatchClaw preflight: syntax + warning guard for ops scripts
# - fails fast when parser warnings/errors are detected
# - emits at most one alert per unique warning signature per hour

set -euo pipefail

ENV_FILE="/root/.openclaw/.env"
[ -f "$ENV_FILE" ] && set -a && source "$ENV_FILE" && set +a

BOT="${OPS_ALERTS_BOT_TOKEN:-}"
CHAT_ID="${ALERTS_TELEGRAM_CHAT:--5206059645}"
STATE_FILE="/root/.openclaw/workspace/agents/ops/logs/watchclaw-preflight-state.json"
SCRIPTS_DIR="/root/.openclaw/workspace/agents/ops/scripts"

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
done < <(find "$SCRIPTS_DIR" -type f -name "*.sh" | sort)

# Runtime smoke test: ensure WatchClaw init works even if HOME is unset
RUNTIME_OUT=$(env -u HOME bash -lc 'source /root/.openclaw/workspace/agents/ops/scripts/lib/watchclaw-lib.sh && watchclaw_init && echo ok' 2>&1 || true)
if ! echo "$RUNTIME_OUT" | grep -q '^ok$'; then
  warnings+="runtime: env -u HOME watchclaw_init failed: ${RUNTIME_OUT}"$'\n'
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
  msg="🚨 WatchClaw Preflight failed\n\n$(printf '%s' "$warnings" | head -n 12)"
  send_alert "$msg"
  jq -n --argjson ts "$now" --arg sig "$sig" '{last_alert_ts:$ts,last_signature:$sig}' > "$STATE_FILE"
fi

echo "{\"status\":\"failed\",\"warnings\":$(printf '%s' "$warnings" | grep -c .),\"signature\":\"$sig\"}"
exit 1
