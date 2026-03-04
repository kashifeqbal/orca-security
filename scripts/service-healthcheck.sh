#!/bin/bash
# WatchClaw — https://github.com/kashifeqbal/watchclaw
# WatchClaw Self-Healing Health Check
# Runs every 10min. Checks services, restarts failures, alerts on issues.

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

BOT="${WATCHCLAW_TELEGRAM_TOKEN:-}"
CHAT_ID="${WATCHCLAW_ALERT_CHAT_ID:-}"
LOG="/var/log/watchclaw/service-health.log"
WATCHCLAW_STATE_FILE="${WATCHCLAW_DIR:-${HOME:-/root}/.watchclaw}/watchclaw-state.json"

mkdir -p "$(dirname "$LOG")"
TS=$(date '+%Y-%m-%d %H:%M:%S')
ISSUES=()
FIXED=()

alert() {
  [ -z "$BOT" ] && return 0
  curl -s -X POST "https://api.telegram.org/bot${BOT}/sendMessage" \
    --data-urlencode "chat_id=${CHAT_ID}" \
    --data-urlencode "text=$1" > /dev/null
}

log() { echo "[$TS] $1" >> "$LOG"; }

# ── 0. WatchClaw preflight (fail fast on script warnings/errors) ──────────────
PREFLIGHT_SCRIPT="$(dirname "$0")/watchclaw-preflight.sh"
if [ -x "$PREFLIGHT_SCRIPT" ]; then
  PREFLIGHT_OUT=$("$PREFLIGHT_SCRIPT" 2>/dev/null || true)
  if echo "$PREFLIGHT_OUT" | grep -q '"status":"failed"'; then
    ISSUES+=("WatchClaw preflight failed (script parser warnings/errors)")
    log "ISSUE: preflight failed payload=${PREFLIGHT_OUT}"
    MSG="🚨 *WatchClaw Alert — $(date '+%Y-%m-%d %H:%M')*\n\n❌ WatchClaw preflight failed.\nCheck: /opt/watchclaw/scripts/watchclaw-preflight.sh"
    alert "$MSG"
    exit 0
  fi
fi

# ── 1. Check system services ──────────────────────────────────────────────────
check_service() {
  local name=$1
  local restart_cmd=$2
  if ! systemctl is-active --quiet "$name" 2>/dev/null; then
    log "WARN: $name is down — restarting"
    eval "$restart_cmd" >> "$LOG" 2>&1
    sleep 3
    if systemctl is-active --quiet "$name" 2>/dev/null; then
      FIXED+=("$name restarted ✅")
    else
      ISSUES+=("$name STILL DOWN ❌")
    fi
  fi
}

check_service "fail2ban" "systemctl restart fail2ban"
check_service "cowrie"   "systemctl restart cowrie"

# ── 2. Check cowrie process ───────────────────────────────────────────────────
if ! pgrep -u cowrie twistd > /dev/null 2>&1; then
  log "WARN: Cowrie process not found — restarting service"
  systemctl restart cowrie >> "$LOG" 2>&1
  sleep 3
  if pgrep -u cowrie twistd > /dev/null 2>&1; then
    FIXED+=("Cowrie honeypot restarted ✅")
  else
    ISSUES+=("Cowrie honeypot STILL DOWN ❌")
  fi
fi

# ── 3. Check disk usage ───────────────────────────────────────────────────────
DISK_PCT=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
if [ "$DISK_PCT" -gt 85 ]; then
  ISSUES+=("⚠️ Disk usage at ${DISK_PCT}% — action needed")
fi

# ── 4. Run security posture report (handles its own Telegram for ELEVATED+) ───
POSTURE_SCRIPT="$(dirname "$0")/security-posture.sh"
if [ -x "$POSTURE_SCRIPT" ]; then
  POSTURE_ERR_FILE=$(mktemp)
  POSTURE_OUTPUT=$("$POSTURE_SCRIPT" 2>"$POSTURE_ERR_FILE" || true)
  POSTURE_STDERR=$(cat "$POSTURE_ERR_FILE" 2>/dev/null || true)
  rm -f "$POSTURE_ERR_FILE"

  if [ -n "$POSTURE_STDERR" ]; then
    ISSUES+=("Warnings from security-posture.sh")
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      ISSUES+=("stderr: $line")
    done <<< "$POSTURE_STDERR"
  fi

  POSTURE_SEVERITY=$(echo "$POSTURE_OUTPUT" | grep '^SECURITY STATUS:' | awk '{print $3}')
  if [ "$POSTURE_SEVERITY" = "CRITICAL" ]; then
    # Rate-limit: suppress if last CRITICAL was < 10m ago
    SUPPRESS_CRIT="0"
    if [ -f "$WATCHCLAW_STATE_FILE" ]; then
      SUPPRESS_CRIT=$(python3 - "$WATCHCLAW_STATE_FILE" <<'PYEOF' 2>/dev/null || echo "0"
import sys, json, datetime
p = sys.argv[1]
try:
    s = json.load(open(p))
except Exception:
    print("0")
    raise SystemExit
last = (s.get('alert_rates', {}) or {}).get('CRITICAL', '')
if not last:
    print('0')
    raise SystemExit
try:
    last_dt = datetime.datetime.fromisoformat(last.rstrip('Z'))
    now = datetime.datetime.utcnow()
    print('1' if (now - last_dt).total_seconds() < 600 else '0')
except Exception:
    print('0')
PYEOF
)
    fi

    if [ "$SUPPRESS_CRIT" = "1" ]; then
      log "Posture CRITICAL alert suppressed (already sent within 10m)"
    else
      ISSUES+=("🔴 Security posture CRITICAL — see /var/log/watchclaw/security-posture.log")
    fi
  fi
  log "Posture: severity=${POSTURE_SEVERITY:-unknown}"
fi

# ── 5. Send alerts ────────────────────────────────────────────────────────────
if [ ${#ISSUES[@]} -gt 0 ]; then
  MSG="🚨 *WatchClaw Alert — $(date '+%Y-%m-%d %H:%M')*"$'\n\n'
  for issue in "${ISSUES[@]}"; do
    MSG+="❌ $issue"$'\n'
    log "ISSUE: $issue"
  done
  if [ ${#FIXED[@]} -gt 0 ]; then
    MSG+=$'\n'"*Auto-fixed:*"$'\n'
    for fix in "${FIXED[@]}"; do
      MSG+="✅ $fix"$'\n'
      log "FIXED: $fix"
    done
  fi
  alert "$MSG"
elif [ ${#FIXED[@]} -gt 0 ]; then
  MSG="🔧 *WatchClaw Auto-fix — $(date '+%Y-%m-%d %H:%M')*"$'\n\n'
  for fix in "${FIXED[@]}"; do
    MSG+="✅ $fix"$'\n'
    log "FIXED: $fix"
  done
  alert "$MSG"
else
  log "OK: All services healthy | Disk: ${DISK_PCT}%"
fi
