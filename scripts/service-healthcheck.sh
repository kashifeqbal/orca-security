#!/bin/bash
# WatchClaw Self-Healing Health Check
# Runs every 30min. Checks services, restarts failures, alerts on issues.

ENV_FILE="/root/.openclaw/.env"
[ -f "$ENV_FILE" ] && set -a && source "$ENV_FILE" && set +a

BOT="${OPS_ALERTS_BOT_TOKEN:-}"
CHAT_ID="${ALERTS_TELEGRAM_CHAT:-}"
LOG="/root/.openclaw/workspace/agents/ops/logs/service-health.log"
CRON_SOURCE="/root/.openclaw/workspace/config/cron-jobs-source.json"
CRON_BACKUP="/root/.openclaw/workspace/config/cron-jobs-backup.json"
CRON_LIVE="/root/.openclaw/cron/jobs.json"
CRON_AUDIT="/root/.openclaw/workspace/scripts/cron-channel-audit.sh"
WATCHCLAW_STATE="/root/.watchclaw/watchclaw-state.json"

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

# ── 0. WatchClaw preflight (fail fast on script warnings/errors) ─────────────────
PREFLIGHT_SCRIPT="$(dirname "$0")/watchclaw-preflight.sh"
if [ -x "$PREFLIGHT_SCRIPT" ]; then
  PREFLIGHT_OUT=$("$PREFLIGHT_SCRIPT" 2>/dev/null || true)
  if echo "$PREFLIGHT_OUT" | grep -q '"status":"failed"'; then
    ISSUES+=("WatchClaw preflight failed (script parser warnings/errors)")
    log "ISSUE: preflight failed payload=${PREFLIGHT_OUT}"
    MSG="🚨 *Ops Alert — $(date '+%Y-%m-%d %H:%M')*\n\n❌ WatchClaw preflight failed (script parser warnings/errors).\nCheck: /root/.openclaw/workspace/agents/ops/scripts/watchclaw-preflight.sh"
    alert "$MSG"
    exit 0
  fi
fi

# ── 1. Check .env has all required keys ──────────────────────────────────────
ENV_FILE="/root/.openclaw/.env"
REQUIRED_KEYS="OPENAI_API_KEY GEMINI_API_KEY TAVILY_API_KEY SKILL_GOPLACES_KEY"
ENV_BROKEN=false
for key in $REQUIRED_KEYS; do
  val=$(grep "^${key}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2-)
  if [ -z "$val" ]; then
    ENV_BROKEN=true
    break
  fi
done

if [ "$ENV_BROKEN" = true ]; then
  log "WARN: .env has missing keys — running load-secrets.sh"
  /usr/local/bin/load-secrets.sh >> "$LOG" 2>&1
  FIXED+=(".env secrets reloaded from 1Password")
fi

# ── 2. Check crons — restore if count drops unexpectedly ────────────────────
CRON_COUNT=$(openclaw cron list --all 2>/dev/null | grep -c "idle\|ok\|error\|running") || CRON_COUNT=0
if [ "$CRON_COUNT" -lt 9 ]; then
  log "WARN: Only $CRON_COUNT crons found (expected >=9) — restoring"
  if [ -x "/root/.openclaw/workspace/scripts/restore-crons.sh" ]; then
    /root/.openclaw/workspace/scripts/restore-crons.sh >> "$LOG" 2>&1
    NEW_COUNT=$(openclaw cron list --all 2>/dev/null | grep -c "idle\|ok\|error\|running") || NEW_COUNT=0
    if [ "$NEW_COUNT" -ge 9 ]; then
      FIXED+=("Crons restored via restore-crons.sh ($CRON_COUNT → $NEW_COUNT)")
    else
      ISSUES+=("Cron restore attempted but count still low ($NEW_COUNT)")
    fi
  else
    RESTORE_FROM=""
    if [ -f "$CRON_SOURCE" ]; then
      RESTORE_FROM="$CRON_SOURCE"
    elif [ -f "$CRON_BACKUP" ]; then
      RESTORE_FROM="$CRON_BACKUP"
    fi

    if [ -n "$RESTORE_FROM" ]; then
      cp "$RESTORE_FROM" "$CRON_LIVE"
      if [ -x "$CRON_AUDIT" ]; then
        "$CRON_AUDIT" "$CRON_LIVE" >> "$LOG" 2>&1 || ISSUES+=("Cron audit failed after restore")
      fi
      FIXED+=("Crons restored from $(basename "$RESTORE_FROM")")
    else
      ISSUES+=("Cron source/backup missing — manual restore needed")
    fi
  fi
fi

# ── 3. Check OpenClaw gateway ────────────────────────────────────────────────
GW_STATUS=$(openclaw gateway status 2>/dev/null)
if echo "$GW_STATUS" | grep -q "running"; then
  : # gateway ok
elif curl -sf http://127.0.0.1:18789/ > /dev/null 2>&1; then
  : # gateway reachable via HTTP, ok
else
  log "WARN: OpenClaw gateway down — restarting"
  /usr/local/bin/load-secrets.sh >> "$LOG" 2>&1
  sleep 3
  XDG_RUNTIME_DIR=/run/user/0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus     openclaw gateway start >> "$LOG" 2>&1
  sleep 5
  if openclaw gateway status 2>/dev/null | grep -q "running"; then
    FIXED+=("OpenClaw gateway restarted ✅")
  else
    ISSUES+=("OpenClaw gateway STILL DOWN after restart ❌")
  fi
fi

# ── 4. Check system services ─────────────────────────────────────────────────
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

check_service "syncthing@syncthing" "systemctl restart syncthing@syncthing"
check_service "cloudflared" "systemctl restart cloudflared"
check_service "fail2ban" "systemctl restart fail2ban"
check_service "cowrie" "systemctl restart cowrie"

# ── 5. Check cowrie actually listening on port 22 ────────────────────────────
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

# ── 6. Check disk usage ──────────────────────────────────────────────────────
DISK_PCT=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
if [ "$DISK_PCT" -gt 85 ]; then
  ISSUES+=("⚠️ Disk usage at ${DISK_PCT}% — action needed")
fi

# ── 6b. Run security posture report (separate from health checks) ────────────
# Posture reporter handles its own Telegram alerts for MEDIUM+ severity.
# We capture any critical posture issues and add to ISSUES for health alert.
POSTURE_SCRIPT="$(dirname "$0")/security-posture.sh"
if [ -x "$POSTURE_SCRIPT" ]; then
  POSTURE_ERR_FILE=$(mktemp)
  POSTURE_OUTPUT=$("$POSTURE_SCRIPT" 2>"$POSTURE_ERR_FILE" || true)
  POSTURE_STDERR=$(cat "$POSTURE_ERR_FILE" 2>/dev/null || true)
  rm -f "$POSTURE_ERR_FILE"

  if [ -n "$POSTURE_STDERR" ] || echo "$POSTURE_STDERR" | grep -Eqi "unterminated|syntax error|unexpected token"; then
    ISSUES+=("Script warning output detected from security-posture.sh")
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      ISSUES+=("stderr: $line")
    done <<< "$POSTURE_STDERR"
  fi

  POSTURE_SEVERITY=$(echo "$POSTURE_OUTPUT" | grep '^SECURITY STATUS:' | awk '{print $3}')
  if [ "$POSTURE_SEVERITY" = "CRITICAL" ]; then
    SUPPRESS_CRIT_ALERT="0"
    if [ -f "$WATCHCLAW_STATE" ]; then
      SUPPRESS_CRIT_ALERT=$(python3 - "$WATCHCLAW_STATE" <<'PYEOF' 2>/dev/null || echo "0"
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

    if [ "$SUPPRESS_CRIT_ALERT" = "1" ]; then
      log "Posture CRITICAL alert suppressed (already sent within 10m by WatchClaw)"
    else
      ISSUES+=("🔴 Security posture CRITICAL — see security-posture.log")
    fi
  fi
  log "Posture: severity=${POSTURE_SEVERITY:-unknown} score=$(echo "$POSTURE_OUTPUT" | grep 'Active Threat' | awk '{print $NF}')"
fi

# ── 7. Send alerts ───────────────────────────────────────────────────────────
if [ ${#ISSUES[@]} -gt 0 ]; then
  MSG="🚨 *Ops Alert — $(date '+%Y-%m-%d %H:%M')*"$'\n\n'
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
  MSG="🔧 *Ops Auto-fix — $(date '+%Y-%m-%d %H:%M')*"$'\n\n'
  for fix in "${FIXED[@]}"; do
    MSG+="✅ $fix"$'\n'
    log "FIXED: $fix"
  done
  alert "$MSG"
else
  log "OK: All services healthy | Disk: ${DISK_PCT}% | Crons: $CRON_COUNT/9"
fi
