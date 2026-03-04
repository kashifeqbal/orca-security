#!/bin/bash
# WatchClaw — https://github.com/kashifeqbal/watchclaw
# =============================================================================
# cowrie-notify.sh — Cowrie Honeypot Telegram Notifier + WatchClaw Threat Feeder
# =============================================================================
# Reads new cowrie JSON log entries, feeds events into the WatchClaw threat DB
# for stateful scoring, then sends a Telegram summary for notable activity.
#
# Original behaviour preserved: alerts on login success, commands, malware.
# New: every event is recorded in ~/.watchclaw/threat-db.json with scoring.
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

BOT_TOKEN="${WATCHCLAW_TELEGRAM_TOKEN:-}"
CHAT_ID="${WATCHCLAW_ALERT_CHAT_ID:-}"
LOGFILE="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
STATEFILE="/var/lib/watchclaw/cowrie-lastpos"

# Source WatchClaw library
LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)/lib"
# shellcheck source=lib/watchclaw-lib.sh
source "${LIB_DIR}/watchclaw-lib.sh"

# ── Helpers ───────────────────────────────────────────────────────────────────
send_telegram() {
    [ -z "$BOT_TOKEN" ] && return 0
    curl -s --max-time 10 -X POST \
        "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        -d "chat_id=${CHAT_ID}" \
        --data-urlencode "text=$1" > /dev/null
}

[ ! -f "$LOGFILE" ] && exit 0

# ── Track position in log file ────────────────────────────────────────────────
LASTPOS=0
[ -f "$STATEFILE" ] && LASTPOS=$(cat "$STATEFILE")
FILESIZE=$(stat -c%s "$LOGFILE" 2>/dev/null || echo 0)

# Reset if file was rotated
[ "$FILESIZE" -lt "$LASTPOS" ] && LASTPOS=0

# Read new lines
NEW_LINES=$(tail -c +"$((LASTPOS + 1))" "$LOGFILE" 2>/dev/null)
[ -z "$NEW_LINES" ] && exit 0

# Save new position
echo "$FILESIZE" > "$STATEFILE"

# ── Parse events, score each IP, build Telegram message ───────────────────────
watchclaw_init

# We'll accumulate alert lines and also feed threat DB in one Python pass,
# then post-process with shell for scoring/bans.
_PYSC=$(mktemp /tmp/cowrie-parse-XXXXXX.py)
cat > "$_PYSC" <<'PYEOF'
import sys, json

scored_events = []  # list of (ip, event_type, extra_info, display_str)

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        e  = json.loads(line)
        t  = e.get('eventid', '')
        ip = e.get('src_ip', '?')

        if t == 'cowrie.login.failed':
            scored_events.append((ip, 'failed_login', '', None))  # suppress individual lines

        elif t == 'cowrie.login.success':
            user = e.get('username', '?')
            pw   = e.get('password', '?')
            s    = f"🚨 LOGIN SUCCESS: {ip} user={user} pass={pw}"
            scored_events.append((ip, 'login_success', f"{user}:{pw}", s))

        elif t == 'cowrie.command.input':
            cmd = e.get('input', '?')
            s   = f"💻 Command: {ip} ran: {cmd}"
            # Detect persistence attempts
            event_type = 'command_exec'
            if any(k in cmd for k in ('authorized_keys', '.bashrc', '.profile', 'crontab', 'systemctl enable', 'rc.local')):
                event_type = 'persistence_attempt'
                s = f"⛓️ Persistence attempt: {ip} cmd: {cmd}"
            scored_events.append((ip, event_type, cmd, s))

        elif t == 'cowrie.session.file_download':
            url = e.get('url', '?')
            s   = f"📥 Malware download: {ip} → {url}"
            scored_events.append((ip, 'malware_download', url, s))

        elif t == 'cowrie.direct-tcpip.request':
            dst = e.get('dst_ip', '?')
            s   = f"🌐 Tunnel attempt: {ip} → {dst}"
            scored_events.append((ip, 'tunnel_tcpip', dst, s))

        elif t in ('cowrie.fingerprint.ssh', 'cowrie.client.version'):
            # Track fingerprint chain events; combine with session.connect to flag recon
            scored_events.append((ip, 'recon_fingerprint', t, None))

        elif t == 'cowrie.session.connect':
            scored_events.append((ip, 'failed_login', '', None))  # count connects as low-score

    except Exception:
        pass

# Print: type|ip|event_type|extra|display
# "display" is empty string for suppressed lines
for ip, event_type, extra, display in scored_events:
    disp = display if display else ''
    # escape pipes in fields
    extra_safe = extra.replace('|', '/') if extra else ''
    disp_safe  = disp.replace('\n', ' ')
    print(f"SCORE_EVENT|{ip}|{event_type}|{extra_safe}|{disp_safe}")

# Aggregate failed logins for display
failed_ips = {}
for ip, event_type, extra, display in scored_events:
    if event_type == 'failed_login':
        failed_ips[ip] = failed_ips.get(ip, 0) + 1

if failed_ips:
    total  = sum(failed_ips.values())
    ip_cnt = len(failed_ips)
    top5   = ', '.join(list(failed_ips.keys())[:5])
    print(f"FAILED_SUMMARY|{total}|{ip_cnt}|{top5}")
PYEOF
PARSE_OUTPUT=$(echo "$NEW_LINES" | python3 "$_PYSC")
rm -f "$_PYSC"

# ── Feed each event into WatchClaw threat DB and check for bans ──────────────
BAN_LINES=()
FAILED_SUMMARY=""

while IFS='|' read -r record_type f1 f2 f3 f4; do
    case "$record_type" in
        SCORE_EVENT)
            ip="$f1"; event_type="$f2"; extra="$f3"
            # Record in threat DB (get new score back)
            new_score=$(watchclaw_record_event "$ip" "$event_type" "$extra" 2>/dev/null || echo 0)
            # Check and apply bans based on updated score
            ban_applied=$(watchclaw_check_and_ban "$ip" 2>/dev/null || echo "none")
            if [ "$ban_applied" != "none" ]; then
                BAN_LINES+=("🚫 Auto-ban ($ban_applied): $ip (score: $new_score)")
            fi
            ;;
        FAILED_SUMMARY)
            total="$f1"; ip_cnt="$f2"; top5="$f3"
            FAILED_SUMMARY="🔒 ${total} login attempts from ${ip_cnt} IPs: ${top5}"
            ;;
    esac
done <<< "$PARSE_OUTPUT"

# ── Update rolling baseline ──────────────────────────────────────────────────
TOTAL_EVENTS=$(echo "$PARSE_OUTPUT" | grep -c '^SCORE_EVENT' || echo 0)
orca_update_baseline "$TOTAL_EVENTS"

# ── Safety net: direct scan for high-priority events ────────────────────────
# Independent of PARSE_OUTPUT — guarantees login.success always alerts
_SAFETY_PY=$(mktemp /tmp/watchclaw-safety-XXXXXX.py)
cat > "$_SAFETY_PY" <<'PYEOF'
import sys, json
lines = []
for raw in sys.stdin:
    raw = raw.strip()
    if not raw: continue
    try:
        e = json.loads(raw)
        t  = e.get('eventid','')
        ip = e.get('src_ip','?')
        if t == 'cowrie.login.success':
            user = e.get('username','?')
            pw   = e.get('password','?')
            lines.append(f"🚨 LOGIN SUCCESS: {ip}  user={user}  pass={pw}")
        elif t == 'cowrie.command.input':
            cmd = e.get('input','?')[:120]
            lines.append(f"💻 CMD: {ip} → {cmd}")
        elif t == 'cowrie.session.file_download':
            lines.append(f"📥 MALWARE DOWNLOAD: {ip} → {e.get('url','?')}")
        elif t == 'cowrie.direct-tcpip.request':
            lines.append(f"🌐 TUNNEL ATTEMPT: {ip} → {e.get('dst_ip','?')}")
    except Exception:
        pass
print('\n'.join(lines))
PYEOF
CRITICAL_ALERTS=$(echo "$NEW_LINES" | python3 "$_SAFETY_PY" 2>/dev/null)
rm -f "$_SAFETY_PY"

# ── Build Telegram message ────────────────────────────────────────────────────
MSG_BODY=""

# Safety net owns all high-priority display (login, cmds, malware, tunnels)
if [ -n "$CRITICAL_ALERTS" ]; then
    MSG_BODY="${MSG_BODY}${CRITICAL_ALERTS}
"
fi

# Failed login summary
if [ -n "$FAILED_SUMMARY" ]; then
    MSG_BODY="${MSG_BODY}${FAILED_SUMMARY}
"
fi

# Score-based auto-bans (not duplicated by safety net)
if [ "${#BAN_LINES[@]}" -gt 0 ]; then
    for line in "${BAN_LINES[@]:0:5}"; do
        MSG_BODY="${MSG_BODY}${line}
"
    done
fi

# Only send if there's something worth reporting
if [ -n "$MSG_BODY" ]; then
    TS_LABEL=$(date '+%H:%M UTC%z')
    send_telegram "🪤 Cowrie Honeypot — ${TS_LABEL}

${MSG_BODY}"
fi

# ── Block repeat honeypot abusers from Cowrie itself ─────────────────────────
# IPs with 5+ successful honeypot logins get dropped on port 22 via iptables
# This stops them generating more score noise
COWRIE_BLOCKED=$(python3 - "${WATCHCLAW_DB:-${HOME:-/root}/.watchclaw/threat-db.json}" <<'PYEOF' 2>/dev/null
import sys, json
db_path = sys.argv[1]
try:
    with open(db_path) as f: db = json.load(f)
except Exception:
    db = {}
for ip, rec in db.items():
    et = rec.get('event_types', {})
    if et.get('login_success', 0) >= 5:
        print(ip)
PYEOF
)

IPTABLES="/usr/sbin/iptables"
COWRIE_BAN_LOG="/var/log/watchclaw/cowrie-port22-bans.log"
for ip in $COWRIE_BLOCKED; do
    # Check if already blocked on port 22 specifically
    if ! $IPTABLES -C INPUT -s "$ip" -p tcp --dport 22 -j DROP 2>/dev/null; then
        $IPTABLES -I INPUT 1 -s "$ip" -p tcp --dport 22 -j DROP 2>/dev/null || true
        echo "[$(date -Iseconds)] COWRIE-BLOCKED: $ip (5+ honeypot logins)" >> "$COWRIE_BAN_LOG"
    fi
done

# ── WatchClaw post-batch: cluster detection + geo anomaly checks ──────────────
watchclaw_post_batch 2>/dev/null || true

# ── Score decay (run periodically; cowrie-notify runs every 15m) ──────────────
# Decay runs at most once per hour to avoid redundant work
DECAY_LOCKFILE="${WATCHCLAW_DIR}/.decay_last_run"
NOW_TS=$(date +%s)
LAST_DECAY=0
[ -f "$DECAY_LOCKFILE" ] && LAST_DECAY=$(cat "$DECAY_LOCKFILE" 2>/dev/null || echo 0)
if [ $(( NOW_TS - LAST_DECAY )) -gt 3600 ]; then
    watchclaw_decay_all 2>/dev/null || true
    echo "$NOW_TS" > "$DECAY_LOCKFILE"
fi
