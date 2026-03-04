#!/bin/bash
# =============================================================================
# security-posture.sh — Argus Security Posture Reporter
# =============================================================================
# Outputs a combined system health + security posture summary.
# Intended to be run by cron or manually. Notifies Telegram for ELEVATED+.
#
# Output format:
#   SYSTEM HEALTH: OK/DEGRADED
#   SECURITY STATUS: LOW/ELEVATED/HIGH/CRITICAL
#   Active Threat Score (rolling 30m): <N>
#   Top Offender: <IP> (score: N, class: X)
#   Repeat Offenders: <list>
#   Ban Actions Taken: <list>
#   Recommended Action: <text>
# =============================================================================

set -euo pipefail

# ── Load environment ──────────────────────────────────────────────────────────
ENV_FILE="/root/.openclaw/.env"
[ -f "$ENV_FILE" ] && set -a && source "$ENV_FILE" && set +a

# ── Config ────────────────────────────────────────────────────────────────────
BOT="${OPS_ALERTS_BOT_TOKEN:-}"
CHAT_ID="${ALERTS_TELEGRAM_CHAT:-}"
LOG_DIR="/root/.openclaw/workspace/agents/ops/logs"
POSTURE_LOG="${LOG_DIR}/security-posture.log"
HEALTH_LOG="${LOG_DIR}/service-health.log"

# Source WatchClaw library (threat-db.sh is now a compat shim → watchclaw-lib.sh)
LIB_DIR="$(dirname "$0")/lib"
# shellcheck source=scripts/lib/threat-db.sh
source "${LIB_DIR}/threat-db.sh"

mkdir -p "$LOG_DIR"
TS=$(date '+%Y-%m-%d %H:%M:%S')

# ── Helper: send Telegram message ────────────────────────────────────────────
send_telegram() {
    [ -z "$BOT" ] && return 0
    curl -s --max-time 15 -X POST \
        "https://api.telegram.org/bot${BOT}/sendMessage" \
        -d "chat_id=${CHAT_ID}" \
        --data-urlencode "text=$1" > /dev/null
}

log_posture() { echo "[$TS] $1" >> "$POSTURE_LOG"; }

# =============================================================================
# 1. SYSTEM HEALTH — check key services (read-only, no restarts)
# =============================================================================
HEALTH_STATUS="OK"
HEALTH_ISSUES=()

check_svc_status() {
    local svc="$1"
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        HEALTH_ISSUES+=("$svc: DOWN")
        HEALTH_STATUS="DEGRADED"
    fi
}

check_svc_status "fail2ban"
check_svc_status "cowrie"
check_svc_status "cloudflared"
check_svc_status "syncthing@syncthing"

# Check Hindsight
if ! curl -sf http://127.0.0.1:8787/health > /dev/null 2>&1; then
    HEALTH_ISSUES+=("hindsight: unreachable")
    HEALTH_STATUS="DEGRADED"
fi

# Check disk
DISK_PCT=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
if [ "${DISK_PCT:-0}" -gt 85 ]; then
    HEALTH_ISSUES+=("disk: ${DISK_PCT}% used")
    HEALTH_STATUS="DEGRADED"
fi

# Script warning detection (non-empty stderr OR known parser warnings)
SCRIPT_WARNINGS=()
for script in "$(dirname "$0")"/*.sh "$(dirname "$0")"/lib/*.sh; do
    [ -f "$script" ] || continue
    CHECK_ERR=$(bash -n "$script" 2>&1 || true)
    if [ -n "$CHECK_ERR" ]; then
        HEALTH_STATUS="DEGRADED"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            if echo "$line" | grep -Eqi "unterminated|syntax error|unexpected token"; then
                SCRIPT_WARNINGS+=("$(basename "$script"): $line")
            else
                SCRIPT_WARNINGS+=("$(basename "$script"): $line")
            fi
        done <<< "$CHECK_ERR"
    fi
done
if [ "${#SCRIPT_WARNINGS[@]}" -gt 0 ]; then
    HEALTH_ISSUES+=("script warnings detected")
fi

# =============================================================================
# 2. THREAT DATA — read WatchClaw threat DB and compute posture
# =============================================================================
watchclaw_init

# Rolling 30m threat score
ROLLING_SCORE=$(threat_rolling_score 30)

# Parse full DB for analytics
POSTURE_DATA=$(python3 - "$ARGUS_DB" "$ARGUS_BASELINE" <<'PYEOF'
import sys, json, datetime, statistics

db_path       = sys.argv[1]
baseline_path = sys.argv[2]

now_dt    = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
cutoff_30 = (now_dt - datetime.timedelta(minutes=30)).isoformat() + 'Z'

try:
    with open(db_path) as f:
        db = json.load(f)
except Exception:
    db = {}

# -- Collect stats --
top_life_ip      = None
top_life_score   = 0.0
top_30m_ip       = None
top_30m_score    = 0.0
repeat_offenders = []
recent_events    = 0
ban_actions      = []

# Determine baseline anomaly
try:
    with open(baseline_path) as f:
        b = json.load(f)
    counts = [x['count'] for x in b.get('event_counts', [])]
except Exception:
    counts = []

baseline_avg = statistics.mean(counts) if len(counts) >= 3 else 0
cutoff_30_dt = now_dt - datetime.timedelta(minutes=30)

for ip, rec in db.items():
    score      = float(rec.get('score', 0) or 0)
    last_seen  = rec.get('last_seen', '')
    windows    = rec.get('windows', [])
    bans       = rec.get('bans', [])
    cls        = rec.get('classification', 'unknown')

    if last_seen >= cutoff_30:
        recent_events += rec.get('total_events', 0)

    if score > top_life_score:
        top_life_score = score
        top_life_ip    = ip

    # 30m contribution score from score_events
    score_30m = 0.0
    for ev in rec.get('score_events', []):
        ts = ev.get('ts', '')
        try:
            ev_dt = datetime.datetime.fromisoformat(ts.rstrip('Z'))
        except Exception:
            continue
        if ev_dt >= cutoff_30_dt:
            score_30m += float(ev.get('delta', 0) or 0)

    if score_30m > top_30m_score:
        top_30m_score = score_30m
        top_30m_ip = ip

    if len(windows) >= 3:
        repeat_offenders.append(f"{ip} ({cls}, lifetime:{score:.1f})")

    for ban in bans:
        if ban.get('active', False) and ban.get('at', '') >= cutoff_30:
            ban_actions.append(f"{ip} → {ban['type']}")

# Format outputs (pipe-delimited for easy shell parsing)
top_30m_str  = f"{top_30m_ip} ({top_30m_score:.1f} in 30m)" if top_30m_ip else "none"
top_life_str = f"{top_life_ip} ({top_life_score:.1f} lifetime)" if top_life_ip else "none"
rep_str      = ", ".join(repeat_offenders[:5]) if repeat_offenders else "none"
bans_str     = ", ".join(ban_actions[:5]) if ban_actions else "none"

print(f"TOP_30M={top_30m_str}")
print(f"TOP_LIFETIME={top_life_str}")
print(f"REPEAT={rep_str}")
print(f"BANS={bans_str}")
print(f"BANS_COUNT_30M={len(ban_actions)}")
print(f"RECENT_EVENTS={recent_events}")
print(f"BASELINE_AVG={baseline_avg:.1f}")
PYEOF
)

# Parse Python output into shell vars
TOP_30M=$(echo "$POSTURE_DATA"       | grep '^TOP_30M='      | cut -d= -f2-)
TOP_LIFETIME=$(echo "$POSTURE_DATA"  | grep '^TOP_LIFETIME=' | cut -d= -f2-)
REPEAT=$(echo "$POSTURE_DATA"        | grep '^REPEAT='       | cut -d= -f2-)
BANS=$(echo "$POSTURE_DATA"          | grep '^BANS='         | cut -d= -f2-)
BANS_COUNT_30M=$(echo "$POSTURE_DATA"| grep '^BANS_COUNT_30M=' | cut -d= -f2-)
RECENT_EVENTS=$(echo "$POSTURE_DATA" | grep '^RECENT_EVENTS=' | cut -d= -f2-)
BASELINE_AVG=$(echo "$POSTURE_DATA"  | grep '^BASELINE_AVG='  | cut -d= -f2-)

# Security posture recalibration (rolling score thresholds + hard-signal guard)
ROLLING_SCORE_INT=$(printf '%.0f' "${ROLLING_SCORE:-0}")
HARD_SIGNAL_ACTIVE=$(python3 - "$ARGUS_DB" <<'PYEOF' 2>/dev/null || echo "0"
import sys, json, datetime
p = sys.argv[1]
try:
    db = json.load(open(p))
except Exception:
    print('0'); raise SystemExit
cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
for rec in db.values():
    et = rec.get('event_types', {}) or {}
    if et.get('malware_download', 0) > 0 or et.get('persistence_attempt', 0) > 0 or et.get('tunnel_tcpip', 0) > 0:
        print('1'); raise SystemExit
    # command_exec is medium-hard: only count if high volume
    if et.get('command_exec', 0) >= 10:
        print('1'); raise SystemExit
print('0')
PYEOF
)

if [ "$ROLLING_SCORE_INT" -lt 100 ]; then
    SEVERITY="LOW"
elif [ "$ROLLING_SCORE_INT" -le 300 ]; then
    SEVERITY="ELEVATED"
elif [ "$ROLLING_SCORE_INT" -le 600 ]; then
    SEVERITY="HIGH"
else
    # Require stronger signal for CRITICAL; pure recon storms stay HIGH
    if [ "$HARD_SIGNAL_ACTIVE" = "1" ]; then
        SEVERITY="CRITICAL"
    else
        SEVERITY="HIGH"
    fi
fi

# =============================================================================
# 3. Verify ban effectiveness — escalate if any bans are broken
# =============================================================================
INEFFECTIVE_BANS=$(threat_verify_bans)
if [ -n "$INEFFECTIVE_BANS" ]; then
    HEALTH_ISSUES+=("Ineffective bans detected: $INEFFECTIVE_BANS")
    HEALTH_STATUS="DEGRADED"
    # Re-apply any missing UFW rules
    while IFS='|' read -r bip btype breason; do
        if [ -n "$bip" ]; then
            log_posture "WARN: Ineffective ban for $bip ($btype): $breason — re-applying"
            /usr/sbin/ufw deny from "$bip" to any comment "argus-reapplied" 2>/dev/null || true
        fi
    done <<< "$INEFFECTIVE_BANS"
fi

# =============================================================================
# 4. Determine recommended action
# =============================================================================
case "$SEVERITY" in
    LOW)
        RISK_LABEL="Normal background noise"
        ACTION_NOW="No action needed"
        RECOMMENDED="No immediate action required. Continue monitoring."
        ;;
    ELEVATED)
        RISK_LABEL="More attacks than usual"
        ACTION_NOW="Verify auto-bans are active"
        RECOMMENDED="Top attackers are auto-banned. Verify blocks are active and keep monitoring."
        ;;
    HIGH)
        RISK_LABEL="Sustained hostile activity"
        ACTION_NOW="Investigate now"
        RECOMMENDED="Immediate analyst review: validate containment and cluster activity."
        ;;
    CRITICAL)
        RISK_LABEL="Potential active security incident"
        ACTION_NOW="Immediate response"
        RECOMMENDED="IMMEDIATE RESPONSE REQUIRED — containment + operator escalation now."
        ;;
    *)
        RISK_LABEL="Unknown"
        ACTION_NOW="Manual review"
        RECOMMENDED="Unknown severity — review posture log."
        ;;
esac

# =============================================================================
# 5. Build output
# =============================================================================
REPORT="SYSTEM HEALTH: ${HEALTH_STATUS}
SECURITY STATUS: ${SEVERITY}
Risk Meaning: ${RISK_LABEL}
Action Right Now: ${ACTION_NOW}

Active Threat Score (last 30m): ${ROLLING_SCORE}
Top Offender (last 30m): ${TOP_30M}
Highest Lifetime Offender: ${TOP_LIFETIME}
Repeat Offenders: ${REPEAT}

Ban Actions (last 30m): ${BANS_COUNT_30M}
Recent Ban Details: ${BANS}

Recommended Action: ${RECOMMENDED}"

# Add health details if degraded
if [ "$HEALTH_STATUS" = "DEGRADED" ] && [ "${#HEALTH_ISSUES[@]}" -gt 0 ]; then
    REPORT="${REPORT}
Health Issues: $(IFS=', '; echo "${HEALTH_ISSUES[*]}")"
fi
if [ "${#SCRIPT_WARNINGS[@]}" -gt 0 ]; then
    WARN_BLOCK=$(printf '%s\n' "${SCRIPT_WARNINGS[@]}" | head -n 8)
    REPORT="${REPORT}
Script Warnings:
${WARN_BLOCK}"
fi

# Print to stdout always
echo "$REPORT"

# Log to file
log_posture "health=${HEALTH_STATUS} severity=${SEVERITY} rolling_score=${ROLLING_SCORE} events_30m=${RECENT_EVENTS} baseline=${BASELINE_AVG}"

# =============================================================================
# 6. Alert severity gating
# =============================================================================
# LOW → aggregate, do NOT send Telegram (suppress)
# ELEVATED+ → send Telegram

if [ "$SEVERITY" = "LOW" ]; then
    # Aggregate LOW — update counter but don't notify
    python3 - "$ARGUS_ALERTS_STATE" "$ROLLING_SCORE" <<'PYEOF'
import sys, json, os, datetime
state_path  = sys.argv[1]
score       = sys.argv[2]
now_iso     = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + 'Z'
try:
    with open(state_path) as f:
        s = json.load(f)
except Exception:
    s = {}
s['last_info_at'] = now_iso
s['info_count']   = s.get('info_count', 0) + 1
tmp = state_path + '.tmp'
with open(tmp, 'w') as f:
    json.dump(s, f)
os.replace(tmp, state_path)
PYEOF
    log_posture "SUPPRESS: severity=${SEVERITY} — no Telegram notification"
    exit 0
fi

# ── WatchClaw enrichment: ASN clusters + geo anomalies + rep risks ─────────────────
WATCHCLAW_ENRICH=$(python3 - "$ORCA_ASN_DB" "$ORCA_GEO_DB" "$ORCA_REP_CACHE" "$WATCHCLAW_DB" <<'PYEOF' 2>/dev/null || echo ""
import sys, json, datetime

asn_db_path, geo_db_path, rep_cache_path, db_path = sys.argv[1:]

try:
    with open(asn_db_path) as f: asn_db = json.load(f)
except Exception: asn_db = {}
try:
    with open(geo_db_path) as f: geo_db = json.load(f)
except Exception: geo_db = {}
try:
    with open(rep_cache_path) as f: rep_cache = json.load(f)
except Exception: rep_cache = {}
try:
    with open(db_path) as f: db = json.load(f)
except Exception: db = {}

now_dt = datetime.datetime.utcnow()
cutoff_7d = (now_dt - datetime.timedelta(days=7)).isoformat() + 'Z'

# Suspicious clusters
clusters = [(asn, e) for asn, e in asn_db.items() if e.get('suspicious_cluster')]
cluster_str = ', '.join(f"{asn}({e.get('hostile_count_7d',0)} hostile)" for asn, e in clusters[:3]) if clusters else "none"

# Top countries (7d)
countries = geo_db.get('countries', {})
top_c = sorted(countries.items(), key=lambda x: x[1].get('rolling_7d_events', 0), reverse=True)[:3]
country_names = {
    'US': 'United States', 'CN': 'China', 'RU': 'Russia', 'DE': 'Germany', 'FR': 'France',
    'GB': 'United Kingdom', 'IN': 'India', 'BR': 'Brazil', 'MX': 'Mexico', 'AU': 'Australia',
    'CA': 'Canada', 'JP': 'Japan', 'KR': 'South Korea', 'NL': 'Netherlands', 'SG': 'Singapore',
    'HK': 'Hong Kong', 'UA': 'Ukraine', 'PL': 'Poland', 'IT': 'Italy', 'ES': 'Spain',
    'TR': 'Turkey', 'IR': 'Iran', 'ID': 'Indonesia', 'VN': 'Vietnam', 'TH': 'Thailand',
    'RO': 'Romania', 'BG': 'Bulgaria', 'SE': 'Sweden', 'NO': 'Norway', 'FI': 'Finland',
}
def cname(code):
    code = (code or '').upper()
    return country_names.get(code, code or 'Unknown')
geo_str = ', '.join(f"{cname(c)}: {d.get('rolling_7d_events',0)}" for c, d in top_c) if top_c else "none"

# High rep risk IPs active in 24h
cutoff_24h = (now_dt - datetime.timedelta(hours=24)).isoformat() + 'Z'
rep_risks = [ip for ip, r in db.items()
             if r.get('high_reputation_risk') and r.get('last_seen','') >= cutoff_24h]
rep_str = ', '.join(rep_risks[:3]) if rep_risks else "none"

print(f"CLUSTERS={cluster_str}")
print(f"GEO_TOP={geo_str}")
print(f"REP_RISKS={rep_str}")
print(f"CLUSTER_COUNT={len(clusters)}")
PYEOF
)

WATCHCLAW_CLUSTERS=$(echo "$WATCHCLAW_ENRICH"   | grep '^CLUSTERS=' | cut -d= -f2-)
WATCHCLAW_GEO_TOP=$(echo "$WATCHCLAW_ENRICH"    | grep '^GEO_TOP='  | cut -d= -f2-)
WATCHCLAW_REP_RISKS=$(echo "$WATCHCLAW_ENRICH"  | grep '^REP_RISKS=' | cut -d= -f2-)
WATCHCLAW_CLUSTER_CNT=$(echo "$WATCHCLAW_ENRICH"| grep '^CLUSTER_COUNT=' | cut -d= -f2-)

# Elevate to HIGH if suspicious clusters found
if [ "${WATCHCLAW_CLUSTER_CNT:-0}" -gt 0 ] && [ "$SEVERITY" = "LOW" ]; then
    SEVERITY="ELEVATED"
fi

# ELEVATED, HIGH, CRITICAL → send to Telegram (with rate-limiting via WatchClaw)
EMOJI="⚠️"
[ "$SEVERITY" = "ELEVATED" ] && EMOJI="🟠"
[ "$SEVERITY" = "HIGH" ]     && EMOJI="🔴"
[ "$SEVERITY" = "CRITICAL" ] && EMOJI="🚨"

TELE_MSG="${EMOJI} *WatchClaw Security Report — $(date '+%Y-%m-%d %H:%M')*

${REPORT}

Simple Summary:
- Is system healthy? ${HEALTH_STATUS}
- Is security risky? ${SEVERITY} (${RISK_LABEL})
- Do I need to act now? ${ACTION_NOW}

Intel:
- ASN Clusters: ${WATCHCLAW_CLUSTERS:-none}
- Top Countries (7d): ${WATCHCLAW_GEO_TOP:-none}
- Reputation Risks: ${WATCHCLAW_REP_RISKS:-none}"

# Use WatchClaw rate-limited Telegram function
watchclaw_telegram "$SEVERITY" "$TELE_MSG" 2>/dev/null || send_telegram "$TELE_MSG"
log_posture "ALERTED: severity=${SEVERITY} clusters=${WATCHCLAW_CLUSTERS:-none} geo=${WATCHCLAW_GEO_TOP:-none}"

# ── CRITICAL: auto-create GitHub issue (rate limited via WatchClaw state) ───────────
if [ "$SEVERITY" = "CRITICAL" ]; then
    ISSUE_SCRIPT="$(dirname "$0")/watchclaw-critical-issue.sh"
    if [ -x "$ISSUE_SCRIPT" ]; then
        "$ISSUE_SCRIPT" 2>/dev/null || true
        log_posture "CRITICAL: github issue attempted"
    fi
fi
