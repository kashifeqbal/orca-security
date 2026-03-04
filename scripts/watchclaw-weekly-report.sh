#!/bin/bash
# WatchClaw — https://github.com/kashifeqbal/watchclaw
# =============================================================================
# watchclaw-weekly-report.sh — WatchClaw Weekly Threat Summary
# =============================================================================
# Schedule: Sunday 02:00 server local time
# Output: stdout + optional file (WATCHCLAW_REPORT_DIR if set)
#
# Also called via: watchclaw report
# =============================================================================

set -euo pipefail

# Load WatchClaw config
WATCHCLAW_CONF="${WATCHCLAW_CONF:-/etc/watchclaw/watchclaw.conf}"
# shellcheck source=/etc/watchclaw/watchclaw.conf
[ -f "$WATCHCLAW_CONF" ] && source "$WATCHCLAW_CONF"

# Telegram credentials (accept WATCHCLAW_ prefix or ALERT_ prefix from config)
WATCHCLAW_TELEGRAM_TOKEN="${WATCHCLAW_TELEGRAM_TOKEN:-${ALERT_TELEGRAM_TOKEN:-}}"
WATCHCLAW_ALERT_CHAT_ID="${WATCHCLAW_ALERT_CHAT_ID:-${ALERT_TELEGRAM_CHAT:-}}"
# Bridge for watchclaw-lib.sh
OPS_ALERTS_BOT_TOKEN="${WATCHCLAW_TELEGRAM_TOKEN:-}"
ALERTS_TELEGRAM_CHAT="${WATCHCLAW_ALERT_CHAT_ID:-}"

# Source WatchClaw library
LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)/lib"
# shellcheck source=lib/watchclaw-lib.sh
source "${LIB_DIR}/watchclaw-lib.sh"

watchclaw_init

LOG_DIR="/var/log/watchclaw"
mkdir -p "$LOG_DIR"

REPORT_DATE=$(date '+%Y-%m-%d')
REPORT_TS=$(date '+%Y-%m-%d %H:%M %Z')

# Optional report output file (set WATCHCLAW_REPORT_DIR in config)
REPORT_FILE=""
if [ -n "${WATCHCLAW_REPORT_DIR:-}" ]; then
    mkdir -p "$WATCHCLAW_REPORT_DIR"
    REPORT_FILE="${WATCHCLAW_REPORT_DIR}/WatchClaw Weekly Threat Report ${REPORT_DATE}.md"
fi

echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] watchclaw-weekly-report: generating report for $REPORT_DATE" >> "${LOG_DIR}/weekly.log"

# ── Generate report data via Python ──────────────────────────────────────────
REPORT_DATA=$(python3 - "$WATCHCLAW_DB" "$ORCA_ASN_DB" "$ORCA_GEO_DB" "$WATCHCLAW_STATE" "$ORCA_REP_CACHE" <<'PYEOF'
import sys, json, datetime, statistics

db_path, asn_db_path, geo_db_path, state_path, rep_cache_path = sys.argv[1:]

now_dt = datetime.datetime.utcnow()
cutoff_7d  = (now_dt - datetime.timedelta(days=7)).isoformat()  + 'Z'
cutoff_30d = (now_dt - datetime.timedelta(days=30)).isoformat() + 'Z'

def load(path):
    try:
        with open(path) as f: return json.load(f)
    except Exception: return {}

db        = load(db_path)
asn_db    = load(asn_db_path)
geo_db    = load(geo_db_path)
state     = load(state_path)
rep_cache = load(rep_cache_path)

# ── Threat DB stats ──────────────────────────────────────────────────────────
total_ips     = len(db)
active_7d     = [(ip, r) for ip, r in db.items() if r.get('last_seen','') >= cutoff_7d]
active_7d.sort(key=lambda x: x[1].get('score', 0), reverse=True)
active_30d    = [(ip, r) for ip, r in db.items() if r.get('last_seen','') >= cutoff_30d]

banned_perm   = sum(1 for _, r in active_30d if any(b.get('type')=='permanent' and b.get('active') for b in r.get('bans',[])))
banned_temp   = sum(1 for _, r in active_30d if any(b.get('active') and b.get('type') in ('short','long') for b in r.get('bans',[])))
high_rep_risk = sum(1 for _, r in active_30d if r.get('high_reputation_risk'))

total_events_7d = sum(r.get('total_events',0) for _, r in active_7d)

# Severity determination
severity = 'LOW'
for ip, r in active_7d:
    et = r.get('event_types', {})
    s = r.get('score', 0)
    if et.get('malware_download',0) > 0 or et.get('persistence_attempt',0) > 0:
        severity = 'HIGH' if severity not in ('CRITICAL',) else severity
    if s >= 150: severity = 'CRITICAL'
    if et.get('login_success',0) > 0 and severity == 'LOW':
        severity = 'MEDIUM'

# Top offenders table
top_offenders = active_7d[:10]

# ── Ban actions this week ────────────────────────────────────────────────────
bans_this_week = []
for ip, r in active_30d:
    for b in r.get('bans', []):
        at = b.get('at', '')
        if at >= cutoff_7d:
            bans_this_week.append({'ip': ip, 'type': b.get('type','?'), 'at': at,
                                   'reason': b.get('comment','')})
bans_this_week.sort(key=lambda x: x['at'], reverse=True)

# ── ASN clusters ────────────────────────────────────────────────────────────
clusters = [(asn, e) for asn, e in asn_db.items() if e.get('suspicious_cluster')]
clusters.sort(key=lambda x: x[1].get('cluster_score', 0), reverse=True)

all_asns = sorted(asn_db.items(), key=lambda x: x[1].get('rolling_7d_events', 0), reverse=True)
top_asns = all_asns[:10]

# ── Geo summary ──────────────────────────────────────────────────────────────
countries = geo_db.get('countries', {})
top_countries = sorted(countries.items(), key=lambda x: x[1].get('rolling_7d_events',0), reverse=True)[:10]

# ── Baseline ──────────────────────────────────────────────────────────────────
event_counts = state.get('event_counts', [])
if len(event_counts) >= 3:
    recent = [x['count'] for x in event_counts[-48:]]
    baseline_avg = statistics.mean(recent) if recent else 0
else:
    baseline_avg = 0

# ── Recommendations ──────────────────────────────────────────────────────────
recs = []
if clusters:
    for asn, e in clusters[:3]:
        recs.append(f"- Review ASN {asn} for block (`watchclaw ban-asn {asn}`)")
if high_rep_risk > 0:
    recs.append(f"- {high_rep_risk} IPs flagged HIGH reputation risk — consider permanent bans")
if severity in ('HIGH', 'CRITICAL'):
    recs.append("- Investigate high-severity events immediately; check cowrie logs")
if not recs:
    recs.append("- No immediate actions required. Continue routine monitoring.")

# ── Output as JSON ──────────────────────────────────────────────────────────
output = {
    'severity': severity,
    'total_ips': total_ips,
    'active_7d': len(active_7d),
    'active_30d': len(active_30d),
    'total_events_7d': total_events_7d,
    'banned_perm': banned_perm,
    'banned_temp': banned_temp,
    'high_rep_risk': high_rep_risk,
    'baseline_avg': round(baseline_avg, 1),
    'top_offenders': [
        {
            'ip': ip,
            'score': round(r.get('score',0),1),
            'class': r.get('classification','?'),
            'country': r.get('country','?'),
            'asn': r.get('asn','?'),
            'rep': r.get('rep_score',0),
            'events': r.get('total_events',0),
            'banned': any(b.get('active') for b in r.get('bans',[])),
        }
        for ip, r in top_offenders
    ],
    'top_asns': [
        {
            'asn': asn,
            'unique_ips': len(e.get('unique_ips',[])),
            'events_7d': e.get('rolling_7d_events',0),
            'hostile': e.get('hostile_count_7d',0),
            'cluster': e.get('suspicious_cluster',False),
        }
        for asn, e in top_asns
    ],
    'top_countries': [
        {
            'country': c,
            'events_7d': d.get('rolling_7d_events',0),
            'unique_ips': len(d.get('unique_ips',[])),
        }
        for c, d in top_countries
    ],
    'ban_actions': bans_this_week[:15],
    'recommendations': recs,
    'clusters': [{'asn': asn, 'ips_7d': len(e.get('unique_ips_7d', e.get('unique_ips',[]))),
                  'hostile': e.get('hostile_count_7d',0), 'score': e.get('cluster_score',0)}
                 for asn, e in clusters],
}
print(json.dumps(output))
PYEOF
)

# ── Format report as Markdown ─────────────────────────────────────────────────
REPORT_CONTENT=$(python3 - "$REPORT_DATA" "$REPORT_DATE" "$REPORT_TS" <<'PYEOF'
import sys, json

data_str, report_date, report_ts = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.loads(data_str)

severity_emoji = {'LOW': '🟢', 'MEDIUM': '🟡', 'HIGH': '🔴', 'CRITICAL': '🚨'}.get(d['severity'], '⚪')

lines = []
lines.append(f"# WatchClaw Weekly Threat Report — {report_date}")
lines.append(f"*Generated: {report_ts}*")
lines.append("")
lines.append("---")
lines.append("")

# ── Executive Summary ────────────────────────────────────────────────────────
lines.append("## 🛡️ Security Posture")
lines.append("")
lines.append(f"| Metric | Value |")
lines.append(f"|--------|-------|")
lines.append(f"| **SECURITY STATUS** | {severity_emoji} **{d['severity']}** |")
lines.append(f"| Active IPs (7d) | {d['active_7d']} |")
lines.append(f"| Total IPs tracked | {d['total_ips']} |")
lines.append(f"| Total events (7d) | {d['total_events_7d']} |")
lines.append(f"| Permanently banned | {d['banned_perm']} |")
lines.append(f"| Temporarily banned | {d['banned_temp']} |")
lines.append(f"| High reputation risk | {d['high_rep_risk']} |")
lines.append(f"| Baseline avg events/window | {d['baseline_avg']} |")
lines.append("")

# ── Top Offenders ────────────────────────────────────────────────────────────
lines.append("## 🎯 Top Offenders (7d)")
lines.append("")
if d['top_offenders']:
    lines.append("| IP | Score | Class | Country | ASN | Rep | Events | Banned |")
    lines.append("|-----|-------|-------|---------|-----|-----|--------|--------|")
    for o in d['top_offenders']:
        banned = "✅ YES" if o['banned'] else "—"
        lines.append(f"| `{o['ip']}` | {o['score']} | {o['class']} | {o['country']} | {o['asn']} | {o['rep']} | {o['events']} | {banned} |")
else:
    lines.append("*No active offenders this week.*")
lines.append("")

# ── ASN Table ────────────────────────────────────────────────────────────────
lines.append("## 🌐 Top ASNs (7d)")
lines.append("")
if d['top_asns']:
    lines.append("| ASN | Unique IPs | Events (7d) | Hostile | Cluster? |")
    lines.append("|-----|-----------|-------------|---------|----------|")
    for a in d['top_asns']:
        cluster = "⚠️ YES" if a['cluster'] else "—"
        lines.append(f"| {a['asn']} | {a['unique_ips']} | {a['events_7d']} | {a['hostile']} | {cluster} |")
else:
    lines.append("*No ASN data available.*")
lines.append("")

# ── Geo Summary ──────────────────────────────────────────────────────────────
lines.append("## 🗺️ Geo Distribution (7d)")
lines.append("")
if d['top_countries']:
    lines.append("| Country | Events (7d) | Unique IPs |")
    lines.append("|---------|------------|-----------|")
    for c in d['top_countries']:
        lines.append(f"| {c['country']} | {c['events_7d']} | {c['unique_ips']} |")
else:
    lines.append("*No geo data available.*")
lines.append("")

# ── Suspicious Clusters ───────────────────────────────────────────────────────
if d['clusters']:
    lines.append("## ⚠️ Suspicious ASN Clusters")
    lines.append("")
    lines.append("| ASN | Unique IPs (7d) | Hostile Offenders | Cluster Score |")
    lines.append("|-----|-----------------|-------------------|---------------|")
    for c in d['clusters']:
        lines.append(f"| {c['asn']} | {c['ips_7d']} | {c['hostile']} | {c['score']} |")
    lines.append("")

# ── Escalations / Actions ────────────────────────────────────────────────────
lines.append("## ⚡ Escalations & Actions (7d)")
lines.append("")
if d['ban_actions']:
    lines.append("| IP | Ban Type | Applied At | Reason |")
    lines.append("|-----|---------|-----------|--------|")
    for b in d['ban_actions']:
        reason = b.get('reason', '')[:40]
        lines.append(f"| `{b['ip']}` | {b['type']} | {b['at'][:19]} | {reason} |")
else:
    lines.append("*No ban actions this week.*")
lines.append("")

# ── Recommendations ───────────────────────────────────────────────────────────
lines.append("## 📋 Recommendations")
lines.append("")
for r in d['recommendations']:
    lines.append(r)
lines.append("")

# ── Footer ───────────────────────────────────────────────────────────────────
lines.append("---")
lines.append("")
lines.append("*Report generated by WatchClaw. State: `~/.watchclaw/`*")
lines.append(f"*Manual commands: `watchclaw status` | `watchclaw report`*")

print('\n'.join(lines))
PYEOF
)

# Print to stdout
echo "$REPORT_CONTENT"

# Write to file if configured
if [ -n "$REPORT_FILE" ]; then
    echo "$REPORT_CONTENT" > "$REPORT_FILE"
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] watchclaw-weekly-report: written to $REPORT_FILE" >> "${LOG_DIR}/weekly.log"
fi

echo "{\"status\":\"ok\",\"date\":\"$REPORT_DATE\"}"
