#!/bin/bash
# =============================================================================
# orca-critical-issue.sh — ORCA GitHub Critical Issue Generator
# =============================================================================
# Creates a GitHub issue when SECURITY STATUS is CRITICAL.
# Rate limit: 1 issue per 6 hours (persisted in ~/.orca/orca-state.json).
# Also called via: orca issue critical --run-now [--force]
# =============================================================================

set -euo pipefail

ENV_FILE="/root/.openclaw/.env"
[ -f "$ENV_FILE" ] && set -a && source "$ENV_FILE" && set +a

# Source ORCA library
LIB_DIR="$(dirname "$0")/lib"
# shellcheck source=lib/orca-lib.sh
source "${LIB_DIR}/orca-lib.sh"

orca_init

FORCE=false
for arg in "$@"; do
    [ "$arg" = "--force" ] && FORCE=true
done

GITHUB_REPO="${ORCA_GITHUB_REPO:-tap-health/infrastructure-security}"
ISSUE_RATE_HRS="${ORCA_ISSUE_RATE_HRS:-6}"
LOG_DIR="/root/.openclaw/workspace/agents/ops/logs"
mkdir -p "$LOG_DIR"
LOG="${LOG_DIR}/orca-weekly.log"

NOW_ISO=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# ── Check security status ─────────────────────────────────────────────────────
STATUS_JSON=$(orca_status_json)
SEVERITY=$(echo "$STATUS_JSON" | jq -r '.security_status // "LOW"')

if [ "$SEVERITY" != "CRITICAL" ] && [ "$FORCE" = "false" ]; then
    echo "{\"status\":\"skipped\",\"reason\":\"security_status is $SEVERITY, not CRITICAL. Use --force to override.\"}"
    exit 0
fi

# ── Rate limit check ─────────────────────────────────────────────────────────
RATE_OK=$(python3 - "$ORCA_STATE" "$ISSUE_RATE_HRS" <<'PYEOF'
import sys, json, datetime
state_path, rate_hrs_s = sys.argv[1], sys.argv[2]
rate_secs = int(rate_hrs_s) * 3600
now_dt = datetime.datetime.utcnow()
try:
    with open(state_path) as f: s = json.load(f)
except Exception: s = {}
last_issue = s.get('last_issue_at', '')
if last_issue:
    try:
        last_dt = datetime.datetime.fromisoformat(last_issue.rstrip('Z'))
        if (now_dt - last_dt).total_seconds() < rate_secs:
            print('rate_limited')
            sys.exit(0)
    except: pass
print('ok')
PYEOF
)

if [ "$RATE_OK" = "rate_limited" ] && [ "$FORCE" = "false" ]; then
    LAST=$(jq -r '.last_issue_at // "unknown"' "$ORCA_STATE" 2>/dev/null || echo "unknown")
    echo "{\"status\":\"skipped\",\"reason\":\"rate_limited\",\"last_issue_at\":\"$LAST\"}"
    exit 0
fi

# ── Build issue content ───────────────────────────────────────────────────────
ISSUE_DATA=$(python3 - "$STATUS_JSON" "$NOW_ISO" <<'PYEOF'
import sys, json, datetime

status_str, now_iso = sys.argv[1], sys.argv[2]
try:
    d = json.loads(status_str)
except Exception:
    d = {}

severity = d.get('security_status', 'CRITICAL')
db = d.get('threat_db', {})
top = d.get('top_offenders', [])
clusters = d.get('suspicious_asn_clusters', [])
countries = d.get('top_countries_7d', [])
rep_risk = d.get('high_reputation_risk_ips', [])

# Title
title = f"[ORCA CRITICAL] Security Alert — {now_iso[:10]}"

# Body (Markdown)
body_lines = []
body_lines.append(f"## 🚨 ORCA SECURITY ALERT — CRITICAL STATUS")
body_lines.append(f"")
body_lines.append(f"**Timestamp (UTC):** {now_iso}")
body_lines.append(f"**Security Status:** 🚨 {severity}")
body_lines.append(f"")
body_lines.append(f"### Summary")
body_lines.append(f"")
body_lines.append(f"| Metric | Value |")
body_lines.append(f"|--------|-------|")
body_lines.append(f"| Active IPs (7d) | {db.get('active_7d', '?')} |")
body_lines.append(f"| Active IPs (24h) | {db.get('active_24h', '?')} |")
body_lines.append(f"| Rolling threat score (30m) | {db.get('rolling_score_30m', '?')} |")
body_lines.append(f"| Banned IPs | {db.get('banned', '?')} |")
body_lines.append(f"| High reputation risk | {db.get('high_reputation_risk', '?')} |")
body_lines.append(f"")

# Top IPs
if top:
    body_lines.append(f"### Top Threat IPs")
    body_lines.append(f"")
    body_lines.append(f"| IP | Score | Class | Country | ASN | Rep Score |")
    body_lines.append(f"|-----|-------|-------|---------|-----|-----------|")
    for o in top[:5]:
        body_lines.append(f"| `{o['ip']}` | {o['score']} | {o['classification']} | {o['country']} | {o['asn']} | {o['rep_score']} |")
    body_lines.append(f"")

# Suspicious clusters
if clusters:
    body_lines.append(f"### Suspicious ASN Clusters")
    body_lines.append(f"")
    for c in clusters[:3]:
        body_lines.append(f"- **{c['asn']}**: {c.get('unique_ips_7d','?')} IPs, {c.get('hostile_count','?')} hostile — `orca enforce ban-asn {c['asn']} --mode ufw`")
    body_lines.append(f"")

# Geo
if countries:
    top_c = ', '.join(f"{c['country']} ({c['events_7d']})" for c in countries[:5])
    body_lines.append(f"### Top Countries (7d)")
    body_lines.append(f"")
    body_lines.append(f"{top_c}")
    body_lines.append(f"")

# Actions taken
body_lines.append(f"### Actions Taken")
body_lines.append(f"")
body_lines.append(f"- ORCA auto-ban enforcement active (UFW + fail2ban)")
body_lines.append(f"- Score-based escalation applied")
body_lines.append(f"- Telegram alerts sent to ops group")
body_lines.append(f"")

# Recommendations
body_lines.append(f"### Recommendations")
body_lines.append(f"")
body_lines.append(f"- [ ] Review top offenders and verify bans: `orca top --window 24h`")
body_lines.append(f"- [ ] Verify all ban rules are active: `orca status`")
if clusters:
    for c in clusters[:2]:
        body_lines.append(f"- [ ] Approve ASN block for {c['asn']}: `orca enforce ban-asn {c['asn']} --mode ufw`")
body_lines.append(f"- [ ] Review cowrie logs for novel attack patterns")
body_lines.append(f"- [ ] Check geo anomalies in ORCA weekly report")
body_lines.append(f"")
body_lines.append(f"---")
body_lines.append(f"*Auto-generated by ORCA Security System on {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*")

result = {
    'title': title,
    'body': '\n'.join(body_lines),
    'labels': ['security', 'critical', 'orca'],
}
print(json.dumps(result))
PYEOF
)

ISSUE_TITLE=$(echo "$ISSUE_DATA" | jq -r '.title')
ISSUE_BODY=$(echo "$ISSUE_DATA" | jq -r '.body')

# ── Create GitHub issue ───────────────────────────────────────────────────────
GH_RESULT=""
GH_URL=""

if command -v gh >/dev/null 2>&1; then
    # Check if gh is authenticated
    if gh auth status >/dev/null 2>&1; then
        GH_RESULT=$(echo "$ISSUE_BODY" | gh issue create \
            --repo "$GITHUB_REPO" \
            --title "$ISSUE_TITLE" \
            --label "security" \
            --label "critical" \
            --body-file - 2>&1 || echo "FAILED")
        GH_URL=$(echo "$GH_RESULT" | grep -oE 'https://github.com/[^ ]+' | head -1 || echo "")
    else
        GH_RESULT="gh_not_authenticated"
    fi
else
    GH_RESULT="gh_not_installed"
fi

# ── Update last_issue_at in state ────────────────────────────────────────────
python3 - "$ORCA_STATE" "$NOW_ISO" "$GH_URL" <<'PYEOF' 2>/dev/null || true
import sys, json, os
state_path, now_iso, gh_url = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(state_path) as f: s = json.load(f)
except Exception: s = {}
s['last_issue_at'] = now_iso
issues = s.get('github_issues', [])
issues.append({'at': now_iso, 'url': gh_url})
issues = issues[-50:]  # cap
s['github_issues'] = issues
tmp = state_path + '.tmp'
with open(tmp, 'w') as f: json.dump(s, f, indent=2)
os.replace(tmp, state_path)
PYEOF

# ── Telegram alert about issue ────────────────────────────────────────────────
if [ -n "$GH_URL" ]; then
    MSG="🚨 ORCA CRITICAL ALERT

GitHub issue created: $GH_URL
Severity: $SEVERITY
Time: $NOW_ISO

Run \`orca status\` for full details."
    orca_telegram "CRITICAL" "$MSG" 2>/dev/null || true
fi

echo "{\"status\":\"ok\",\"title\":\"$ISSUE_TITLE\",\"github_url\":\"$GH_URL\",\"gh_result\":\"$GH_RESULT\",\"severity\":\"$SEVERITY\"}"
echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] orca-critical-issue: issued title='$ISSUE_TITLE' url='$GH_URL'" >> "$LOG"
