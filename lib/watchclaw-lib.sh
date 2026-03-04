#!/bin/bash
# =============================================================================
# lib/watchclaw-lib.sh — WatchClaw Threat Intelligence Library v2.0
# =============================================================================
# WatchClaw owns: threat state, scoring, enrichment, enforcement, reporting, alerts.
# State lives exclusively under ~/.watchclaw/
#
# Exported functions:
#   watchclaw_init                       — init dirs, migrate from argus
#   watchclaw_record_event ip type extra — record + enrich + score, returns score
#   watchclaw_check_and_ban ip           — apply bans based on score, returns ban type
#   orca_verify_bans                — check ban effectiveness, print ip|type|reason
#   watchclaw_post_batch                 — cluster + geo anomaly checks (call after batch)
#   watchclaw_decay_all                  — apply 10%/24h score decay to all IPs
#   orca_prune_db                   — remove IPs unseen > 45 days
#   orca_rolling_score [minutes]    — total score for recent activity
#   orca_update_baseline count      — update event baseline
#   orca_check_alert_rate severity  — "ok" or "rate_limited"
#   orca_telegram severity message  — send Telegram with rate-limit guard
#   orca_status_json                — JSON status for `watchclaw status`
#   orca_top_json window            — JSON for `watchclaw top`
#   orca_get_score ip               — numeric score
#   orca_dump_db                    — print full threat-db
# =============================================================================

# ── State paths ───────────────────────────────────────────────────────────────
WATCHCLAW_DIR="${WATCHCLAW_DIR:-${HOME:-/root}/.watchclaw}"
WATCHCLAW_DB="${WATCHCLAW_DIR}/threat-db.json"
ORCA_REP_CACHE="${WATCHCLAW_DIR}/reputation-cache.json"
ORCA_ASN_DB="${WATCHCLAW_DIR}/asn-db.json"
ORCA_GEO_DB="${WATCHCLAW_DIR}/geo-db.json"
WATCHCLAW_STATE="${WATCHCLAW_DIR}/watchclaw-state.json"
WATCHCLAW_LOG="${WATCHCLAW_DIR}/watchclaw.log"

# ── Tuning ────────────────────────────────────────────────────────────────────
ORCA_CLUSTER_MIN_IPS=5
ORCA_CLUSTER_MIN_HOSTILE=3
ORCA_GEO_NEW_COUNTRY_DAYS=30
ORCA_GEO_SPIKE_FACTOR=3
ORCA_GEO_MIN_DAILY=50
ORCA_ALERT_RATE_MINS=15
ORCA_DECAY_RATE="0.10"
ORCA_PRUNE_DAYS=45
ORCA_GITHUB_REPO="${ORCA_GITHUB_REPO:-tap-health/infrastructure-security}"
ORCA_ISSUE_RATE_HRS=6
ORCA_REP_TTL_SECS=86400          # 24h reputation cache
ORCA_ENRICH_TTL_SECS=86400       # 24h ASN/geo re-resolve

# Telegram
ORCA_BOT="${OPS_ALERTS_BOT_TOKEN:-}"
ORCA_CHAT="${ALERTS_TELEGRAM_CHAT:--5206059645}"

# ── Helpers ───────────────────────────────────────────────────────────────────
_orca_log() {
    local ts; ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    echo "[$ts] $*" >> "$WATCHCLAW_LOG" 2>/dev/null || true
}

_atomic_write() {
    local path="$1" content="$2"
    local tmp="${path}.tmp.$$"
    printf '%s' "$content" > "$tmp" && mv -f "$tmp" "$path"
}

_jq_atomic_update() {
    # Usage: _jq_atomic_update path jq_filter [args...]
    local path="$1"; shift
    local tmp="${path}.tmp.$$"
    jq "$@" "$path" > "$tmp" && mv -f "$tmp" "$path"
}

# =============================================================================
# watchclaw_init — ensure dirs and files exist, migrate from argus if needed
# =============================================================================
watchclaw_init() {
    mkdir -p "$WATCHCLAW_DIR"
    [ -f "$WATCHCLAW_DB" ]         || echo '{}' > "$WATCHCLAW_DB"
    [ -f "$ORCA_REP_CACHE" ]  || echo '{}' > "$ORCA_REP_CACHE"
    [ -f "$ORCA_ASN_DB" ]     || echo '{}' > "$ORCA_ASN_DB"
    [ -f "$ORCA_GEO_DB" ]     || echo '{"countries":{},"history":[]}' > "$ORCA_GEO_DB"
    [ -f "$WATCHCLAW_STATE" ]      || echo '{"alert_rates":{},"last_issue_at":"","info_count":0,"event_counts":[],"last_baseline_updated":""}' > "$WATCHCLAW_STATE"

    # One-time migration from argus
    local argus_db="${HOME:-/root}/.argus/threat-db.json"
    local orca_migrated="${WATCHCLAW_DIR}/.migrated_from_argus"
    if [ -f "$argus_db" ] && [ ! -f "$orca_migrated" ]; then
        # Merge argus records into WatchClaw DB (don't overwrite existing WatchClaw records)
        python3 - "$argus_db" "$WATCHCLAW_DB" <<'PYEOF' 2>/dev/null && touch "$orca_migrated" || true
import sys, json, os
src_path, dst_path = sys.argv[1], sys.argv[2]
try:
    with open(src_path) as f: src = json.load(f)
except Exception: src = {}
try:
    with open(dst_path) as f: dst = json.load(f)
except Exception: dst = {}
merged = dict(src)
merged.update(dst)  # WatchClaw wins on conflict
tmp = dst_path + '.tmp'
with open(tmp, 'w') as f: json.dump(merged, f, indent=2)
os.replace(tmp, dst_path)
print(f"Migrated {len(src)} argus records into WatchClaw threat-db", file=sys.stderr)
PYEOF
        _orca_log "INIT migrated argus→watchclaw threat-db"
    fi
}

# =============================================================================
# orca_get_reputation <ip>  →  prints abuse_score (0 if unknown/unavailable)
# Also updates reputation-cache.json
# =============================================================================
orca_get_reputation() {
    local ip="$1"
    watchclaw_init

    # Check cache
    local cached now_ts cache_ts abuse_score
    now_ts=$(date +%s)
    cached=$(jq -r --arg ip "$ip" '.[$ip] // empty' "$ORCA_REP_CACHE" 2>/dev/null)

    if [ -n "$cached" ]; then
        cache_ts=$(echo "$cached" | jq -r '.cached_at_ts // 0')
        if [ $(( now_ts - cache_ts )) -lt "$ORCA_REP_TTL_SECS" ]; then
            echo "$cached" | jq -r '.abuse_score // 0'
            return 0
        fi
    fi

    # Try AbuseIPDB if key available
    abuse_score=0
    local categories=""
    local usage_type=""
    if [ -n "${ABUSEIPDB_API_KEY:-}" ]; then
        local api_resp
        api_resp=$(curl -s --max-time 10 \
            "https://api.abuseipdb.com/api/v2/check" \
            -G \
            --data-urlencode "ipAddress=${ip}" \
            --data-urlencode "maxAgeInDays=90" \
            --data-urlencode "verbose" \
            -H "Key: ${ABUSEIPDB_API_KEY}" \
            -H "Accept: application/json" 2>/dev/null || echo "")
        if [ -n "$api_resp" ] && echo "$api_resp" | jq -e '.data.abuseConfidenceScore' >/dev/null 2>&1; then
            abuse_score=$(echo "$api_resp" | jq -r '.data.abuseConfidenceScore // 0')
            categories=$(echo "$api_resp" | jq -r '.data.reports[0:3] | map(.categories[]) | unique | join(",")' 2>/dev/null || echo "")
            usage_type=$(echo "$api_resp" | jq -r '.data.usageType // ""' 2>/dev/null || echo "")
        fi
    fi

    # Write to cache (atomic)
    local entry
    entry=$(jq -n \
        --argjson score "$abuse_score" \
        --arg cats "$categories" \
        --arg usage "$usage_type" \
        --argjson ts "$now_ts" \
        '{abuse_score: $score, categories: $cats, usage_type: $usage, cached_at_ts: $ts}')
    python3 - "$ORCA_REP_CACHE" "$ip" "$entry" <<'PYEOF' 2>/dev/null || true
import sys, json, os
path, ip, entry_str = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path) as f: cache = json.load(f)
except Exception: cache = {}
cache[ip] = json.loads(entry_str)
tmp = path + '.tmp'
with open(tmp, 'w') as f: json.dump(cache, f, indent=2)
os.replace(tmp, path)
PYEOF
    echo "$abuse_score"
}

# =============================================================================
# orca_resolve_asn <ip>  →  prints ASN string (e.g. "AS12345") or "unknown"
# =============================================================================
orca_resolve_asn() {
    local ip="$1"

    # Check ASN DB first
    local cached
    cached=$(jq -r --arg ip "$ip" '.[$ip].asn // empty' "$ORCA_ASN_DB" 2>/dev/null)
    if [ -n "$cached" ] && [ "$cached" != "unknown" ]; then
        echo "$cached"; return 0
    fi

    # Try ipinfo.io (fast, structured)
    local asn=""
    local resp
    resp=$(curl -s --max-time 4 "https://ipinfo.io/${ip}/json" 2>/dev/null || echo "")
    if [ -n "$resp" ]; then
        asn=$(echo "$resp" | jq -r '.org // ""' 2>/dev/null | grep -oE 'AS[0-9]+' | head -1 || echo "")
    fi

    # Fallback: whois
    if [ -z "$asn" ]; then
        asn=$(timeout 5 whois "$ip" 2>/dev/null | grep -iE "^(origin|aut-num):" | head -1 | awk '{print $NF}' | grep -oE 'AS?[0-9]+' | sed 's/^/AS/' | tr -d 'AS' | sed 's/^/AS/' || echo "")
        # Simplify: just get the ASN number
        asn=$(timeout 5 whois "$ip" 2>/dev/null | grep -iE "^origin:" | head -1 | awk '{print $NF}' | tr '[:lower:]' '[:upper:]' || echo "")
    fi

    [ -z "$asn" ] && asn="unknown"
    echo "$asn"
}

# =============================================================================
# orca_resolve_geo <ip>  →  prints country code (e.g. "CN") or "unknown"
# =============================================================================
orca_resolve_geo() {
    local ip="$1"

    # Check GEO DB first
    local cached
    cached=$(jq -r --arg ip "$ip" '.[$ip].country // empty' "$ORCA_GEO_DB" 2>/dev/null || echo "")
    if [ -n "$cached" ] && [ "$cached" != "unknown" ]; then
        echo "$cached"; return 0
    fi

    # Try ipinfo.io
    local country=""
    local resp
    resp=$(curl -s --max-time 4 "https://ipinfo.io/${ip}/json" 2>/dev/null || echo "")
    if [ -n "$resp" ]; then
        country=$(echo "$resp" | jq -r '.country // ""' 2>/dev/null || echo "")
    fi

    # Fallback: whois
    if [ -z "$country" ]; then
        country=$(timeout 5 whois "$ip" 2>/dev/null | grep -iE "^country:" | head -1 | awk '{print $NF}' | tr '[:lower:]' '[:upper:]' || echo "")
    fi

    [ -z "$country" ] && country="unknown"
    echo "$country"
}

# =============================================================================
# watchclaw_record_event <ip> <event_type> [extra_info]
#
# Records an event, applies scoring, enriches with rep/asn/geo (cached).
# Returns updated score to stdout.
# =============================================================================
watchclaw_record_event() {
    local ip="$1"
    local event_type="$2"
    local extra_info="${3:-}"
    [ -z "$ip" ] || [ -z "$event_type" ] && return 1
    watchclaw_init

    # Step 1: Record event in threat-db (Python handles scoring, decay, classification)
    local new_score enrich_needed
    local result
    result=$(python3 - "$ip" "$event_type" "$extra_info" "$WATCHCLAW_DB" "$WATCHCLAW_LOG" <<'PYEOF' 2>/dev/null
import sys, json, os, datetime, math

ip, event_type, extra_info = sys.argv[1], sys.argv[2], sys.argv[3]
db_path, log_path = sys.argv[4], sys.argv[5]

SCORE_MAP = {
    'failed_login':          1,
    'login_success':         5,
    'command_exec':          5,
    'recon_fingerprint':     3,
    'tunnel_tcpip':         20,
    'persistence_attempt':  50,
    'malware_download':     75,
}
DECAY_RATE = 0.10  # 10% per 24h
RECON_CAP_POINTS_30M = 30   # cap recon contribution per IP in rolling 30m

score_delta = SCORE_MAP.get(event_type, 1)
now_dt = datetime.datetime.utcnow()
now_iso = now_dt.isoformat() + 'Z'
today = now_dt.date().isoformat()

try:
    with open(db_path) as f: db = json.load(f)
except Exception: db = {}

rec = db.get(ip, {
    'first_seen': now_iso, 'last_seen': now_iso,
    'total_events': 0, 'score': 0, 'raw_score': 0,
    'classification': 'unknown', 'bans': [], 'windows': [],
    'event_types': {}, 'enriched_at': '', 'asn': '', 'country': '',
    'rep_score': 0, 'high_reputation_risk': False,
    'score_events': [],
})

# Apply score decay (10% per 24h since last_seen)
try:
    last_dt = datetime.datetime.fromisoformat(rec.get('last_seen', now_iso).rstrip('Z'))
    hours_since = (now_dt - last_dt).total_seconds() / 3600.0
    days_since = hours_since / 24.0
    if days_since >= 1.0:
        decay_factor = math.pow(1.0 - DECAY_RATE, days_since)
        rec['score'] = max(0, rec.get('score', 0) * decay_factor)
except Exception:
    pass

# Double penalty for reappearance after active ban
active_ban = False
for ban in rec.get('bans', []):
    if not ban.get('active', False): continue
    if ban.get('type') == 'permanent':
        active_ban = True; break
    expires = ban.get('expires', '')
    if expires:
        try:
            exp_dt = datetime.datetime.fromisoformat(expires.rstrip('Z'))
            if now_dt < exp_dt: active_ban = True; break
        except Exception: pass

if active_ban:
    score_delta *= 2

# Per-IP recon scoring cap (rolling 30m) to reduce noise inflation
score_events = rec.get('score_events', [])
cutoff_30m = now_dt - datetime.timedelta(minutes=30)
filtered_events = []
recon_points_30m = 0.0
for ev in score_events:
    ts = ev.get('ts', '')
    try:
        ev_dt = datetime.datetime.fromisoformat(ts.rstrip('Z'))
    except Exception:
        continue
    if ev_dt >= cutoff_30m:
        filtered_events.append(ev)
        if ev.get('type') == 'recon_fingerprint':
            recon_points_30m += float(ev.get('delta', 0) or 0)

if event_type == 'recon_fingerprint' and score_delta > 0:
    allowed = max(0.0, RECON_CAP_POINTS_30M - recon_points_30m)
    score_delta = min(float(score_delta), allowed)

# Update record
rec['last_seen'] = now_iso
rec['total_events'] = rec.get('total_events', 0) + 1
rec['score'] = rec.get('score', 0) + score_delta
rec['raw_score'] = rec.get('raw_score', 0) + score_delta

# Keep scoring event history (for per-type window caps)
filtered_events.append({'ts': now_iso, 'type': event_type, 'delta': score_delta})
rec['score_events'] = filtered_events[-300:]

# Windows tracking
windows = rec.get('windows', [])
if today not in windows:
    windows.append(today)
windows = sorted(set(windows))[-30:]
rec['windows'] = windows

# Event type counters
et = rec.get('event_types', {})
et[event_type] = et.get(event_type, 0) + 1
rec['event_types'] = et

# Classification
if len(windows) >= 2:
    if et.get('malware_download', 0) > 0:
        rec['classification'] = 'crypto_miner'
    elif et.get('persistence_attempt', 0) > 0 or et.get('tunnel_tcpip', 0) > 0:
        rec['classification'] = 'recon_bot'
    elif et.get('command_exec', 0) > 0:
        rec['classification'] = 'botnet_node'
    elif et.get('recon_fingerprint', 0) > 5:
        rec['classification'] = 'scanner'

db[ip] = rec

# Atomic write
tmp = db_path + '.tmp'
with open(tmp, 'w') as f: json.dump(db, f, indent=2)
os.replace(tmp, db_path)

# Determine if enrichment needed
last_enriched = rec.get('enriched_at', '')
needs_enrich = 0
if not last_enriched:
    needs_enrich = 1
else:
    try:
        enrich_dt = datetime.datetime.fromisoformat(last_enriched.rstrip('Z'))
        if (now_dt - enrich_dt).total_seconds() > 86400:
            needs_enrich = 1
    except Exception:
        needs_enrich = 1

os.makedirs(os.path.dirname(log_path), exist_ok=True)
with open(log_path, 'a') as f:
    f.write(f"[{now_iso}] EVENT ip={ip} type={event_type} delta={score_delta} score={rec['score']:.1f} ban={active_ban}\n")

print(f"{rec['score']:.1f}|{needs_enrich}")
PYEOF
)

    new_score=$(echo "$result" | cut -d'|' -f1)
    enrich_needed=$(echo "$result" | cut -d'|' -f2)

    # Step 2: Enrichment (ASN + Geo + Reputation) — only if needed
    if [ "${enrich_needed:-0}" = "1" ]; then
        local asn country rep_score rep_risk=0
        asn=$(orca_resolve_asn "$ip" 2>/dev/null || echo "unknown")
        country=$(orca_resolve_geo "$ip" 2>/dev/null || echo "unknown")
        rep_score=$(orca_get_reputation "$ip" 2>/dev/null || echo "0")

        [ "$rep_score" -gt 90 ] && rep_risk=1

        # Apply reputation score bonus if needed (+50 for >75)
        local rep_bonus=0
        [ "$rep_score" -gt 75 ] && rep_bonus=50

        # Update threat-db with enrichment data + rep bonus
        new_score=$(python3 - "$ip" "$asn" "$country" "$rep_score" "$rep_risk" "$rep_bonus" "$WATCHCLAW_DB" <<'PYEOF' 2>/dev/null
import sys, json, os, datetime
ip, asn, country, rep_score_str, rep_risk_str, rep_bonus_str, db_path = sys.argv[1:]
rep_score = int(rep_score_str); rep_risk = rep_risk_str == '1'; rep_bonus = int(rep_bonus_str)
now_iso = datetime.datetime.utcnow().isoformat() + 'Z'
try:
    with open(db_path) as f: db = json.load(f)
except Exception: db = {}
rec = db.get(ip, {})
rec['asn'] = asn
rec['country'] = country
rec['rep_score'] = rep_score
rec['high_reputation_risk'] = rep_risk
rec['enriched_at'] = now_iso
if rep_bonus > 0:
    rec['score'] = rec.get('score', 0) + rep_bonus
db[ip] = rec
tmp = db_path + '.tmp'
with open(tmp, 'w') as f: json.dump(db, f, indent=2)
os.replace(tmp, db_path)
print(f"{rec['score']:.1f}")
PYEOF
)

        # Update ASN DB
        orca_asn_update "$ip" "$asn" 2>/dev/null || true

        # Update Geo DB
        orca_geo_update "$ip" "$country" 2>/dev/null || true

        _orca_log "ENRICH ip=$ip asn=$asn country=$country rep=$rep_score"
    fi

    echo "${new_score:-0}"
}

# =============================================================================
# orca_asn_update <ip> <asn>  — updates ASN DB with this IP's event
# =============================================================================
orca_asn_update() {
    local ip="$1" asn="$2"
    [ -z "$asn" ] || [ "$asn" = "unknown" ] && return 0
    watchclaw_init

    python3 - "$ip" "$asn" "$ORCA_ASN_DB" "$WATCHCLAW_DB" <<'PYEOF' 2>/dev/null || true
import sys, json, os, datetime

ip, asn, asn_db_path, threat_db_path = sys.argv[1:]
now_dt = datetime.datetime.utcnow()
now_iso = now_dt.isoformat() + 'Z'
today = now_dt.date().isoformat()
cutoff_7d = (now_dt - datetime.timedelta(days=7)).isoformat() + 'Z'

try:
    with open(asn_db_path) as f: asn_db = json.load(f)
except Exception: asn_db = {}

try:
    with open(threat_db_path) as f: threat_db = json.load(f)
except Exception: threat_db = {}

entry = asn_db.get(asn, {
    'asn': asn, 'unique_ips': [], 'total_events': 0,
    'rolling_7d_events': 0, 'cluster_score': 0,
    'events_by_day': {}, 'last_updated': now_iso,
    'suspicious_cluster': False, 'cluster_flagged_at': ''
})

# Track unique IPs
unique_ips = entry.get('unique_ips', [])
if ip not in unique_ips:
    unique_ips.append(ip)
entry['unique_ips'] = unique_ips

# Track events by day
ebd = entry.get('events_by_day', {})
ebd[today] = ebd.get(today, 0) + 1
# Prune old days (keep 30d)
cutoff_day = (now_dt - datetime.timedelta(days=30)).date().isoformat()
ebd = {d: c for d, c in ebd.items() if d >= cutoff_day}
entry['events_by_day'] = ebd

entry['total_events'] = entry.get('total_events', 0) + 1

# Rolling 7d events
cutoff_7d_day = (now_dt - datetime.timedelta(days=7)).date().isoformat()
rolling_7d = sum(c for d, c in ebd.items() if d >= cutoff_7d_day)
entry['rolling_7d_events'] = rolling_7d

# 7d unique IPs (IPs with activity in threat_db in last 7d)
ips_7d = []
for rec_ip in unique_ips:
    rec = threat_db.get(rec_ip, {})
    ls = rec.get('last_seen', '')
    if ls >= cutoff_7d:
        ips_7d.append(rec_ip)
entry['unique_ips_7d'] = ips_7d

# Cluster score: normalize by unique IPs x events
n_ips_7d = len(ips_7d)
entry['cluster_score'] = round(rolling_7d * n_ips_7d / max(1, 10), 2)

# Count hostile classifications from this ASN in 7d
hostile_classes = {'botnet_node', 'crypto_miner', 'recon_bot'}
hostile_count = sum(
    1 for rec_ip in ips_7d
    if threat_db.get(rec_ip, {}).get('classification', '') in hostile_classes
)
entry['hostile_count_7d'] = hostile_count

# Detect suspicious cluster
was_flagged = entry.get('suspicious_cluster', False)
is_cluster = n_ips_7d >= 5 and hostile_count >= 3
entry['suspicious_cluster'] = is_cluster
if is_cluster and not was_flagged:
    entry['cluster_flagged_at'] = now_iso  # newly detected

entry['last_updated'] = now_iso
asn_db[asn] = entry

tmp = asn_db_path + '.tmp'
with open(tmp, 'w') as f: json.dump(asn_db, f, indent=2)
os.replace(tmp, asn_db_path)
PYEOF
}

# =============================================================================
# orca_geo_update <ip> <country>  — updates GEO DB
# =============================================================================
orca_geo_update() {
    local ip="$1" country="$2"
    [ -z "$country" ] || [ "$country" = "unknown" ] && return 0
    watchclaw_init

    python3 - "$ip" "$country" "$ORCA_GEO_DB" <<'PYEOF' 2>/dev/null || true
import sys, json, os, datetime

ip, country, geo_db_path = sys.argv[1:]
now_dt = datetime.datetime.utcnow()
now_iso = now_dt.isoformat() + 'Z'
today = now_dt.date().isoformat()

try:
    with open(geo_db_path) as f: geo_db = json.load(f)
except Exception: geo_db = {'countries': {}, 'ip_country': {}, 'history': []}

# Per-country stats
countries = geo_db.get('countries', {})
c = countries.get(country, {
    'country': country, 'total_events': 0, 'unique_ips': [],
    'events_by_day': {}, 'rolling_7d_events': 0, 'last_seen': '',
    'first_seen_ever': now_iso,
})

# Unique IPs
unique_ips = c.get('unique_ips', [])
if ip not in unique_ips:
    unique_ips.append(ip)
c['unique_ips'] = unique_ips

# Events by day
ebd = c.get('events_by_day', {})
ebd[today] = ebd.get(today, 0) + 1
cutoff_day = (now_dt - datetime.timedelta(days=30)).date().isoformat()
ebd = {d: cnt for d, cnt in ebd.items() if d >= cutoff_day}
c['events_by_day'] = ebd

c['total_events'] = c.get('total_events', 0) + 1

# Rolling 7d
cutoff_7d_day = (now_dt - datetime.timedelta(days=7)).date().isoformat()
c['rolling_7d_events'] = sum(cnt for d, cnt in ebd.items() if d >= cutoff_7d_day)

c['last_seen'] = now_iso
countries[country] = c
geo_db['countries'] = countries

# IP → country index
ip_country = geo_db.get('ip_country', {})
ip_country[ip] = country
geo_db['ip_country'] = ip_country

# History entry
history = geo_db.get('history', [])
history.append({'ts': now_iso, 'ip': ip, 'country': country})
history = history[-500:]  # cap
geo_db['history'] = history

tmp = geo_db_path + '.tmp'
with open(tmp, 'w') as f: json.dump(geo_db, f, indent=2)
os.replace(tmp, geo_db_path)
PYEOF
}

# =============================================================================
# watchclaw_check_and_ban <ip>  →  prints ban type applied (none|short|long|permanent)
# =============================================================================
watchclaw_check_and_ban() {
    local ip="$1"
    watchclaw_init

    python3 - "$ip" "$WATCHCLAW_DB" "$WATCHCLAW_LOG" <<'PYEOF' 2>/dev/null
import sys, json, os, datetime, subprocess

ip, db_path, log_path = sys.argv[1], sys.argv[2], sys.argv[3]
UFW = '/usr/sbin/ufw'
now_dt = datetime.datetime.utcnow()
now_iso = now_dt.isoformat() + 'Z'

try:
    with open(db_path) as f: db = json.load(f)
except Exception: db = {}

rec = db.get(ip)
if not rec:
    print('none'); sys.exit(0)

score = rec.get('score', 0)
bans = rec.get('bans', [])

def active_bans(bans):
    result = []
    for b in bans:
        if not b.get('active', False): continue
        if b.get('type') == 'permanent': result.append(b); continue
        expires = b.get('expires', '')
        if expires:
            try:
                exp_dt = datetime.datetime.fromisoformat(expires.rstrip('Z'))
                if now_dt < exp_dt: result.append(b)
                else: b['active'] = False
            except: pass
    return result

active = active_bans(bans)
active_types = {b['type'] for b in active}

tier = {'none': 0, 'short': 1, 'long': 2, 'permanent': 3}
et = rec.get('event_types', {})

# Immediate ban: any login_success on honeypot = guaranteed malicious
if et.get('login_success', 0) > 0:
    if score >= 150: needed = 'permanent'
    elif score >= 75: needed = 'long'
    else: needed = 'short'  # instant ban even below 25
elif score >= 150: needed = 'permanent'
elif score >= 75: needed = 'long'
elif score >= 25: needed = 'short'
else: needed = 'none'

current_tier = max((tier.get(t, 0) for t in active_types), default=0)
needed_tier = tier.get(needed, 0)

if needed_tier <= current_tier:
    print('none'); sys.exit(0)

# Deactivate existing bans (escalation)
for b in bans: b['active'] = False

# Calculate expiry
if needed == 'short':
    expires = (now_dt + datetime.timedelta(hours=24)).isoformat() + 'Z'
    comment = 'watchclaw-short-ban'
elif needed == 'long':
    expires = (now_dt + datetime.timedelta(days=7)).isoformat() + 'Z'
    comment = 'watchclaw-long-ban'
else:
    expires = None
    comment = 'watchclaw-permanent-ban'

# Apply UFW ban (idempotent)
ufw_ok = False
try:
    r = subprocess.run([UFW, 'deny', 'from', ip, 'to', 'any', 'comment', comment],
                       capture_output=True, text=True, timeout=10)
    ufw_ok = r.returncode == 0
except Exception: pass

# Apply fail2ban ban
try:
    subprocess.run(['fail2ban-client', 'set', 'sshd', 'banip', ip],
                   capture_output=True, text=True, timeout=10)
except Exception: pass

# Try ipset if available
try:
    subprocess.run(['ipset', 'add', 'watchclaw-block', ip, 'comment', comment, '-exist'],
                   capture_output=True, text=True, timeout=5)
except Exception: pass

ban_rec = {
    'type': needed, 'at': now_iso, 'expires': expires,
    'active': True, 'ufw_applied': ufw_ok, 'comment': comment,
    'score_at_ban': score,
}
bans.append(ban_rec)
rec['bans'] = bans
db[ip] = rec

tmp = db_path + '.tmp'
with open(tmp, 'w') as f: json.dump(db, f, indent=2)
os.replace(tmp, db_path)

os.makedirs(os.path.dirname(log_path), exist_ok=True)
with open(log_path, 'a') as f:
    f.write(f"[{now_iso}] BAN ip={ip} type={needed} score={score:.1f} ufw={ufw_ok}\n")

print(needed)
PYEOF
}

# =============================================================================
# orca_verify_bans  →  prints "ip|type|reason" for each ineffective ban
# Also re-applies missing UFW rules silently.
# =============================================================================
orca_verify_bans() {
    watchclaw_init

    python3 - "$WATCHCLAW_DB" "$WATCHCLAW_LOG" <<'PYEOF' 2>/dev/null
import sys, json, os, datetime, subprocess

db_path, log_path = sys.argv[1], sys.argv[2]
now_dt = datetime.datetime.utcnow()
now_iso = now_dt.isoformat() + 'Z'

try:
    with open(db_path) as f: db = json.load(f)
except Exception: db = {}

try:
    ufw_status = subprocess.run(['/usr/sbin/ufw', 'status'],
                                capture_output=True, text=True, timeout=10).stdout
except Exception: ufw_status = ''

ineffective = []
db_changed = False

for ip, rec in db.items():
    for ban in rec.get('bans', []):
        if not ban.get('active', False): continue
        btype = ban.get('type', '')
        if btype == 'permanent':
            if ip not in ufw_status:
                ineffective.append((ip, btype, 'UFW rule missing'))
        else:
            expires = ban.get('expires', '')
            if expires:
                try:
                    exp_dt = datetime.datetime.fromisoformat(expires.rstrip('Z'))
                    if now_dt > exp_dt:
                        ban['active'] = False; db_changed = True
                    elif ip not in ufw_status:
                        ineffective.append((ip, btype, 'UFW rule missing'))
                except: pass

if db_changed:
    tmp = db_path + '.tmp'
    with open(tmp, 'w') as f: json.dump(db, f, indent=2)
    os.replace(tmp, db_path)

os.makedirs(os.path.dirname(log_path), exist_ok=True)
for ip, btype, reason in ineffective:
    print(f"{ip}|{btype}|{reason}")
    with open(log_path, 'a') as f:
        f.write(f"[{now_iso}] INEFFECTIVE_BAN ip={ip} type={btype} reason={reason}\n")
PYEOF
}

# =============================================================================
# watchclaw_post_batch  — call after processing a batch of events
# Checks: ASN cluster alerts, geo anomalies, CRITICAL GitHub issues
# =============================================================================
watchclaw_post_batch() {
    watchclaw_init

    # ── ASN cluster detection ────────────────────────────────────────────────
    local cluster_alerts
    cluster_alerts=$(python3 - "$ORCA_ASN_DB" "$WATCHCLAW_STATE" \
        "$ORCA_CLUSTER_MIN_IPS" "$ORCA_CLUSTER_MIN_HOSTILE" <<'PYEOF' 2>/dev/null
import sys, json, os, datetime
asn_db_path, state_path, min_ips_s, min_hostile_s = sys.argv[1:]
min_ips, min_hostile = int(min_ips_s), int(min_hostile_s)
try:
    with open(asn_db_path) as f: asn_db = json.load(f)
except Exception: asn_db = {}
try:
    with open(state_path) as f: state = json.load(f)
except Exception: state = {}

now_iso = datetime.datetime.utcnow().isoformat() + 'Z'
alerted_asns = state.get('cluster_alerted_asns', {})
alerts = []

for asn, entry in asn_db.items():
    if not entry.get('suspicious_cluster', False): continue
    ips_7d = entry.get('unique_ips_7d', entry.get('unique_ips', []))
    hostile = entry.get('hostile_count_7d', 0)
    # Rate limit: only alert once per 24h per ASN
    last_alert = alerted_asns.get(asn, '')
    if last_alert:
        try:
            last_dt = datetime.datetime.fromisoformat(last_alert.rstrip('Z'))
            if (datetime.datetime.utcnow() - last_dt).total_seconds() < 86400:
                continue
        except: pass
    alerts.append(f"{asn}|{len(ips_7d)}|{hostile}")
    alerted_asns[asn] = now_iso

state['cluster_alerted_asns'] = alerted_asns
tmp = state_path + '.tmp'
with open(tmp, 'w') as f: json.dump(state, f, indent=2)
os.replace(tmp, state_path)

for a in alerts: print(a)
PYEOF
)

    if [ -n "$cluster_alerts" ]; then
        while IFS='|' read -r asn n_ips hostile_cnt; do
            [ -z "$asn" ] && continue
            local msg="🚨 WatchClaw: Suspicious ASN cluster detected!

ASN: ${asn}
Unique IPs (7d): ${n_ips}
Hostile offenders: ${hostile_cnt} (botnet/miner/recon)

⚠️ Recommend ASN block review.
Run: watchclaw recommend asn-block ${asn}
Approve: watchclaw enforce ban-asn ${asn} --mode ufw"
            orca_telegram "HIGH" "$msg"
            _orca_log "CLUSTER_ALERT asn=$asn ips=$n_ips hostile=$hostile_cnt"
        done <<< "$cluster_alerts"
    fi

    # ── Geo anomaly detection (tuned): low-noise, hourly batched alerts ─────
    local geo_anomalies
    geo_anomalies=$(python3 - "$ORCA_GEO_DB" "$WATCHCLAW_STATE" \
        "$ORCA_GEO_SPIKE_FACTOR" "$ORCA_GEO_MIN_DAILY" <<'PYEOF' 2>/dev/null
import sys, json, os, datetime

geo_db_path, state_path, spike_factor_s, min_daily_s = sys.argv[1:]
spike_factor, min_daily = float(spike_factor_s), int(min_daily_s)

try:
    with open(geo_db_path) as f: geo_db = json.load(f)
except Exception: geo_db = {}
try:
    with open(state_path) as f: state = json.load(f)
except Exception: state = {}

now_dt = datetime.datetime.utcnow()
now_iso = now_dt.isoformat() + 'Z'
today = now_dt.date().isoformat()
cutoff_7d = (now_dt - datetime.timedelta(days=7)).date().isoformat()
countries = geo_db.get('countries', {})
anomalies = []

for country, data in countries.items():
    if country == 'unknown':
        continue

    ebd = data.get('events_by_day', {})
    today_count = int(ebd.get(today, 0) or 0)
    historical_7d = [int(c) for d, c in ebd.items() if d < today and d >= cutoff_7d]
    seen_last_7d = len(historical_7d) > 0

    # Alert condition A:
    # country_event_count_today >= 25 AND country not seen in last 7 days
    if today_count >= 25 and not seen_last_7d:
        anomalies.append(f"NEW7D|{country}|{today_count}|-")
        continue

    # Alert condition B:
    # country volume > 3x baseline AND baseline >= 50
    baseline = (sum(historical_7d) / len(historical_7d)) if historical_7d else 0
    if baseline >= min_daily and today_count > baseline * spike_factor:
        anomalies.append(f"SPIKE|{country}|{today_count}|{baseline:.0f}")

# Persist silent anomaly candidates for weekly reporting
silent = state.get('geo_silent_events', [])
for entry in anomalies:
    parts = entry.split('|')
    if len(parts) >= 4:
        silent.append({'ts': now_iso, 'type': parts[0], 'country': parts[1], 'count': parts[2], 'baseline': parts[3]})
state['geo_silent_events'] = silent[-500:]

# Hourly global geo alert limiter
state.setdefault('rate_limits', {})
state['rate_limits'].setdefault('geo_last_alert_ts', '')

tmp = state_path + '.tmp'
with open(tmp, 'w') as f:
    json.dump(state, f, indent=2)
os.replace(tmp, state_path)

for a in anomalies:
    print(a)
PYEOF
)

    if [ -n "$geo_anomalies" ]; then
        local geo_rate_ok="0"
        geo_rate_ok=$(python3 - "$WATCHCLAW_STATE" <<'PYEOF' 2>/dev/null || echo "0"
import sys, json, os, datetime
state_path = sys.argv[1]
now = datetime.datetime.utcnow()
try:
    with open(state_path) as f:
        s = json.load(f)
except Exception:
    s = {}
rl = s.setdefault('rate_limits', {})
last = rl.get('geo_last_alert_ts', '')
ok = True
if last:
    try:
        last_dt = datetime.datetime.fromisoformat(last.rstrip('Z'))
        ok = (now - last_dt).total_seconds() >= 3600
    except Exception:
        ok = True
if ok:
    rl['geo_last_alert_ts'] = now.isoformat() + 'Z'
    tmp = state_path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(s, f, indent=2)
    os.replace(tmp, state_path)
    print('1')
else:
    print('0')
PYEOF
)

        if [ "$geo_rate_ok" = "1" ]; then
            local geo_lines=""
            local geo_count=0
            while IFS='|' read -r anomaly_type country count baseline; do
                [ -z "$anomaly_type" ] && continue
                geo_count=$((geo_count + 1))
                if [ "$anomaly_type" = "NEW7D" ]; then
                    geo_lines+="- ${country}: ${count} events (new in last 7d)"$'\n'
                else
                    geo_lines+="- ${country}: ${count} events (baseline ${baseline}/day)"$'\n'
                fi
                _orca_log "GEO_ANOMALY type=$anomaly_type country=$country count=$count baseline=$baseline"
            done <<< "$geo_anomalies"

            local geo_msg="🌍 WatchClaw: Geo anomaly batch (${geo_count} country/countries)\n\n${geo_lines}\nThresholds: new-country>=25 + unseen 7d OR >${ORCA_GEO_SPIKE_FACTOR}x baseline (baseline>=${ORCA_GEO_MIN_DAILY})."
            orca_telegram "MEDIUM" "$geo_msg"
        else
            _orca_log "GEO_ANOMALY suppressed by hourly rate limit"
        fi
    fi
}

# =============================================================================
# watchclaw_decay_all  — apply 10%/24h score decay to all IPs in threat-db
# =============================================================================
watchclaw_decay_all() {
    watchclaw_init

    python3 - "$WATCHCLAW_DB" "$WATCHCLAW_LOG" <<'PYEOF' 2>/dev/null || true
import sys, json, os, datetime, math

db_path, log_path = sys.argv[1], sys.argv[2]
DECAY_RATE = 0.10

try:
    with open(db_path) as f: db = json.load(f)
except Exception: db = {}

now_dt = datetime.datetime.utcnow()
now_iso = now_dt.isoformat() + 'Z'
decayed = 0

for ip, rec in db.items():
    try:
        last_dt = datetime.datetime.fromisoformat(rec.get('last_seen', now_iso).rstrip('Z'))
        hours = (now_dt - last_dt).total_seconds() / 3600.0
        days = hours / 24.0
        if days >= 1.0:
            old = rec.get('score', 0)
            new = max(0, old * math.pow(1.0 - DECAY_RATE, days))
            rec['score'] = new
            decayed += 1
    except Exception:
        pass

if decayed:
    tmp = db_path + '.tmp'
    with open(tmp, 'w') as f: json.dump(db, f, indent=2)
    os.replace(tmp, db_path)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, 'a') as f:
        f.write(f"[{now_iso}] DECAY applied to {decayed} IPs\n")

print(decayed)
PYEOF
}

# =============================================================================
# orca_prune_db  — remove IPs unseen > 45 days
# =============================================================================
orca_prune_db() {
    watchclaw_init

    python3 - "$WATCHCLAW_DB" "$WATCHCLAW_LOG" "$ORCA_PRUNE_DAYS" <<'PYEOF' 2>/dev/null || true
import sys, json, os, datetime

db_path, log_path, prune_days_s = sys.argv[1], sys.argv[2], sys.argv[3]
prune_days = int(prune_days_s)
cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=prune_days)).isoformat() + 'Z'

try:
    with open(db_path) as f: db = json.load(f)
except Exception: db = {}

to_remove = [ip for ip, rec in db.items()
             if rec.get('last_seen', '2000-01-01Z') < cutoff
             and not any(b.get('active') and b.get('type') == 'permanent'
                         for b in rec.get('bans', []))]

for ip in to_remove:
    del db[ip]

if to_remove:
    tmp = db_path + '.tmp'
    with open(tmp, 'w') as f: json.dump(db, f, indent=2)
    os.replace(tmp, db_path)
    now_iso = datetime.datetime.utcnow().isoformat() + 'Z'
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, 'a') as f:
        f.write(f"[{now_iso}] PRUNE removed {len(to_remove)} IPs older than {prune_days}d\n")

print(len(to_remove))
PYEOF
}

# =============================================================================
# orca_rolling_score [minutes]  →  total event-weight score within last N minutes
# Uses score_events (timestamped deltas) when available; falls back to IP score.
# =============================================================================
orca_rolling_score() {
    local minutes="${1:-30}"
    watchclaw_init

    python3 - "$minutes" "$WATCHCLAW_DB" <<'PYEOF' 2>/dev/null
import sys, json, datetime
minutes = int(sys.argv[1])
db_path = sys.argv[2]
cutoff_dt = datetime.datetime.utcnow() - datetime.timedelta(minutes=minutes)
cutoff_iso = cutoff_dt.isoformat() + 'Z'
try:
    with open(db_path) as f: db = json.load(f)
except Exception: db = {}

total = 0.0
for rec in db.values():
    se = rec.get('score_events', [])
    if se:
        for ev in se:
            ts = ev.get('ts', '')
            try:
                ev_dt = datetime.datetime.fromisoformat(ts.rstrip('Z'))
            except Exception:
                continue
            if ev_dt >= cutoff_dt:
                total += float(ev.get('delta', 0) or 0)
    elif rec.get('last_seen', '') >= cutoff_iso:
        # legacy fallback for records without score_events
        total += float(rec.get('score', 0) or 0)

print(f"{total:.1f}")
PYEOF
}

# =============================================================================
# orca_update_baseline <count>  — append event count to rolling baseline
# =============================================================================
orca_update_baseline() {
    local count="${1:-0}"
    watchclaw_init

    python3 - "$count" "$WATCHCLAW_STATE" <<'PYEOF' 2>/dev/null || true
import sys, json, os, datetime
count, state_path = int(sys.argv[1]), sys.argv[2]
now_iso = datetime.datetime.utcnow().isoformat() + 'Z'
try:
    with open(state_path) as f: s = json.load(f)
except Exception: s = {}
counts = s.get('event_counts', [])
counts.append({'ts': now_iso, 'count': count})
counts = counts[-96:]  # ~48h at 30min intervals
s['event_counts'] = counts
s['last_baseline_updated'] = now_iso
tmp = state_path + '.tmp'
with open(tmp, 'w') as f: json.dump(s, f, indent=2)
os.replace(tmp, state_path)
PYEOF
}

# =============================================================================
# orca_check_alert_rate <severity>  →  "ok" or "rate_limited"
# Rate limit: 1 alert per severity per 15 minutes
# =============================================================================
orca_check_alert_rate() {
    local severity="${1:-MEDIUM}"
    watchclaw_init

    python3 - "$severity" "$WATCHCLAW_STATE" "$ORCA_ALERT_RATE_MINS" <<'PYEOF' 2>/dev/null
import sys, json, os, datetime
severity, state_path, rate_mins_s = sys.argv[1], sys.argv[2], sys.argv[3]
rate_secs = int(rate_mins_s) * 60
now_dt = datetime.datetime.utcnow()
now_iso = now_dt.isoformat() + 'Z'

try:
    with open(state_path) as f: s = json.load(f)
except Exception: s = {}

rates = s.get('alert_rates', {})
last_alert = rates.get(severity, '')

if last_alert:
    try:
        last_dt = datetime.datetime.fromisoformat(last_alert.rstrip('Z'))
        if (now_dt - last_dt).total_seconds() < rate_secs:
            print('rate_limited')
            sys.exit(0)
    except: pass

rates[severity] = now_iso
s['alert_rates'] = rates
tmp = state_path + '.tmp'
with open(tmp, 'w') as f: json.dump(s, f, indent=2)
os.replace(tmp, state_path)
print('ok')
PYEOF
}

# =============================================================================
# orca_telegram <severity> <message>  — send Telegram with rate-limit guard
# =============================================================================
orca_telegram() {
    local severity="$1"
    local message="$2"

    # Check rate limit
    local rate_check
    rate_check=$(orca_check_alert_rate "$severity" 2>/dev/null || echo "ok")
    if [ "$rate_check" = "rate_limited" ]; then
        _orca_log "ALERT rate_limited severity=$severity"
        return 0
    fi

    local bot="${OPS_ALERTS_BOT_TOKEN:-$ORCA_BOT}"
    local chat="${ALERTS_TELEGRAM_CHAT:-$ORCA_CHAT}"
    [ -z "$bot" ] && return 0

    curl -s --max-time 15 -X POST \
        "https://api.telegram.org/bot${bot}/sendMessage" \
        -d "chat_id=${chat}" \
        --data-urlencode "text=${message}" > /dev/null 2>&1 || true

    _orca_log "ALERT severity=$severity sent"
}

# =============================================================================
# orca_status_json  →  JSON status summary
# =============================================================================
orca_status_json() {
    watchclaw_init

    python3 - "$WATCHCLAW_DB" "$ORCA_ASN_DB" "$ORCA_GEO_DB" "$WATCHCLAW_STATE" "$ORCA_REP_CACHE" <<'PYEOF' 2>/dev/null
import sys, json, datetime, statistics

db_path, asn_db_path, geo_db_path, state_path, rep_cache_path = sys.argv[1:]

now_dt = datetime.datetime.utcnow()
now_iso = now_dt.isoformat() + 'Z'
cutoff_30m = (now_dt - datetime.timedelta(minutes=30)).isoformat() + 'Z'
cutoff_24h = (now_dt - datetime.timedelta(hours=24)).isoformat() + 'Z'
cutoff_7d  = (now_dt - datetime.timedelta(days=7)).isoformat()   + 'Z'

try:
    with open(db_path) as f: db = json.load(f)
except Exception: db = {}
try:
    with open(asn_db_path) as f: asn_db = json.load(f)
except Exception: asn_db = {}
try:
    with open(geo_db_path) as f: geo_db = json.load(f)
except Exception: geo_db = {}
try:
    with open(state_path) as f: state = json.load(f)
except Exception: state = {}
try:
    with open(rep_cache_path) as f: rep_cache = json.load(f)
except Exception: rep_cache = {}

# Threat stats
total_ips = len(db)
active_30m = sum(1 for r in db.values() if r.get('last_seen','') >= cutoff_30m)
active_24h = sum(1 for r in db.values() if r.get('last_seen','') >= cutoff_24h)
active_7d  = sum(1 for r in db.values() if r.get('last_seen','') >= cutoff_7d)
banned     = sum(1 for r in db.values() if any(b.get('active') for b in r.get('bans',[])))
high_rep_risk = sum(1 for r in db.values() if r.get('high_reputation_risk'))

# Top offenders by score
top = sorted(db.items(), key=lambda x: x[1].get('score',0), reverse=True)[:5]
top_list = [{'ip': ip, 'score': round(r.get('score',0),1), 'class': r.get('classification','?'),
             'country': r.get('country','?'), 'asn': r.get('asn','?'),
             'rep_score': r.get('rep_score',0)} for ip, r in top]

# Security severity
severity = 'LOW'
rolling_score = sum(r.get('score',0) for r in db.values() if r.get('last_seen','') >= cutoff_30m)
for ip, r in db.items():
    et = r.get('event_types', {})
    ls = r.get('last_seen', '')
    if et.get('malware_download',0) > 0 and ls >= cutoff_24h: severity = max(severity, 'HIGH', key=lambda s: ['LOW','MEDIUM','HIGH','CRITICAL'].index(s) if s in ['LOW','MEDIUM','HIGH','CRITICAL'] else 0)
    if et.get('persistence_attempt',0) > 0 and ls >= cutoff_24h: severity = 'HIGH' if severity not in ('CRITICAL',) else severity
    if et.get('login_success',0) > 0 and ls >= cutoff_24h: severity = 'MEDIUM' if severity == 'LOW' else severity
    if r.get('score',0) >= 150 and ls >= cutoff_7d: severity = 'CRITICAL'

# Baseline check
event_counts = state.get('event_counts', [])
if len(event_counts) >= 3:
    recent_counts = [x['count'] for x in event_counts[-6:]]
    baseline_avg = statistics.mean(recent_counts) if recent_counts else 0
    if baseline_avg > 0 and rolling_score > baseline_avg * 3: severity = 'CRITICAL'
else:
    baseline_avg = 0

# Suspicious ASN clusters
clusters = {asn: e for asn, e in asn_db.items() if e.get('suspicious_cluster')}

# Geo summary
countries = geo_db.get('countries', {})
top_countries = sorted(countries.items(), key=lambda x: x[1].get('rolling_7d_events',0), reverse=True)[:5]

# High rep risk IPs
rep_risk_ips = [(ip, r.get('rep_score',0)) for ip, r in db.items() if r.get('high_reputation_risk')]
rep_risk_ips.sort(key=lambda x: x[1], reverse=True)

out = {
    'timestamp': now_iso,
    'security_status': severity,
    'threat_db': {
        'total_ips': total_ips,
        'active_30m': active_30m,
        'active_24h': active_24h,
        'active_7d': active_7d,
        'banned': banned,
        'high_reputation_risk': high_rep_risk,
        'rolling_score_30m': round(rolling_score, 1),
    },
    'top_offenders': top_list,
    'suspicious_asn_clusters': [
        {'asn': asn, 'unique_ips_7d': len(e.get('unique_ips_7d', e.get('unique_ips',[]))),
         'hostile_count': e.get('hostile_count_7d', 0), 'cluster_score': e.get('cluster_score',0)}
        for asn, e in clusters.items()
    ],
    'top_countries_7d': [
        {'country': c, 'events_7d': d.get('rolling_7d_events',0), 'unique_ips': len(d.get('unique_ips',[]))}
        for c, d in top_countries
    ],
    'high_reputation_risk_ips': [{'ip': ip, 'abuse_score': score} for ip, score in rep_risk_ips[:5]],
    'baseline_avg': round(baseline_avg, 1),
}
print(json.dumps(out, indent=2))
PYEOF
}

# =============================================================================
# orca_top_json <window>  →  JSON of top IPs for given window (30m|24h|7d)
# =============================================================================
orca_top_json() {
    local window="${1:-24h}"
    watchclaw_init

    python3 - "$window" "$WATCHCLAW_DB" <<'PYEOF' 2>/dev/null
import sys, json, datetime

window, db_path = sys.argv[1], sys.argv[2]
now_dt = datetime.datetime.utcnow()

if window == '30m':
    cutoff = (now_dt - datetime.timedelta(minutes=30)).isoformat() + 'Z'
elif window == '7d':
    cutoff = (now_dt - datetime.timedelta(days=7)).isoformat() + 'Z'
else:  # 24h default
    cutoff = (now_dt - datetime.timedelta(hours=24)).isoformat() + 'Z'

try:
    with open(db_path) as f: db = json.load(f)
except Exception: db = {}

active = [(ip, r) for ip, r in db.items() if r.get('last_seen','') >= cutoff]
active.sort(key=lambda x: x[1].get('score', 0), reverse=True)

result = []
for ip, r in active[:20]:
    result.append({
        'ip': ip,
        'score': round(r.get('score', 0), 1),
        'classification': r.get('classification', 'unknown'),
        'country': r.get('country', '?'),
        'asn': r.get('asn', '?'),
        'rep_score': r.get('rep_score', 0),
        'high_reputation_risk': r.get('high_reputation_risk', False),
        'total_events': r.get('total_events', 0),
        'event_types': r.get('event_types', {}),
        'bans': [b for b in r.get('bans', []) if b.get('active')],
        'last_seen': r.get('last_seen', ''),
    })

print(json.dumps({'window': window, 'timestamp': now_dt.isoformat() + 'Z', 'count': len(result), 'ips': result}, indent=2))
PYEOF
}

# =============================================================================
# orca_get_score <ip>  →  numeric score
# =============================================================================
orca_get_score() {
    local ip="$1"
    watchclaw_init
    jq -r --arg ip "$ip" '.[$ip].score // 0' "$WATCHCLAW_DB" 2>/dev/null || echo 0
}

# =============================================================================
# orca_dump_db  →  full threat-db JSON
# =============================================================================
orca_dump_db() {
    watchclaw_init
    cat "$WATCHCLAW_DB"
}

# =============================================================================
# Backward-compatible Argus aliases
# =============================================================================
# These allow existing scripts (cowrie-notify, cowrie-autoban, security-posture)
# to continue working without modification.

argus_init()            { watchclaw_init "$@"; }
threat_record_event()   { watchclaw_record_event "$@"; }
threat_check_and_ban()  { watchclaw_check_and_ban "$@"; }
threat_verify_bans()    { orca_verify_bans "$@"; }
threat_get_score()      { orca_get_score "$@"; }
threat_dump_db()        { orca_dump_db "$@"; }
threat_rolling_score()  { orca_rolling_score "$@"; }
threat_update_baseline(){ orca_update_baseline "$@"; }

threat_baseline_check() {
    local current="${1:-0}"
    watchclaw_init
    python3 - "$current" "$WATCHCLAW_STATE" <<'PYEOF' 2>/dev/null
import sys, json, statistics
current = int(sys.argv[1])
state_path = sys.argv[2]
try:
    with open(state_path) as f: s = json.load(f)
    counts = [x['count'] for x in s.get('event_counts', [])]
except Exception: counts = []
if len(counts) < 3:
    print(f"0|{current}|false")
    sys.exit(0)
avg = statistics.mean(counts)
is_anomaly = (avg > 0) and (current > avg * 3)
print(f"{avg:.1f}|{current}|{'true' if is_anomaly else 'false'}")
PYEOF
}
