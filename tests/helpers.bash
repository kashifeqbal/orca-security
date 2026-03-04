#!/usr/bin/env bash
# =============================================================================
# tests/helpers.bash — Shared test helpers for WatchClaw test suite
# =============================================================================

# ── Paths ─────────────────────────────────────────────────────────────────────
WATCHCLAW_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WATCHCLAW_LIB="${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
WATCHCLAW_INSTALL="${WATCHCLAW_REPO_ROOT}/install.sh"
WATCHCLAW_MODULES_DIR="${WATCHCLAW_REPO_ROOT}/modules"

# ── Setup / Teardown ──────────────────────────────────────────────────────────

# Creates a fresh temp WATCHCLAW_DIR for each test and sources the library.
# Call from setup() in each .bats file.
setup_orca_env() {
    TEST_TMPDIR="$(mktemp -d)"
    export WATCHCLAW_DIR="${TEST_TMPDIR}/.watchclaw"
    export WATCHCLAW_DB="${WATCHCLAW_DIR}/threat-db.json"
    export WATCHCLAW_REP_CACHE="${WATCHCLAW_DIR}/reputation-cache.json"
    export WATCHCLAW_ASN_DB="${WATCHCLAW_DIR}/asn-db.json"
    export WATCHCLAW_GEO_DB="${WATCHCLAW_DIR}/geo-db.json"
    export WATCHCLAW_STATE="${WATCHCLAW_DIR}/watchclaw-state.json"
    export WATCHCLAW_LOG="${WATCHCLAW_DIR}/watchclaw.log"

    mkdir -p "${WATCHCLAW_DIR}"

    # Suppress network calls
    export ABUSEIPDB_API_KEY=""
    export OPS_ALERTS_BOT_TOKEN=""
    export ALERTS_TELEGRAM_CHAT=""

    # Source the library
    # shellcheck disable=SC1090
    source "${WATCHCLAW_LIB}"

    # Initialize state files
    watchclaw_init
}

# Removes temp directory. Call from teardown() in each .bats file.
teardown_orca_env() {
    if [ -n "${TEST_TMPDIR:-}" ] && [ -d "${TEST_TMPDIR}" ]; then
        rm -rf "${TEST_TMPDIR}"
    fi
}

# ── DB helpers ────────────────────────────────────────────────────────────────

# Returns the raw score for an IP from the threat DB.
db_score() {
    local ip="$1"
    jq -r --arg ip "$ip" '.[$ip].score // 0' "${WATCHCLAW_DB}"
}

# Returns the event-type count for an IP.
db_event_count() {
    local ip="$1"
    local event_type="$2"
    jq -r --arg ip "$ip" --arg et "$event_type" '.[$ip].event_types[$et] // 0' "${WATCHCLAW_DB}"
}

# Returns the most recent active ban type for an IP (none|short|long|permanent).
db_active_ban() {
    local ip="$1"
    jq -r --arg ip "$ip" '
      .[$ip].bans // [] |
      map(select(.active == true)) |
      sort_by(.at) | last | .type // "none"
    ' "${WATCHCLAW_DB}"
}

# Injects a pre-built record directly into the threat DB (bypasses watchclaw_record_event).
db_inject() {
    local ip="$1"
    local json="$2"
    python3 - "${WATCHCLAW_DB}" "${ip}" "${json}" <<'PYEOF'
import sys, json, os
db_path, ip, rec_str = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(db_path) as f: db = json.load(f)
except Exception: db = {}
db[ip] = json.loads(rec_str)
tmp = db_path + '.tmp'
with open(tmp, 'w') as f: json.dump(db, f, indent=2)
os.replace(tmp, db_path)
PYEOF
}

# Sets last_seen for an IP to N hours ago (used for decay tests).
db_set_last_seen_hours_ago() {
    local ip="$1"
    local hours="$2"
    python3 - "${WATCHCLAW_DB}" "${ip}" "${hours}" <<'PYEOF'
import sys, json, os, datetime
db_path, ip, hours_s = sys.argv[1], sys.argv[2], sys.argv[3]
hours = float(hours_s)
try:
    with open(db_path) as f: db = json.load(f)
except Exception: db = {}
if ip in db:
    past = datetime.datetime.utcnow() - datetime.timedelta(hours=hours)
    db[ip]['last_seen'] = past.isoformat() + 'Z'
    tmp = db_path + '.tmp'
    with open(tmp, 'w') as f: json.dump(db, f, indent=2)
    os.replace(tmp, db_path)
PYEOF
}

# ── Assertion helpers ─────────────────────────────────────────────────────────

# Asserts that $1 (actual float) >= $2 (expected float).
assert_ge() {
    local actual="$1" expected="$2" label="${3:-value}"
    python3 -c "
import sys
a, e = float('${actual}'), float('${expected}')
if a < e:
    print(f'FAIL: {label} {a} < {e}', file=sys.stderr)
    sys.exit(1)
" || return 1
}

# Asserts that $1 (actual float) <= $2 (expected float).
assert_le() {
    local actual="$1" expected="$2" label="${3:-value}"
    python3 -c "
import sys
a, e = float('${actual}'), float('${expected}')
if a > e:
    print(f'FAIL: {label} {a} > {e}', file=sys.stderr)
    sys.exit(1)
" || return 1
}

# Asserts approximate equality within a tolerance.
assert_approx_eq() {
    local actual="$1" expected="$2" tol="${3:-0.5}" label="${4:-value}"
    python3 -c "
import sys
a, e, t = float('${actual}'), float('${expected}'), float('${tol}')
if abs(a - e) > t:
    print(f'FAIL: {label} {a} not ~= {e} (tol {t})', file=sys.stderr)
    sys.exit(1)
" || return 1
}
