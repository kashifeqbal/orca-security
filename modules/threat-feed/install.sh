#!/bin/bash
# =============================================================================
# Module: threat-feed — Import/export threat intelligence
# =============================================================================
# Import: Pull known-bad IPs from public feeds (blocklist.de, AbuseIPDB, etc.)
# Export: Publish your own blocklist for others to use
# =============================================================================

set -euo pipefail
source /etc/watchclaw/watchclaw.conf 2>/dev/null || true

WATCHCLAW_STATE="${WATCHCLAW_STATE_DIR:-/var/lib/watchclaw}"
FEED_DIR="${WATCHCLAW_STATE}/feeds"
EXPORT_DIR="${WATCHCLAW_STATE}/export"

log()  { echo -e "\033[0;32m[WatchClaw:threat-feed]\033[0m $*"; }

mkdir -p "$FEED_DIR" "$EXPORT_DIR"

# ── Create import script ─────────────────────────────────────────────────────
cat > /opt/watchclaw/scripts/watchclaw-import.sh << 'IMPORTEOF'
#!/bin/bash
# Import threat intelligence from configured feeds
set -euo pipefail
source /etc/watchclaw/watchclaw.conf 2>/dev/null || true

WATCHCLAW_STATE="${WATCHCLAW_STATE_DIR:-/var/lib/watchclaw}"
FEED_DIR="${WATCHCLAW_STATE}/feeds"
WATCHCLAW_DB="${WATCHCLAW_DIR:-/var/lib/watchclaw}/threat-db.json"
IMPORT_LOG="/var/log/watchclaw/import.log"
UFW="/usr/sbin/ufw"

log()  { echo "[$(date -Iseconds)] $*" | tee -a "$IMPORT_LOG"; }

FEEDS=(${THREAT_FEEDS[@]:-})
if [ ${#FEEDS[@]} -eq 0 ]; then
    log "No threat feeds configured. Add THREAT_FEEDS to /etc/watchclaw/watchclaw.conf"
    exit 0
fi

TOTAL_IMPORTED=0

for feed_url in "${FEEDS[@]}"; do
    feed_name=$(echo "$feed_url" | sed 's|.*/||; s|\.txt$||; s|\.json$||')
    feed_file="${FEED_DIR}/${feed_name}.txt"

    log "Fetching feed: $feed_name"
    if curl -fsSL --max-time 30 "$feed_url" -o "$feed_file.tmp" 2>/dev/null; then
        mv "$feed_file.tmp" "$feed_file"

        # Parse IPs (handle comments, empty lines)
        count=0
        while IFS= read -r line; do
            line=$(echo "$line" | sed 's/#.*//; s/[[:space:]]//g')
            # Validate IPv4
            if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                # Add to fail2ban (idempotent)
                fail2ban-client set sshd banip "$line" 2>/dev/null || true
                count=$((count + 1))
            fi
        done < "$feed_file"

        log "Imported $count IPs from $feed_name"
        TOTAL_IMPORTED=$((TOTAL_IMPORTED + count))
    else
        log "WARN: Failed to fetch $feed_name"
    fi
done

log "Total imported: $TOTAL_IMPORTED IPs from ${#FEEDS[@]} feeds"
IMPORTEOF
chmod +x /opt/watchclaw/scripts/watchclaw-import.sh

# ── Create export script ─────────────────────────────────────────────────────
cat > /opt/watchclaw/scripts/watchclaw-export.sh << 'EXPORTEOF'
#!/bin/bash
# Export WatchClaw threat intelligence as public blocklist
set -euo pipefail
source /etc/watchclaw/watchclaw.conf 2>/dev/null || true

WATCHCLAW_STATE="${WATCHCLAW_STATE_DIR:-/var/lib/watchclaw}"
EXPORT_DIR="${WATCHCLAW_STATE}/export"
WATCHCLAW_DB="${WATCHCLAW_DIR:-/var/lib/watchclaw}/threat-db.json"
MIN_SCORE="${EXPORT_MIN_SCORE:-25}"

log()  { echo "[$(date -Iseconds)] $*"; }

mkdir -p "$EXPORT_DIR"

# Generate exports
python3 - "$WATCHCLAW_DB" "$EXPORT_DIR" "$MIN_SCORE" << 'PYEOF'
import sys, json, datetime

db_path, export_dir, min_score = sys.argv[1], sys.argv[2], int(sys.argv[3])

try:
    with open(db_path) as f:
        db = json.load(f)
except Exception:
    db = {}

now = datetime.datetime.utcnow().isoformat() + 'Z'
entries = []
plaintext = []

for ip, rec in db.items():
    score = rec.get('score', 0)
    if score < min_score:
        continue

    entry = {
        'ip': ip,
        'score': score,
        'first_seen': rec.get('first_seen', ''),
        'last_seen': rec.get('last_seen', ''),
        'country': rec.get('country', ''),
        'asn': rec.get('asn', ''),
        'event_types': rec.get('event_types', {}),
        'classification': rec.get('classification', 'unknown'),
    }
    entries.append(entry)
    plaintext.append(ip)

# Sort by score descending
entries.sort(key=lambda x: x['score'], reverse=True)
plaintext.sort()

# JSON export
feed = {
    'name': 'WatchClaw Threat Feed',
    'generated': now,
    'total_ips': len(entries),
    'min_score': min_score,
    'entries': entries,
}
with open(f'{export_dir}/blocklist.json', 'w') as f:
    json.dump(feed, f, indent=2)

# Plaintext export (one IP per line)
with open(f'{export_dir}/blocklist.txt', 'w') as f:
    f.write(f'# WatchClaw Threat Feed — generated {now}\n')
    f.write(f'# IPs with score >= {min_score}\n')
    f.write(f'# Total: {len(plaintext)}\n')
    for ip in plaintext:
        f.write(ip + '\n')

# CSV export
with open(f'{export_dir}/blocklist.csv', 'w') as f:
    f.write('ip,score,country,asn,first_seen,last_seen,classification\n')
    for e in entries:
        f.write(f"{e['ip']},{e['score']},{e['country']},{e['asn']},{e['first_seen']},{e['last_seen']},{e['classification']}\n")

print(f"Exported {len(entries)} IPs (score >= {min_score})")
print(f"  JSON: {export_dir}/blocklist.json")
print(f"  Text: {export_dir}/blocklist.txt")
print(f"  CSV:  {export_dir}/blocklist.csv")
PYEOF

# Push to GitHub if configured
if [ -n "${EXPORT_GITHUB_REPO:-}" ]; then
    EXPORT_GIT_DIR="${WATCHCLAW_STATE}/export-repo"
    if [ ! -d "$EXPORT_GIT_DIR/.git" ]; then
        git clone "git@github.com:${EXPORT_GITHUB_REPO}.git" "$EXPORT_GIT_DIR" 2>/dev/null || \
        git clone "https://github.com/${EXPORT_GITHUB_REPO}.git" "$EXPORT_GIT_DIR"
    fi
    cp "$EXPORT_DIR"/blocklist.* "$EXPORT_GIT_DIR/"
    cd "$EXPORT_GIT_DIR"
    git add -A
    git diff --cached --quiet || {
        git commit -m "WatchClaw threat feed update $(date -Iseconds)"
        git push origin "${EXPORT_GITHUB_BRANCH:-main}"
        log "Pushed to GitHub: ${EXPORT_GITHUB_REPO}"
    }
fi

log "Export complete"
EXPORTEOF
chmod +x /opt/watchclaw/scripts/watchclaw-export.sh

log "✅ Threat feed module installed (import + export scripts)"
