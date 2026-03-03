#!/bin/bash
# =============================================================================
# Module: sync — Cross-node threat intelligence sharing
# =============================================================================
# Shares threat-db across your fleet via Git or API.
# Ban on one node → preemptive ban on all nodes.
# =============================================================================

set -euo pipefail
source /etc/orca/orca.conf 2>/dev/null || true

ORCA_STATE="${ORCA_STATE_DIR:-/var/lib/orca}"
SYNC_DIR="${ORCA_STATE}/sync"

log()  { echo -e "\033[0;32m[ORCA:sync]\033[0m $*"; }

mkdir -p "$SYNC_DIR"

# Generate node ID if not set
if [ -z "${SYNC_NODE_ID:-}" ]; then
    SYNC_NODE_ID="node-$(hostname -s)-$(cat /etc/machine-id 2>/dev/null | head -c 8 || echo $$)"
    log "Generated node ID: $SYNC_NODE_ID"
fi

cat > /opt/orca/scripts/orca-sync.sh << 'SYNCEOF'
#!/bin/bash
# Cross-node threat DB sync
set -euo pipefail
source /etc/orca/orca.conf 2>/dev/null || true

ORCA_STATE="${ORCA_STATE_DIR:-/var/lib/orca}"
ORCA_DB="${ORCA_DIR:-/var/lib/orca}/threat-db.json"
SYNC_DIR="${ORCA_STATE}/sync"
SYNC_LOG="/var/log/orca/sync.log"
NODE_ID="${SYNC_NODE_ID:-$(hostname -s)}"
UFW="/usr/sbin/ufw"

log()  { echo "[$(date -Iseconds)] $*" | tee -a "$SYNC_LOG"; }

case "${1:-auto}" in
    push)
        # Export this node's high-confidence bans
        python3 - "$ORCA_DB" "$SYNC_DIR" "$NODE_ID" << 'PYEOF'
import sys, json, datetime

db_path, sync_dir, node_id = sys.argv[1], sys.argv[2], sys.argv[3]
now = datetime.datetime.utcnow().isoformat() + 'Z'

try:
    with open(db_path) as f: db = json.load(f)
except: db = {}

# Only share IPs with active bans (high confidence)
shared = []
for ip, rec in db.items():
    active_bans = [b for b in rec.get('bans', []) if b.get('active')]
    if not active_bans: continue
    shared.append({
        'ip': ip,
        'score': rec.get('score', 0),
        'ban_type': active_bans[0].get('type', 'short'),
        'country': rec.get('country', ''),
        'asn': rec.get('asn', ''),
        'event_types': rec.get('event_types', {}),
        'last_seen': rec.get('last_seen', ''),
    })

payload = {
    'node_id': node_id,
    'timestamp': now,
    'total_shared': len(shared),
    'entries': shared,
}

out_path = f"{sync_dir}/{node_id}.json"
with open(out_path, 'w') as f:
    json.dump(payload, f, indent=2)
print(f"Pushed {len(shared)} bans from {node_id}")
PYEOF

        # Git push if configured
        if [ -n "${SYNC_REPO:-}" ]; then
            SYNC_GIT="${SYNC_DIR}/repo"
            if [ ! -d "$SYNC_GIT/.git" ]; then
                git clone "$SYNC_REPO" "$SYNC_GIT" 2>/dev/null
            fi
            cp "${SYNC_DIR}/${NODE_ID}.json" "$SYNC_GIT/"
            cd "$SYNC_GIT"
            git add -A
            git diff --cached --quiet || {
                git commit -m "ORCA sync: ${NODE_ID} $(date -Iseconds)"
                git push origin "${SYNC_BRANCH:-main}"
            }
            log "Pushed to sync repo"
        fi
        ;;

    pull)
        # Pull from sync repo
        if [ -n "${SYNC_REPO:-}" ]; then
            SYNC_GIT="${SYNC_DIR}/repo"
            if [ ! -d "$SYNC_GIT/.git" ]; then
                git clone "$SYNC_REPO" "$SYNC_GIT" 2>/dev/null
            else
                cd "$SYNC_GIT" && git pull --rebase origin "${SYNC_BRANCH:-main}" 2>/dev/null
            fi
        fi

        # Merge all node files (except our own)
        IMPORTED=0
        for node_file in "${SYNC_DIR}/repo"/*.json "${SYNC_DIR}"/*.json; do
            [ ! -f "$node_file" ] && continue
            # Skip our own
            [[ "$node_file" == *"${NODE_ID}"* ]] && continue

            # Import bans
            while IFS= read -r ip; do
                [ -z "$ip" ] && continue
                if ! $UFW status | grep -qF "$ip"; then
                    $UFW deny from "$ip" to any comment "orca-sync-import" 2>/dev/null || true
                    fail2ban-client set sshd banip "$ip" 2>/dev/null || true
                    IMPORTED=$((IMPORTED + 1))
                fi
            done < <(python3 -c "
import json,sys
try:
    d=json.load(open('$node_file'))
    for e in d.get('entries',[]):
        print(e['ip'])
except: pass
")
        done
        log "Pulled $IMPORTED new bans from peer nodes"
        ;;

    auto)
        # Push then pull
        "$0" push
        "$0" pull
        ;;

    *)
        echo "Usage: orca sync [push|pull|auto]"
        ;;
esac
SYNCEOF
chmod +x /opt/orca/scripts/orca-sync.sh

log "✅ Cross-node sync module installed (node: ${SYNC_NODE_ID})"
