#!/bin/bash
# =============================================================================
# WatchClaw Installer — One-command security hardening for Linux servers
# =============================================================================
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/kashifeqbal/watchclaw/main/install.sh | bash
#   # or
#   git clone https://github.com/kashifeqbal/watchclaw.git && cd watchclaw && sudo ./install.sh
#
# Options:
#   --standalone      Skip OpenClaw agent integration
#   --with-agents     Include OpenClaw agent integration
#   --modules=LIST    Comma-separated modules (default: all)
#   --dry-run         Show what would be done without doing it
#   --uninstall       Remove WatchClaw (keeps threat DB)
# =============================================================================

set -euo pipefail

WATCHCLAW_VERSION="1.0.0"
WATCHCLAW_REPO="https://github.com/kashifeqbal/watchclaw.git"
WATCHCLAW_INSTALL_DIR="/opt/watchclaw"
WATCHCLAW_STATE_DIR="/var/lib/watchclaw"
WATCHCLAW_LOG_DIR="/var/log/watchclaw"
WATCHCLAW_BIN="/usr/local/bin/watchclaw"
WATCHCLAW_CONF="/etc/watchclaw/watchclaw.conf"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${GREEN}[WatchClaw]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'

     ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗ ██████╗██╗      █████╗ ██╗    ██╗
    ██╔═══██╗██╔══██╗██╔════╝██╔══██╗
    ██║   ██║██████╔╝██║     ███████║
    ██║   ██║██╔══██╗██║     ██╔══██║
    ╚██████╔╝██║  ██║╚██████╗██║  ██║
     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝

    Open Runtime Containment & Analysis
EOF
    echo -e "${NC}"
    echo -e "    Version ${WATCHCLAW_VERSION}"
    echo ""
}

# ── Parse arguments ───────────────────────────────────────────────────────────
MODE="standalone"
DRY_RUN=false
UNINSTALL=false
MODULES_OVERRIDE=""

for arg in "$@"; do
    case "$arg" in
        --standalone)   MODE="standalone" ;;
        --with-agents)  MODE="agents" ;;
        --dry-run)      DRY_RUN=true ;;
        --uninstall)    UNINSTALL=true ;;
        --modules=*)    MODULES_OVERRIDE="${arg#--modules=}" ;;
        --help|-h)
            banner
            echo "Usage: $0 [--standalone|--with-agents] [--modules=LIST] [--dry-run] [--uninstall]"
            echo ""
            echo "Modules: ssh-harden, ufw-baseline, fail2ban, cowrie, kernel, canary, threat-feed, sync"
            exit 0
            ;;
        *) err "Unknown option: $arg"; exit 1 ;;
    esac
done

# ── Pre-flight checks ────────────────────────────────────────────────────────
preflight() {
    if [ "$(id -u)" -ne 0 ]; then
        err "WatchClaw must be run as root"
        exit 1
    fi

    if [ ! -f /etc/os-release ]; then
        err "Cannot detect OS. WatchClaw requires Debian/Ubuntu or RHEL/Rocky."
        exit 1
    fi

    source /etc/os-release
    case "$ID" in
        ubuntu|debian) PKG_MGR="apt" ;;
        centos|rhel|rocky|alma|fedora) PKG_MGR="dnf" ;;
        *) err "Unsupported OS: $ID. WatchClaw supports Debian/Ubuntu and RHEL/Rocky."; exit 1 ;;
    esac

    # Check Python 3
    if ! command -v python3 &>/dev/null; then
        log "Installing Python 3..."
        $DRY_RUN || {
            if [ "$PKG_MGR" = "apt" ]; then
                apt-get update -qq && apt-get install -y -qq python3 python3-pip
            else
                dnf install -y python3 python3-pip
            fi
        }
    fi

    log "Pre-flight checks passed (OS: $PRETTY_NAME, pkg: $PKG_MGR)"
}

# ── Directory setup ───────────────────────────────────────────────────────────
setup_dirs() {
    log "Creating directories..."
    if $DRY_RUN; then
        echo "  [dry-run] Would create: $WATCHCLAW_INSTALL_DIR $WATCHCLAW_STATE_DIR $WATCHCLAW_LOG_DIR /etc/watchclaw"
        echo "  [dry-run] Would create: $WATCHCLAW_STATE_DIR/{export,sync,canary}"
        echo "  [dry-run] Would create: ~/.watchclaw/ (state JSON files)"
        return 0
    fi

    mkdir -p "$WATCHCLAW_INSTALL_DIR" "$WATCHCLAW_STATE_DIR" "$WATCHCLAW_LOG_DIR" /etc/watchclaw
    mkdir -p "$WATCHCLAW_STATE_DIR"/{export,sync,canary}

    # Create per-user WatchClaw state directory with empty JSON stubs
    local wc_state_dir="${HOME:-/root}/.watchclaw"
    mkdir -p "$wc_state_dir"
    [ -f "${wc_state_dir}/threat-db.json" ]       || echo '{}' > "${wc_state_dir}/threat-db.json"
    [ -f "${wc_state_dir}/reputation-cache.json" ] || echo '{}' > "${wc_state_dir}/reputation-cache.json"
    [ -f "${wc_state_dir}/asn-db.json" ]           || echo '{}' > "${wc_state_dir}/asn-db.json"
    [ -f "${wc_state_dir}/geo-db.json" ]           || echo '{"countries":{},"history":[]}' > "${wc_state_dir}/geo-db.json"
    [ -f "${wc_state_dir}/watchclaw-state.json" ]  || echo '{"alert_rates":{},"last_issue_at":"","info_count":0,"event_counts":[],"last_baseline_updated":""}' > "${wc_state_dir}/watchclaw-state.json"

    # Copy files from cloned repo
    local src_dir
    src_dir="$(dirname "$0")"
    if [ -f "${src_dir}/lib/watchclaw-lib.sh" ]; then
        cp -r "${src_dir}/lib"     "$WATCHCLAW_INSTALL_DIR/"
        cp -r "${src_dir}/modules" "$WATCHCLAW_INSTALL_DIR/"
        cp -r "${src_dir}/scripts" "$WATCHCLAW_INSTALL_DIR/"
        cp -r "${src_dir}/config"  "$WATCHCLAW_INSTALL_DIR/"
        chmod +x "${WATCHCLAW_INSTALL_DIR}"/scripts/*.sh
        log "Copied operational scripts to ${WATCHCLAW_INSTALL_DIR}/scripts/"
    fi
}

# ── Load config ───────────────────────────────────────────────────────────────
load_config() {
    if [ -f "$WATCHCLAW_CONF" ]; then
        source "$WATCHCLAW_CONF"
    elif [ -f "config/watchclaw.conf" ]; then
        source "config/watchclaw.conf"
        cp "config/watchclaw.conf" "$WATCHCLAW_CONF"
    elif [ -f "config/watchclaw.conf.example" ]; then
        cp "config/watchclaw.conf.example" "$WATCHCLAW_CONF"
        warn "Using example config. Edit /etc/watchclaw/watchclaw.conf for your setup."
        source "$WATCHCLAW_CONF"
    fi
}

# ── Module runner ─────────────────────────────────────────────────────────────
run_module() {
    local mod="$1"
    local mod_script="${WATCHCLAW_INSTALL_DIR}/modules/${mod}/install.sh"

    if [ ! -f "$mod_script" ]; then
        # Try local path (running from repo)
        mod_script="modules/${mod}/install.sh"
    fi

    if [ ! -f "$mod_script" ]; then
        warn "Module not found: $mod (skipping)"
        return 0
    fi

    log "Installing module: ${BOLD}${mod}${NC}"
    if $DRY_RUN; then
        echo "  [dry-run] Would run: $mod_script"
    else
        bash "$mod_script"
    fi
}

# ── Install CLI ───────────────────────────────────────────────────────────────
install_cli() {
    log "Installing WatchClaw CLI..."
    if $DRY_RUN; then
        echo "  [dry-run] Would install CLI to: $WATCHCLAW_BIN"
        return 0
    fi

    # Copy the CLI script from the repo (it's the canonical source)
    local src_cli
    src_cli="$(dirname "$0")/watchclaw"
    if [ -f "$src_cli" ]; then
        install -m 0755 "$src_cli" "$WATCHCLAW_BIN"
    else
        # Fallback: write inline CLI
        cat > "$WATCHCLAW_BIN" << 'CLIEOF'
#!/bin/bash
# WatchClaw CLI
WATCHCLAW_INSTALL_DIR="${WATCHCLAW_INSTALL_DIR:-/opt/watchclaw}"
WATCHCLAW_CONF="${WATCHCLAW_CONF:-/etc/watchclaw/watchclaw.conf}"
[ -f "$WATCHCLAW_CONF" ] && source "$WATCHCLAW_CONF"
SCRIPTS_DIR="${WATCHCLAW_INSTALL_DIR}/scripts"
LIB_DIR="${WATCHCLAW_INSTALL_DIR}/lib"
[ -f "${LIB_DIR}/watchclaw-lib.sh" ] && source "${LIB_DIR}/watchclaw-lib.sh" 2>/dev/null || true

cmd="${1:-help}"; shift 2>/dev/null || true
case "$cmd" in
    status)   bash "${SCRIPTS_DIR}/security-posture.sh" ;;
    report)   bash "${SCRIPTS_DIR}/watchclaw-weekly-report.sh" ;;
    score)    watchclaw_init; orca_get_score "${1:?Usage: watchclaw score <ip>}" ;;
    ban)      ip="${1:?Usage: watchclaw ban <ip>}"; watchclaw_init; watchclaw_record_event "$ip" "manual_ban" "via_cli" > /dev/null; watchclaw_check_and_ban "$ip"; /usr/sbin/ufw deny from "$ip" to any comment "watchclaw-manual" 2>/dev/null || true; echo "Banned $ip" ;;
    unban)    /usr/sbin/ufw delete deny from "${1:?Usage: watchclaw unban <ip>}" to any 2>/dev/null || true; echo "Unbanned $1" ;;
    health)   bash "${SCRIPTS_DIR}/service-healthcheck.sh" ;;
    selftest) bash "${SCRIPTS_DIR}/watchclaw-preflight.sh" ;;
    version)  echo "WatchClaw v$(cat "${WATCHCLAW_INSTALL_DIR}/VERSION" 2>/dev/null || echo unknown)" ;;
    help|--help|-h)
        echo "WatchClaw — Open Runtime Containment & Analysis"
        echo "Commands: status report score ban unban health selftest version help"
        ;;
    *) echo "Unknown command: $cmd. Run 'watchclaw help' for usage." >&2; exit 1 ;;
esac
CLIEOF
        chmod +x "$WATCHCLAW_BIN"
    fi
    echo "$WATCHCLAW_VERSION" > "${WATCHCLAW_INSTALL_DIR}/VERSION"
}

# ── Install crons ─────────────────────────────────────────────────────────────
install_crons() {
    log "Installing cron schedules..."

    # Determine which modules are active
    local cowrie_enabled=false
    [ -f /etc/systemd/system/cowrie.service ] && cowrie_enabled=true
    [ -d /home/cowrie/cowrie ] && cowrie_enabled=true

    if $DRY_RUN; then
        echo "  [dry-run] Would write /etc/cron.d/watchclaw with:"
        echo "    canary-check.sh        every 5 min"
        echo "    security-posture.sh    every 30 min"
        echo "    service-healthcheck.sh every 10 min"
        echo "    watchclaw-weekly-report.sh  Sunday 02:00"
        if $cowrie_enabled; then
            echo "    cowrie-autoban.sh      every 5 min  (cowrie module active)"
            echo "    cowrie-notify.sh       every 5 min  (cowrie module active)"
        fi
        return 0
    fi

    local cron_file="/etc/cron.d/watchclaw"
    cat > "$cron_file" << EOF
# WatchClaw Security — automated monitoring
# https://github.com/kashifeqbal/watchclaw
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin
WATCHCLAW_CONF=/etc/watchclaw/watchclaw.conf

# Canary token integrity check — every 5 min
*/5 * * * *  root ${WATCHCLAW_INSTALL_DIR}/scripts/canary-check.sh >> ${WATCHCLAW_LOG_DIR}/canary.log 2>&1

# Security posture report — every 30 min
*/30 * * * * root ${WATCHCLAW_INSTALL_DIR}/scripts/security-posture.sh >> ${WATCHCLAW_LOG_DIR}/posture.log 2>&1

# Service health check — every 10 min
*/10 * * * * root ${WATCHCLAW_INSTALL_DIR}/scripts/service-healthcheck.sh >> ${WATCHCLAW_LOG_DIR}/health.log 2>&1

# Weekly summary report — Sunday 02:00
0 2 * * 0    root ${WATCHCLAW_INSTALL_DIR}/scripts/watchclaw-weekly-report.sh >> ${WATCHCLAW_LOG_DIR}/weekly.log 2>&1
EOF

    if $cowrie_enabled; then
        cat >> "$cron_file" << EOF

# Cowrie auto-ban — every 5 min (cowrie module active)
*/5 * * * *  root ${WATCHCLAW_INSTALL_DIR}/scripts/cowrie-autoban.sh >> ${WATCHCLAW_LOG_DIR}/autoban.log 2>&1

# Cowrie event notifier — every 5 min (cowrie module active)
*/5 * * * *  root ${WATCHCLAW_INSTALL_DIR}/scripts/cowrie-notify.sh >> ${WATCHCLAW_LOG_DIR}/notify.log 2>&1
EOF
        log "Cowrie cron entries added (cowrie module detected)"
    fi

    if [ -n "${THREAT_FEEDS:-}" ]; then
        echo "" >> "$cron_file"
        echo "# Threat feed import" >> "$cron_file"
        echo "${CRON_FEED_IMPORT:-0 */6 * * *}  root ${WATCHCLAW_INSTALL_DIR}/scripts/watchclaw-import.sh >> ${WATCHCLAW_LOG_DIR}/import.log 2>&1" >> "$cron_file"
    fi

    if [ "${SYNC_ENABLE:-false}" = "true" ]; then
        echo "" >> "$cron_file"
        echo "# Cross-node threat sync" >> "$cron_file"
        echo "${CRON_SYNC:-*/15 * * * *}  root ${WATCHCLAW_INSTALL_DIR}/scripts/watchclaw-sync.sh >> ${WATCHCLAW_LOG_DIR}/sync.log 2>&1" >> "$cron_file"
    fi

    chmod 644 "$cron_file"
    log "Cron schedule written to $cron_file"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    banner
    preflight
    load_config
    setup_dirs

    # Determine modules to install
    local ALL_MODULES="ssh-harden ufw-baseline fail2ban cowrie kernel canary threat-feed"
    if [ "$MODE" = "agents" ]; then
        ALL_MODULES="$ALL_MODULES openclaw"
    fi

    local modules
    if [ -n "$MODULES_OVERRIDE" ]; then
        modules="${MODULES_OVERRIDE//,/ }"
    else
        modules="$ALL_MODULES"
    fi

    # Run each module
    for mod in $modules; do
        run_module "$mod"
    done

    # Install CLI and crons
    install_cli
    install_crons

    echo ""
    log "${BOLD}${GREEN}✅ WatchClaw installed successfully!${NC}"
    echo ""
    echo -e "  ${CYAN}watchclaw status${NC}     — check security posture"
    echo -e "  ${CYAN}watchclaw selftest${NC}   — verify everything works"
    echo -e "  ${CYAN}watchclaw help${NC}       — all commands"
    echo ""

    if [ -z "${ALERT_TELEGRAM_TOKEN:-}" ] && [ -z "${ALERT_DISCORD_WEBHOOK:-}" ] && [ -z "${ALERT_SLACK_WEBHOOK:-}" ]; then
        warn "No alert channel configured. Edit /etc/watchclaw/watchclaw.conf to add Telegram/Discord/Slack."
    fi
}

main "$@"
