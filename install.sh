#!/bin/bash
# =============================================================================
# ORCA Installer — One-command security hardening for Linux servers
# =============================================================================
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/kashifeqbal/orca-security/main/install.sh | bash
#   # or
#   git clone https://github.com/kashifeqbal/orca-security.git && cd orca-security && sudo ./install.sh
#
# Options:
#   --standalone      Skip OpenClaw agent integration
#   --with-agents     Include OpenClaw agent integration
#   --modules=LIST    Comma-separated modules (default: all)
#   --dry-run         Show what would be done without doing it
#   --uninstall       Remove ORCA (keeps threat DB)
# =============================================================================

set -euo pipefail

ORCA_VERSION="1.0.0"
ORCA_REPO="https://github.com/kashifeqbal/orca-security.git"
ORCA_INSTALL_DIR="/opt/orca"
ORCA_STATE_DIR="/var/lib/orca"
ORCA_LOG_DIR="/var/log/orca"
ORCA_BIN="/usr/local/bin/orca"
ORCA_CONF="/etc/orca/orca.conf"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${GREEN}[ORCA]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'

     ██████╗ ██████╗  ██████╗ █████╗
    ██╔═══██╗██╔══██╗██╔════╝██╔══██╗
    ██║   ██║██████╔╝██║     ███████║
    ██║   ██║██╔══██╗██║     ██╔══██║
    ╚██████╔╝██║  ██║╚██████╗██║  ██║
     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝

    Open Runtime Containment & Analysis
EOF
    echo -e "${NC}"
    echo -e "    Version ${ORCA_VERSION}"
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
        err "ORCA must be run as root"
        exit 1
    fi

    if [ ! -f /etc/os-release ]; then
        err "Cannot detect OS. ORCA requires Debian/Ubuntu or RHEL/Rocky."
        exit 1
    fi

    source /etc/os-release
    case "$ID" in
        ubuntu|debian) PKG_MGR="apt" ;;
        centos|rhel|rocky|alma|fedora) PKG_MGR="dnf" ;;
        *) err "Unsupported OS: $ID. ORCA supports Debian/Ubuntu and RHEL/Rocky."; exit 1 ;;
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
    $DRY_RUN && return 0

    mkdir -p "$ORCA_INSTALL_DIR" "$ORCA_STATE_DIR" "$ORCA_LOG_DIR" /etc/orca
    mkdir -p "$ORCA_STATE_DIR"/{export,sync,canary}

    # Copy files if running from cloned repo
    if [ -f "$(dirname "$0")/lib/orca-lib.sh" ]; then
        cp -r "$(dirname "$0")"/{lib,modules,scripts,config} "$ORCA_INSTALL_DIR/"
    fi
}

# ── Load config ───────────────────────────────────────────────────────────────
load_config() {
    if [ -f "$ORCA_CONF" ]; then
        source "$ORCA_CONF"
    elif [ -f "config/orca.conf" ]; then
        source "config/orca.conf"
        cp "config/orca.conf" "$ORCA_CONF"
    elif [ -f "config/orca.conf.example" ]; then
        cp "config/orca.conf.example" "$ORCA_CONF"
        warn "Using example config. Edit /etc/orca/orca.conf for your setup."
        source "$ORCA_CONF"
    fi
}

# ── Module runner ─────────────────────────────────────────────────────────────
run_module() {
    local mod="$1"
    local mod_script="${ORCA_INSTALL_DIR}/modules/${mod}/install.sh"

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
    log "Installing ORCA CLI..."
    $DRY_RUN && return 0

    cat > "$ORCA_BIN" << 'CLIEOF'
#!/bin/bash
# ORCA CLI — wrapper for orca commands
set -euo pipefail

ORCA_DIR="/opt/orca"
ORCA_STATE="/var/lib/orca"
ORCA_CONF="/etc/orca/orca.conf"

[ -f "$ORCA_CONF" ] && source "$ORCA_CONF"
source "${ORCA_DIR}/lib/orca-lib.sh" 2>/dev/null || true

case "${1:-help}" in
    status)     bash "${ORCA_DIR}/scripts/security-posture.sh" ;;
    report)     bash "${ORCA_DIR}/scripts/security-posture.sh" --full ;;
    threats)    bash "${ORCA_DIR}/scripts/orca-threats.sh" ;;
    ban)        shift; bash "${ORCA_DIR}/scripts/orca-ban.sh" "$@" ;;
    unban)      shift; bash "${ORCA_DIR}/scripts/orca-unban.sh" "$@" ;;
    export)     shift; bash "${ORCA_DIR}/scripts/orca-export.sh" "$@" ;;
    import)     shift; bash "${ORCA_DIR}/scripts/orca-import.sh" "$@" ;;
    sync)       shift; bash "${ORCA_DIR}/scripts/orca-sync.sh" "$@" ;;
    selftest)   bash "${ORCA_DIR}/scripts/orca-selftest.sh" ;;
    module)
        shift
        case "${1:-list}" in
            list)    ls "${ORCA_DIR}/modules/" 2>/dev/null || echo "No modules" ;;
            enable)  shift; bash "${ORCA_DIR}/modules/$1/install.sh" ;;
            disable) shift; bash "${ORCA_DIR}/modules/$1/uninstall.sh" 2>/dev/null || echo "No uninstall for $1" ;;
        esac
        ;;
    version)    echo "ORCA v$(cat ${ORCA_DIR}/VERSION 2>/dev/null || echo unknown)" ;;
    help|--help|-h)
        echo "ORCA — Open Runtime Containment & Analysis"
        echo ""
        echo "Commands:"
        echo "  status          Security posture summary"
        echo "  report          Full security report"
        echo "  threats         List active threats with scores"
        echo "  ban <ip>        Manually ban an IP"
        echo "  unban <ip>      Remove a ban"
        echo "  export          Export threat blocklist"
        echo "  import          Import threat feeds"
        echo "  sync push|pull  Cross-node threat sync"
        echo "  module list     List modules"
        echo "  module enable   Enable a module"
        echo "  module disable  Disable a module"
        echo "  selftest        Run all checks"
        echo "  version         Show version"
        ;;
    *) echo "Unknown command: $1. Run 'orca help' for usage." ;;
esac
CLIEOF
    chmod +x "$ORCA_BIN"
    echo "$ORCA_VERSION" > "${ORCA_INSTALL_DIR}/VERSION"
}

# ── Install crons ─────────────────────────────────────────────────────────────
install_crons() {
    log "Installing cron schedules..."
    $DRY_RUN && return 0

    local cron_file="/etc/cron.d/orca"
    cat > "$cron_file" << EOF
# ORCA Security — automated monitoring
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin
ORCA_CONF=/etc/orca/orca.conf

${CRON_NOTIFY_INTERVAL:-*/15 * * * *}     root ${ORCA_INSTALL_DIR}/scripts/cowrie-notify.sh >> ${ORCA_LOG_DIR}/notify.log 2>&1
${CRON_AUTOBAN_INTERVAL:-*/15 * * * *}    root ${ORCA_INSTALL_DIR}/scripts/cowrie-autoban.sh >> ${ORCA_LOG_DIR}/autoban.log 2>&1
${CRON_POSTURE_INTERVAL:-*/30 * * * *}    root ${ORCA_INSTALL_DIR}/scripts/security-posture.sh >> ${ORCA_LOG_DIR}/posture.log 2>&1
${CRON_HEALTHCHECK_INTERVAL:-*/30 * * * *} root ${ORCA_INSTALL_DIR}/scripts/service-healthcheck.sh >> ${ORCA_LOG_DIR}/health.log 2>&1
${CRON_WEEKLY_REPORT:-0 9 * * 1}          root ${ORCA_INSTALL_DIR}/scripts/orca-weekly-report.sh >> ${ORCA_LOG_DIR}/weekly.log 2>&1
EOF

    if [ "${THREAT_FEEDS:-}" ]; then
        echo "${CRON_FEED_IMPORT:-0 */6 * * *}      root ${ORCA_INSTALL_DIR}/scripts/orca-import.sh >> ${ORCA_LOG_DIR}/import.log 2>&1" >> "$cron_file"
    fi

    if [ "${SYNC_ENABLE:-false}" = "true" ]; then
        echo "${CRON_SYNC:-*/15 * * * *}             root ${ORCA_INSTALL_DIR}/scripts/orca-sync.sh >> ${ORCA_LOG_DIR}/sync.log 2>&1" >> "$cron_file"
    fi

    chmod 644 "$cron_file"
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
    log "${BOLD}${GREEN}✅ ORCA installed successfully!${NC}"
    echo ""
    echo -e "  ${CYAN}orca status${NC}     — check security posture"
    echo -e "  ${CYAN}orca selftest${NC}   — verify everything works"
    echo -e "  ${CYAN}orca help${NC}       — all commands"
    echo ""

    if [ -z "${ALERT_TELEGRAM_TOKEN:-}" ] && [ -z "${ALERT_DISCORD_WEBHOOK:-}" ] && [ -z "${ALERT_SLACK_WEBHOOK:-}" ]; then
        warn "No alert channel configured. Edit /etc/orca/orca.conf to add Telegram/Discord/Slack."
    fi
}

main "$@"
