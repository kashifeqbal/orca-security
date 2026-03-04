#!/usr/bin/env bats
# =============================================================================
# tests/test_modules.bats — Tests for modules/*/install.sh
# =============================================================================
# Covers:
#   - Each module's install.sh has valid bash syntax
#   - Each module's install.sh starts with a shebang
#   - Each module's install.sh has a log() function defined
#   - Modules define expected config variables
#   - Module-specific structural checks
# =============================================================================

load "helpers"

# List of all expected modules
MODULES=(
    ssh-harden
    ufw-baseline
    fail2ban
    cowrie
    kernel
    canary
    threat-feed
    sync
)

setup() {
    TEST_TMPDIR="$(mktemp -d)"
}

teardown() {
    if [ -n "${TEST_TMPDIR:-}" ] && [ -d "${TEST_TMPDIR}" ]; then
        rm -rf "${TEST_TMPDIR}"
    fi
}

# ── Per-module bash syntax validation ─────────────────────────────────────────

@test "ssh-harden/install.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_MODULES_DIR}/ssh-harden/install.sh"
    [ "$status" -eq 0 ]
}

@test "ufw-baseline/install.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_MODULES_DIR}/ufw-baseline/install.sh"
    [ "$status" -eq 0 ]
}

@test "fail2ban/install.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_MODULES_DIR}/fail2ban/install.sh"
    [ "$status" -eq 0 ]
}

@test "cowrie/install.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_MODULES_DIR}/cowrie/install.sh"
    [ "$status" -eq 0 ]
}

@test "kernel/install.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_MODULES_DIR}/kernel/install.sh"
    [ "$status" -eq 0 ]
}

@test "canary/install.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_MODULES_DIR}/canary/install.sh"
    [ "$status" -eq 0 ]
}

@test "threat-feed/install.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_MODULES_DIR}/threat-feed/install.sh"
    [ "$status" -eq 0 ]
}

@test "sync/install.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_MODULES_DIR}/sync/install.sh"
    [ "$status" -eq 0 ]
}

# ── Shebang check ─────────────────────────────────────────────────────────────

@test "ssh-harden/install.sh starts with #!/bin/bash" {
    first_line=$(head -1 "${WATCHCLAW_MODULES_DIR}/ssh-harden/install.sh")
    [[ "$first_line" == "#!/bin/bash"* ]]
}

@test "ufw-baseline/install.sh starts with #!/bin/bash" {
    first_line=$(head -1 "${WATCHCLAW_MODULES_DIR}/ufw-baseline/install.sh")
    [[ "$first_line" == "#!/bin/bash"* ]]
}

@test "fail2ban/install.sh starts with #!/bin/bash" {
    first_line=$(head -1 "${WATCHCLAW_MODULES_DIR}/fail2ban/install.sh")
    [[ "$first_line" == "#!/bin/bash"* ]]
}

@test "cowrie/install.sh starts with #!/bin/bash" {
    first_line=$(head -1 "${WATCHCLAW_MODULES_DIR}/cowrie/install.sh")
    [[ "$first_line" == "#!/bin/bash"* ]]
}

@test "kernel/install.sh starts with #!/bin/bash" {
    first_line=$(head -1 "${WATCHCLAW_MODULES_DIR}/kernel/install.sh")
    [[ "$first_line" == "#!/bin/bash"* ]]
}

@test "canary/install.sh starts with #!/bin/bash" {
    first_line=$(head -1 "${WATCHCLAW_MODULES_DIR}/canary/install.sh")
    [[ "$first_line" == "#!/bin/bash"* ]]
}

@test "threat-feed/install.sh starts with #!/bin/bash" {
    first_line=$(head -1 "${WATCHCLAW_MODULES_DIR}/threat-feed/install.sh")
    [[ "$first_line" == "#!/bin/bash"* ]]
}

@test "sync/install.sh starts with #!/bin/bash" {
    first_line=$(head -1 "${WATCHCLAW_MODULES_DIR}/sync/install.sh")
    [[ "$first_line" == "#!/bin/bash"* ]]
}

# ── log() function defined ────────────────────────────────────────────────────

@test "ssh-harden/install.sh defines log() function" {
    grep -q 'log()' "${WATCHCLAW_MODULES_DIR}/ssh-harden/install.sh"
}

@test "ufw-baseline/install.sh defines log() function" {
    grep -q 'log()' "${WATCHCLAW_MODULES_DIR}/ufw-baseline/install.sh"
}

@test "fail2ban/install.sh defines log() function" {
    grep -q 'log()' "${WATCHCLAW_MODULES_DIR}/fail2ban/install.sh"
}

@test "cowrie/install.sh defines log() function" {
    grep -q 'log()' "${WATCHCLAW_MODULES_DIR}/cowrie/install.sh"
}

@test "kernel/install.sh defines log() function" {
    grep -q 'log()' "${WATCHCLAW_MODULES_DIR}/kernel/install.sh"
}

@test "canary/install.sh defines log() function" {
    grep -q 'log()' "${WATCHCLAW_MODULES_DIR}/canary/install.sh"
}

@test "threat-feed/install.sh defines log() function" {
    grep -q 'log()' "${WATCHCLAW_MODULES_DIR}/threat-feed/install.sh"
}

@test "sync/install.sh defines log() function" {
    grep -q 'log()' "${WATCHCLAW_MODULES_DIR}/sync/install.sh"
}

# ── Module-specific structural checks ────────────────────────────────────────

@test "ssh-harden: references SSH_PORT variable" {
    grep -q 'SSH_PORT' "${WATCHCLAW_MODULES_DIR}/ssh-harden/install.sh"
}

@test "ssh-harden: references sshd_config" {
    grep -q 'sshd_config' "${WATCHCLAW_MODULES_DIR}/ssh-harden/install.sh"
}

@test "ufw-baseline: references ufw command" {
    grep -q 'ufw' "${WATCHCLAW_MODULES_DIR}/ufw-baseline/install.sh"
}

@test "ufw-baseline: references SSH_PORT" {
    grep -q 'SSH_PORT' "${WATCHCLAW_MODULES_DIR}/ufw-baseline/install.sh"
}

@test "fail2ban: references fail2ban-client or fail2ban" {
    grep -qE 'fail2ban' "${WATCHCLAW_MODULES_DIR}/fail2ban/install.sh"
}

@test "fail2ban: creates jail.local configuration" {
    grep -q 'jail.local' "${WATCHCLAW_MODULES_DIR}/fail2ban/install.sh"
}

@test "cowrie: references honeypot or cowrie" {
    grep -qiE 'cowrie|honeypot' "${WATCHCLAW_MODULES_DIR}/cowrie/install.sh"
}

@test "kernel: references sysctl" {
    grep -q 'sysctl' "${WATCHCLAW_MODULES_DIR}/kernel/install.sh"
}

@test "canary: creates or references canary files" {
    grep -qiE 'canary|tripwire|token' "${WATCHCLAW_MODULES_DIR}/canary/install.sh"
}

@test "threat-feed: references threat feed import or URL" {
    grep -qiE 'feed|import|url|http' "${WATCHCLAW_MODULES_DIR}/threat-feed/install.sh"
}

@test "sync: references sync or rsync or remote" {
    grep -qiE 'sync|rsync|remote|ssh' "${WATCHCLAW_MODULES_DIR}/sync/install.sh"
}

# ── set -euo pipefail safety ──────────────────────────────────────────────────

@test "ssh-harden/install.sh uses set -euo pipefail" {
    grep -q 'set -euo pipefail' "${WATCHCLAW_MODULES_DIR}/ssh-harden/install.sh"
}

@test "ufw-baseline/install.sh uses set -euo pipefail" {
    grep -q 'set -euo pipefail' "${WATCHCLAW_MODULES_DIR}/ufw-baseline/install.sh"
}

@test "fail2ban/install.sh uses set -euo pipefail" {
    grep -q 'set -euo pipefail' "${WATCHCLAW_MODULES_DIR}/fail2ban/install.sh"
}

@test "cowrie/install.sh uses set -euo pipefail" {
    grep -q 'set -euo pipefail' "${WATCHCLAW_MODULES_DIR}/cowrie/install.sh"
}

@test "kernel/install.sh uses set -euo pipefail" {
    grep -q 'set -euo pipefail' "${WATCHCLAW_MODULES_DIR}/kernel/install.sh"
}

@test "canary/install.sh uses set -euo pipefail" {
    grep -q 'set -euo pipefail' "${WATCHCLAW_MODULES_DIR}/canary/install.sh"
}

# ── lib/watchclaw-lib.sh checks ────────────────────────────────────────────────────

@test "watchclaw-lib.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
    [ "$status" -eq 0 ]
}

@test "watchclaw-lib.sh exports watchclaw_init function" {
    grep -q 'watchclaw_init()' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
}

@test "watchclaw-lib.sh exports watchclaw_record_event function" {
    grep -q 'watchclaw_record_event()' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
}

@test "watchclaw-lib.sh exports watchclaw_check_and_ban function" {
    grep -q 'watchclaw_check_and_ban()' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
}

@test "watchclaw-lib.sh exports watchclaw_decay_all function" {
    grep -q 'watchclaw_decay_all()' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
}

@test "watchclaw-lib.sh exports orca_prune_db function" {
    grep -q 'orca_prune_db()' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
}

@test "watchclaw-lib.sh exports orca_get_score function" {
    grep -q 'orca_get_score()' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
}

@test "watchclaw-lib.sh exports orca_rolling_score function" {
    grep -q 'orca_rolling_score()' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
}

@test "watchclaw-lib.sh exports orca_telegram function" {
    grep -q 'orca_telegram()' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
}

@test "watchclaw-lib.sh defines backward-compat argus aliases" {
    grep -q 'argus_init()' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
    grep -q 'threat_record_event()' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
    grep -q 'threat_check_and_ban()' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
}

@test "watchclaw-lib.sh SCORE_MAP includes all required event types" {
    grep -q 'failed_login' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
    grep -q 'login_success' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
    grep -q 'command_exec' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
    grep -q 'recon_fingerprint' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
    grep -q 'tunnel_tcpip' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
    grep -q 'persistence_attempt' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
    grep -q 'malware_download' "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
}

@test "watchclaw-lib.sh defines DECAY_RATE = 0.10" {
    grep -q "DECAY_RATE.*0.10" "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
}

@test "watchclaw-lib.sh defines RECON_CAP_POINTS_30M = 30" {
    grep -q "RECON_CAP_POINTS_30M.*30" "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-lib.sh"
}

# ── scripts/ syntax checks ────────────────────────────────────────────────────

@test "scripts/cowrie-autoban.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_REPO_ROOT}/scripts/cowrie-autoban.sh"
    [ "$status" -eq 0 ]
}

@test "scripts/cowrie-notify.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_REPO_ROOT}/scripts/cowrie-notify.sh"
    [ "$status" -eq 0 ]
}

@test "scripts/security-posture.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_REPO_ROOT}/scripts/security-posture.sh"
    [ "$status" -eq 0 ]
}

@test "scripts/watchclaw-weekly-report.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_REPO_ROOT}/scripts/watchclaw-weekly-report.sh"
    [ "$status" -eq 0 ]
}

@test "scripts/canary-check.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_REPO_ROOT}/scripts/canary-check.sh"
    [ "$status" -eq 0 ]
}

@test "scripts/service-healthcheck.sh passes bash syntax check" {
    run bash -n "${WATCHCLAW_REPO_ROOT}/scripts/service-healthcheck.sh"
    [ "$status" -eq 0 ]
}
