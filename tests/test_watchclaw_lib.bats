#!/usr/bin/env bats
# =============================================================================
# tests/test_orca_lib.bats — Tests for lib/watchclaw-lib.sh
# =============================================================================
# Covers:
#   - watchclaw_init: directory and file creation
#   - watchclaw_record_event: per-event-type score deltas
#   - watchclaw_check_and_ban: ban tier thresholds
#   - Instant ban on login_success (honeypot)
#   - Recon cap: max 30 pts per IP per 30m
#   - Score decay via watchclaw_decay_all (10%/24h)
#   - orca_get_score
#   - orca_prune_db
#   - orca_rolling_score
# =============================================================================

load "helpers"

setup() {
    setup_orca_env
}

teardown() {
    teardown_orca_env
}

# ── watchclaw_init ─────────────────────────────────────────────────────────────────

@test "watchclaw_init creates WATCHCLAW_DIR" {
    rm -rf "${WATCHCLAW_DIR}"
    watchclaw_init
    [ -d "${WATCHCLAW_DIR}" ]
}

@test "watchclaw_init creates threat-db.json" {
    [ -f "${WATCHCLAW_DB}" ]
    run jq '.' "${WATCHCLAW_DB}"
    [ "$status" -eq 0 ]
}

@test "watchclaw_init creates reputation-cache.json" {
    [ -f "${ORCA_REP_CACHE}" ]
}

@test "watchclaw_init creates asn-db.json" {
    [ -f "${ORCA_ASN_DB}" ]
}

@test "watchclaw_init creates geo-db.json with expected shape" {
    [ -f "${ORCA_GEO_DB}" ]
    run jq '.countries' "${ORCA_GEO_DB}"
    [ "$status" -eq 0 ]
}

@test "watchclaw_init creates watchclaw-state.json with alert_rates key" {
    [ -f "${WATCHCLAW_STATE}" ]
    run jq '.alert_rates' "${WATCHCLAW_STATE}"
    [ "$status" -eq 0 ]
}

@test "watchclaw_init is idempotent (safe to call multiple times)" {
    watchclaw_init
    watchclaw_init
    run jq '.' "${WATCHCLAW_DB}"
    [ "$status" -eq 0 ]
}

# ── Score map: event type deltas ──────────────────────────────────────────────

@test "failed_login adds 1 point" {
    run watchclaw_record_event "1.2.3.4" "failed_login"
    [ "$status" -eq 0 ]
    score=$(db_score "1.2.3.4")
    assert_approx_eq "$score" "1" "0.1" "failed_login score"
}

@test "login_success adds 5 points" {
    run watchclaw_record_event "1.2.3.5" "login_success"
    [ "$status" -eq 0 ]
    score=$(db_score "1.2.3.5")
    assert_approx_eq "$score" "5" "0.1" "login_success score"
}

@test "command_exec adds 5 points" {
    run watchclaw_record_event "1.2.3.6" "command_exec"
    [ "$status" -eq 0 ]
    score=$(db_score "1.2.3.6")
    assert_approx_eq "$score" "5" "0.1" "command_exec score"
}

@test "recon_fingerprint adds 3 points" {
    run watchclaw_record_event "1.2.3.7" "recon_fingerprint"
    [ "$status" -eq 0 ]
    score=$(db_score "1.2.3.7")
    assert_approx_eq "$score" "3" "0.1" "recon_fingerprint score"
}

@test "tunnel_tcpip adds 20 points" {
    run watchclaw_record_event "1.2.3.8" "tunnel_tcpip"
    [ "$status" -eq 0 ]
    score=$(db_score "1.2.3.8")
    assert_approx_eq "$score" "20" "0.1" "tunnel_tcpip score"
}

@test "persistence_attempt adds 50 points" {
    run watchclaw_record_event "1.2.3.9" "persistence_attempt"
    [ "$status" -eq 0 ]
    score=$(db_score "1.2.3.9")
    assert_approx_eq "$score" "50" "0.1" "persistence_attempt score"
}

@test "malware_download adds 75 points" {
    run watchclaw_record_event "1.2.3.10" "malware_download"
    [ "$status" -eq 0 ]
    score=$(db_score "1.2.3.10")
    assert_approx_eq "$score" "75" "0.1" "malware_download score"
}

@test "multiple events accumulate score" {
    watchclaw_record_event "10.0.0.1" "failed_login"   # +1
    watchclaw_record_event "10.0.0.1" "failed_login"   # +1
    watchclaw_record_event "10.0.0.1" "failed_login"   # +1
    score=$(db_score "10.0.0.1")
    assert_approx_eq "$score" "3" "0.1" "accumulated failed_login score"
}

@test "unknown event type defaults to 1 point" {
    run watchclaw_record_event "10.0.0.2" "unknown_event_xyz"
    [ "$status" -eq 0 ]
    score=$(db_score "10.0.0.2")
    assert_approx_eq "$score" "1" "0.1" "unknown event score"
}

@test "event_types counter is updated" {
    watchclaw_record_event "10.0.0.3" "failed_login"
    watchclaw_record_event "10.0.0.3" "failed_login"
    count=$(db_event_count "10.0.0.3" "failed_login")
    [ "$count" -eq 2 ]
}

# ── Ban thresholds ────────────────────────────────────────────────────────────

@test "score < 25 results in no ban" {
    # 3 x failed_login = 3 pts
    watchclaw_record_event "20.0.0.1" "failed_login"
    watchclaw_record_event "20.0.0.1" "failed_login"
    watchclaw_record_event "20.0.0.1" "failed_login"
    run watchclaw_check_and_ban "20.0.0.1"
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "score >= 25 triggers short ban" {
    # 5 x command_exec = 25 pts
    for i in $(seq 1 5); do
        watchclaw_record_event "20.0.0.2" "command_exec"
    done
    run watchclaw_check_and_ban "20.0.0.2"
    [ "$status" -eq 0 ]
    [ "$output" = "short" ]
}

@test "score >= 75 triggers long ban" {
    # malware_download = 75 pts
    watchclaw_record_event "20.0.0.3" "malware_download"
    run watchclaw_check_and_ban "20.0.0.3"
    [ "$status" -eq 0 ]
    [ "$output" = "long" ]
}

@test "score >= 150 triggers permanent ban" {
    # 2 x malware_download = 150 pts
    watchclaw_record_event "20.0.0.4" "malware_download"
    watchclaw_record_event "20.0.0.4" "malware_download"
    run watchclaw_check_and_ban "20.0.0.4"
    [ "$status" -eq 0 ]
    [ "$output" = "permanent" ]
}

@test "ban tier escalates: existing short ban upgraded to long" {
    # Inject a record that already has a short ban and score in the 25-74 range.
    # This bypasses watchclaw_record_event so we avoid the double-penalty-during-active-ban
    # which would otherwise push the score past 150 (permanent) in one event.
    local now_iso
    now_iso=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    local expires_iso
    expires_iso=$(date -u -d '+24 hours' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
                  || date -u -v+24H '+%Y-%m-%dT%H:%M:%SZ')
    db_inject "20.0.0.5" "{
      \"first_seen\": \"${now_iso}\",
      \"last_seen\": \"${now_iso}\",
      \"total_events\": 5,
      \"score\": 80,
      \"raw_score\": 80,
      \"classification\": \"unknown\",
      \"bans\": [{\"type\": \"short\", \"active\": true, \"at\": \"${now_iso}\", \"expires\": \"${expires_iso}\", \"ufw_applied\": false, \"score_at_ban\": 25}],
      \"event_types\": {\"command_exec\": 5},
      \"score_events\": [],
      \"windows\": []
    }"
    # Score is 80 (>= 75), active ban is short → should escalate to long
    run watchclaw_check_and_ban "20.0.0.5"
    [ "$status" -eq 0 ]
    [ "$output" = "long" ]
}

@test "watchclaw_check_and_ban returns none for unknown IP" {
    run watchclaw_check_and_ban "99.99.99.99"
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "active_ban field is set to true in DB after ban" {
    watchclaw_record_event "20.0.0.6" "malware_download"
    watchclaw_check_and_ban "20.0.0.6"
    ban_type=$(db_active_ban "20.0.0.6")
    [ "$ban_type" = "long" ]
}

# ── Instant ban on login_success (honeypot) ───────────────────────────────────

@test "login_success triggers instant short ban regardless of score" {
    # Only 5 pts — below the normal 25-pt threshold for short ban
    watchclaw_record_event "30.0.0.1" "login_success"
    run watchclaw_check_and_ban "30.0.0.1"
    [ "$status" -eq 0 ]
    # Should be short (not none) even though score is only 5
    [ "$output" != "none" ]
}

@test "login_success + high score escalates to long ban" {
    # 5 + 75 = 80 pts — should get long ban
    watchclaw_record_event "30.0.0.2" "login_success"
    watchclaw_record_event "30.0.0.2" "malware_download"
    run watchclaw_check_and_ban "30.0.0.2"
    [ "$status" -eq 0 ]
    [ "$output" = "long" ]
}

@test "login_success + very high score escalates to permanent ban" {
    # 5 + 75 + 75 = 155 pts — permanent
    watchclaw_record_event "30.0.0.3" "login_success"
    watchclaw_record_event "30.0.0.3" "malware_download"
    watchclaw_record_event "30.0.0.3" "malware_download"
    run watchclaw_check_and_ban "30.0.0.3"
    [ "$status" -eq 0 ]
    [ "$output" = "permanent" ]
}

@test "multiple login_success events are tracked in event_types" {
    watchclaw_record_event "30.0.0.4" "login_success"
    watchclaw_record_event "30.0.0.4" "login_success"
    count=$(db_event_count "30.0.0.4" "login_success")
    [ "$count" -eq 2 ]
}

# ── Recon cap: max 30 pts per IP per 30m ──────────────────────────────────────

@test "recon_fingerprint score is capped at 30 pts per IP in 30m window" {
    # 11 recon events x 3 pts = 33 potential, but cap is 30
    for i in $(seq 1 11); do
        watchclaw_record_event "40.0.0.1" "recon_fingerprint"
    done
    score=$(db_score "40.0.0.1")
    # Score must not exceed 30 from recon alone
    assert_le "$score" "30.1" "recon capped score"
}

@test "recon cap is exactly 30 points (10 events x 3pts)" {
    for i in $(seq 1 10); do
        watchclaw_record_event "40.0.0.2" "recon_fingerprint"
    done
    score=$(db_score "40.0.0.2")
    assert_approx_eq "$score" "30" "0.5" "recon 10 events score"
}

@test "recon cap does not affect non-recon events" {
    # Fill up recon cap
    for i in $(seq 1 11); do
        watchclaw_record_event "40.0.0.3" "recon_fingerprint"
    done
    # Now add a tunnel event — should not be capped
    watchclaw_record_event "40.0.0.3" "tunnel_tcpip"
    score=$(db_score "40.0.0.3")
    # Total should be ~50 (capped recon 30 + tunnel 20)
    assert_ge "$score" "49" "recon cap + tunnel score"
}

@test "11th recon event adds 0 pts when cap reached" {
    # Record exactly 10 recon events to hit cap
    for i in $(seq 1 10); do
        watchclaw_record_event "40.0.0.4" "recon_fingerprint"
    done
    score_at_cap=$(db_score "40.0.0.4")
    # Add one more — should add 0
    watchclaw_record_event "40.0.0.4" "recon_fingerprint"
    score_after=$(db_score "40.0.0.4")
    # Score should not increase
    assert_approx_eq "$score_at_cap" "$score_after" "0.1" "recon no-op after cap"
}

# ── Score decay ───────────────────────────────────────────────────────────────

@test "watchclaw_decay_all reduces scores after 24h" {
    watchclaw_record_event "50.0.0.1" "malware_download"  # 75 pts
    # Fake last_seen to 25h ago
    db_set_last_seen_hours_ago "50.0.0.1" 25
    run watchclaw_decay_all
    [ "$status" -eq 0 ]
    score=$(db_score "50.0.0.1")
    # After ~1 day of decay: 75 * (1 - 0.10)^1 = 67.5
    assert_le "$score" "68" "decayed score"
    assert_ge "$score" "67" "decayed score floor"
}

@test "watchclaw_decay_all does not decay score unseen < 24h" {
    watchclaw_record_event "50.0.0.2" "malware_download"  # 75 pts
    # Fake last_seen to only 12h ago
    db_set_last_seen_hours_ago "50.0.0.2" 12
    watchclaw_decay_all
    score=$(db_score "50.0.0.2")
    # Should still be ~75
    assert_approx_eq "$score" "75" "1" "no-decay score"
}

@test "watchclaw_decay_all returns count of IPs decayed" {
    watchclaw_record_event "50.0.0.3" "failed_login"
    db_set_last_seen_hours_ago "50.0.0.3" 25
    watchclaw_record_event "50.0.0.4" "failed_login"
    db_set_last_seen_hours_ago "50.0.0.4" 25
    run watchclaw_decay_all
    [ "$status" -eq 0 ]
    # Should report at least 2 IPs decayed
    assert_ge "$output" "2" "IPs decayed count"
}

@test "score decays to 0 after many days, not negative" {
    watchclaw_record_event "50.0.0.5" "failed_login"  # 1 pt
    db_set_last_seen_hours_ago "50.0.0.5" 720    # 30 days ago
    watchclaw_decay_all
    score=$(db_score "50.0.0.5")
    assert_ge "$score" "0" "score non-negative after long decay"
}

@test "decay during watchclaw_record_event applies automatically" {
    watchclaw_record_event "50.0.0.6" "malware_download"  # 75 pts
    db_set_last_seen_hours_ago "50.0.0.6" 48
    # Record another event — this should apply 2-day decay first, then add delta
    watchclaw_record_event "50.0.0.6" "failed_login"  # +1 after decay
    score=$(db_score "50.0.0.6")
    # 75 * 0.90^2 + 1 = ~61.75
    assert_le "$score" "63" "in-event decay applied"
    assert_ge "$score" "60" "in-event decay floor"
}

# ── orca_get_score ────────────────────────────────────────────────────────────

@test "orca_get_score returns 0 for unknown IP" {
    run orca_get_score "99.88.77.66"
    [ "$status" -eq 0 ]
    assert_approx_eq "$output" "0" "0.1" "unknown IP score"
}

@test "orca_get_score returns correct score after event" {
    watchclaw_record_event "60.0.0.1" "tunnel_tcpip"
    run orca_get_score "60.0.0.1"
    [ "$status" -eq 0 ]
    assert_approx_eq "$output" "20" "0.1" "get_score after tunnel"
}

# ── orca_prune_db ─────────────────────────────────────────────────────────────

@test "orca_prune_db removes IPs unseen > 45 days" {
    watchclaw_record_event "70.0.0.1" "failed_login"
    db_set_last_seen_hours_ago "70.0.0.1" $((46 * 24))
    run orca_prune_db
    [ "$status" -eq 0 ]
    score=$(db_score "70.0.0.1")
    assert_approx_eq "$score" "0" "0.1" "pruned IP score"
}

@test "orca_prune_db keeps IPs seen within 45 days" {
    watchclaw_record_event "70.0.0.2" "malware_download"
    db_set_last_seen_hours_ago "70.0.0.2" $((44 * 24))
    run orca_prune_db
    [ "$status" -eq 0 ]
    score=$(db_score "70.0.0.2")
    # IP should still be in DB (score > 0)
    assert_ge "$score" "1" "kept IP score"
}

@test "orca_prune_db returns count of removed IPs" {
    watchclaw_record_event "70.0.0.3" "failed_login"
    db_set_last_seen_hours_ago "70.0.0.3" $((50 * 24))
    run orca_prune_db
    [ "$status" -eq 0 ]
    assert_ge "$output" "1" "prune count"
}

@test "orca_prune_db does not remove permanently banned IPs" {
    # Inject a permanent ban record with old last_seen
    local now_iso
    now_iso=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    db_inject "70.0.0.4" "{
      \"first_seen\": \"2020-01-01T00:00:00Z\",
      \"last_seen\": \"2020-01-01T00:00:00Z\",
      \"total_events\": 1,
      \"score\": 200,
      \"raw_score\": 200,
      \"bans\": [{\"type\": \"permanent\", \"active\": true, \"at\": \"2020-01-01T00:00:00Z\", \"expires\": null}],
      \"event_types\": {\"malware_download\": 1},
      \"score_events\": [],
      \"windows\": [],
      \"classification\": \"unknown\"
    }"
    run orca_prune_db
    [ "$status" -eq 0 ]
    # IP should still be present (permanent ban protects it)
    score=$(db_score "70.0.0.4")
    assert_ge "$score" "1" "permanently banned IP retained"
}

# ── orca_rolling_score ────────────────────────────────────────────────────────

@test "orca_rolling_score returns 0 with empty DB" {
    run orca_rolling_score 30
    [ "$status" -eq 0 ]
    assert_approx_eq "$output" "0" "0.1" "empty DB rolling score"
}

@test "orca_rolling_score includes recent event deltas" {
    watchclaw_record_event "80.0.0.1" "tunnel_tcpip"     # 20 pts
    watchclaw_record_event "80.0.0.1" "failed_login"     # 1 pt
    run orca_rolling_score 30
    [ "$status" -eq 0 ]
    assert_ge "$output" "20" "rolling score includes events"
}

@test "orca_rolling_score default window is 30 minutes" {
    watchclaw_record_event "80.0.0.2" "command_exec"
    run orca_rolling_score
    [ "$status" -eq 0 ]
    assert_ge "$output" "5" "default 30m rolling score"
}

# ── Double penalty for active ban ─────────────────────────────────────────────

@test "events during an active ban double the score delta" {
    # Get to 25pt for short ban
    for i in $(seq 1 5); do
        watchclaw_record_event "90.0.0.1" "command_exec"
    done
    watchclaw_check_and_ban "90.0.0.1"

    score_before=$(db_score "90.0.0.1")

    # Add one more failed_login — normally +1, but should be +2 during active ban
    watchclaw_record_event "90.0.0.1" "failed_login"
    score_after=$(db_score "90.0.0.1")

    delta=$(python3 -c "print(round(${score_after} - ${score_before}, 1))")
    assert_approx_eq "$delta" "2" "0.2" "double penalty delta"
}
