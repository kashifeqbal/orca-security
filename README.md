# 🐋 WatchClaw — Open Runtime Containment & Analysis

**One-command security hardening + threat intelligence for any Linux server.**

WatchClaw turns a naked VPS into a hardened, self-defending machine with real-time threat scoring, automated banning, honeypot deception, and cross-node threat sharing — in under 10 minutes.

```bash
curl -fsSL https://raw.githubusercontent.com/kashifeqbal/watchclaw/main/install.sh | bash
```

---

## What You Get

| Layer | What It Does |
|-------|-------------|
| **SSH Hardening** | Move SSH to random high port, key-only auth, disable root password |
| **Firewall** | UFW baseline with sane defaults, rate limiting |
| **Honeypot** | Cowrie SSH honeypot on port 22 (catches attackers thinking it's real SSH) |
| **Fail2ban** | Auto-ban failed logins on real SSH |
| **Threat Scoring** | Every attacker IP scored by behavior: recon, login, commands, tunnels, malware |
| **Auto-Ban Policy** | Score ≥25 → 24h ban, ≥75 → 7d, ≥150 → permanent. Honeypot login = instant ban |
| **Kernel Hardening** | TCP stack hardening, SYN flood protection, disable unused protocols |
| **Canary Tokens** | Tripwire files in sensitive dirs — alerts if touched |
| **Threat Feed** | Import from AbuseIPDB/blocklist.de, export your own public blocklist |
| **Cross-Node Sync** | Share threat intel across your fleet — ban on one, ban on all |
| **Alerts** | Telegram, Discord, Slack, or plain webhook |
| **Reports** | Plain-English security reports anyone can understand |

## Modes

### Standalone (no agents)
```bash
watchclaw install --standalone
```
Pure bash. Cron-driven. No dependencies beyond Python 3, UFW, fail2ban. Works on any Debian/Ubuntu VPS.

### With OpenClaw Agents
```bash
watchclaw install --with-agents
```
Adds AI-powered analysis, natural language reports, RPC commands, and proactive threat hunting via OpenClaw.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/kashifeqbal/watchclaw.git
cd watchclaw

# 2. Configure
cp config/watchclaw.conf.example config/watchclaw.conf
nano config/watchclaw.conf  # Set your SSH key, alert webhook, etc.

# 3. Install
sudo ./install.sh

# 4. Verify
watchclaw status
```

## Architecture

```
┌─────────────────────────────────────────────┐
│                 WatchClaw Engine                   │
│  ┌─────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ Scoring  │ │ Ban      │ │ Threat Feed  │  │
│  │ Engine   │ │ Policy   │ │ Import/Export│  │
│  └────┬─────┘ └────┬─────┘ └──────┬───────┘  │
│       │            │               │          │
│  ┌────▼────────────▼───────────────▼───────┐  │
│  │           lib/watchclaw-lib.sh               │  │
│  │     (core: state, scoring, bans)        │  │
│  └─────────────────────────────────────────┘  │
└──────────────┬──────────────────┬─────────────┘
               │                  │
    ┌──────────▼──────┐  ┌───────▼────────┐
    │   Modules        │  │   Alerts       │
    │ ┌──────────────┐ │  │ • Telegram     │
    │ │ cowrie       │ │  │ • Discord      │
    │ │ ssh-harden   │ │  │ • Slack        │
    │ │ ufw-baseline │ │  │ • Webhook      │
    │ │ fail2ban     │ │  │ • Email        │
    │ │ kernel       │ │  └────────────────┘
    │ │ canary       │ │
    │ │ threat-feed  │ │  ┌────────────────┐
    │ │ sync         │ │  │  Cross-Node    │
    │ └──────────────┘ │  │  Threat Sync   │
    └──────────────────┘  │  (Git/API)     │
                          └────────────────┘
```

## Modules

Each module is independent. Install what you need:

```bash
watchclaw module enable cowrie        # SSH honeypot
watchclaw module enable ssh-harden    # SSH hardening
watchclaw module enable ufw-baseline  # Firewall rules
watchclaw module enable fail2ban      # Brute-force protection
watchclaw module enable kernel        # Kernel/sysctl hardening
watchclaw module enable canary        # Tripwire canary tokens
watchclaw module enable threat-feed   # Import/export threat intel
watchclaw module enable sync          # Cross-node threat sharing
```

## Commands

```bash
watchclaw status              # System health + security posture
watchclaw report              # Full security report (plain English)
watchclaw threats             # Active threats with scores
watchclaw ban <ip>            # Manual ban
watchclaw unban <ip>          # Remove ban
watchclaw export              # Export blocklist (JSON + plaintext)
watchclaw import              # Pull latest threat feeds
watchclaw sync push           # Push threat DB to shared repo
watchclaw sync pull           # Pull threat DB from shared repo
watchclaw module list         # List installed modules
watchclaw module enable <m>   # Enable a module
watchclaw module disable <m>  # Disable a module
watchclaw selftest            # Run all checks
```

## Alert Channels

```bash
# config/watchclaw.conf
ALERT_TELEGRAM_TOKEN="your-bot-token"
ALERT_TELEGRAM_CHAT="-1001234567890"

# Or Discord
ALERT_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."

# Or Slack
ALERT_SLACK_WEBHOOK="https://hooks.slack.com/services/..."

# Or generic webhook
ALERT_WEBHOOK_URL="https://your-endpoint.com/alerts"
```

## Public Threat Feed

WatchClaw can export your threat intelligence as a public blocklist:

```bash
watchclaw export --format=plaintext > blocklist.txt    # IP list
watchclaw export --format=json > threat-feed.json      # Full intel
watchclaw export --publish-github                       # Auto-push to GitHub Pages
```

Other WatchClaw users can import your feed:
```bash
# config/watchclaw.conf
THREAT_FEEDS=(
    "https://raw.githubusercontent.com/kashifeqbal/watchclaw-threats/main/blocklist.json"
    "https://lists.blocklist.de/lists/ssh.txt"
)
```

## Requirements

- Debian/Ubuntu (20.04+) or RHEL/Rocky/Alma (8+)
- Python 3.8+
- Root access
- Public IP (for honeypot to be useful)

## Roadmap

- [x] Core scoring engine
- [x] Cowrie integration
- [x] UFW + fail2ban automation
- [x] SSH hardening
- [x] Telegram alerts
- [x] Plain-English reports
- [x] Auto-ban policy (score-based + instant honeypot-login ban)
- [ ] One-command installer
- [ ] Kernel/sysctl hardening module
- [ ] Canary token module
- [ ] AbuseIPDB / blocklist.de import
- [ ] Public blocklist export
- [ ] Cross-node sync (Git-based)
- [ ] Cross-node sync (API-based)
- [ ] Discord / Slack / webhook alerts
- [ ] Web dashboard (optional)
- [ ] ARM/Raspberry Pi support
- [ ] Ansible playbook alternative
- [ ] OpenClaw agent integration module
- [ ] GeoIP blocking policy
- [ ] ASN-level blocking
- [ ] Automated threat hunting
- [ ] Weekly PDF reports
- [ ] Integration with CrowdSec / Wazuh feeds

## License

MIT — use it, fork it, deploy it everywhere.

---

**Built by [Kashif Eqbal](https://github.com/kashifeqbal)** — born from running a $14 VPS and refusing to let bots win.
