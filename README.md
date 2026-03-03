# 🐋 ORCA — Open Runtime Containment & Analysis

**One-command security hardening + threat intelligence for any Linux server.**

ORCA turns a naked VPS into a hardened, self-defending machine with real-time threat scoring, automated banning, honeypot deception, and cross-node threat sharing — in under 10 minutes.

```bash
curl -fsSL https://raw.githubusercontent.com/kashifeqbal/orca-security/main/install.sh | bash
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
orca install --standalone
```
Pure bash. Cron-driven. No dependencies beyond Python 3, UFW, fail2ban. Works on any Debian/Ubuntu VPS.

### With OpenClaw Agents
```bash
orca install --with-agents
```
Adds AI-powered analysis, natural language reports, RPC commands, and proactive threat hunting via OpenClaw.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/kashifeqbal/orca-security.git
cd orca-security

# 2. Configure
cp config/orca.conf.example config/orca.conf
nano config/orca.conf  # Set your SSH key, alert webhook, etc.

# 3. Install
sudo ./install.sh

# 4. Verify
orca status
```

## Architecture

```
┌─────────────────────────────────────────────┐
│                 ORCA Engine                   │
│  ┌─────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ Scoring  │ │ Ban      │ │ Threat Feed  │  │
│  │ Engine   │ │ Policy   │ │ Import/Export│  │
│  └────┬─────┘ └────┬─────┘ └──────┬───────┘  │
│       │            │               │          │
│  ┌────▼────────────▼───────────────▼───────┐  │
│  │           lib/orca-lib.sh               │  │
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
orca module enable cowrie        # SSH honeypot
orca module enable ssh-harden    # SSH hardening
orca module enable ufw-baseline  # Firewall rules
orca module enable fail2ban      # Brute-force protection
orca module enable kernel        # Kernel/sysctl hardening
orca module enable canary        # Tripwire canary tokens
orca module enable threat-feed   # Import/export threat intel
orca module enable sync          # Cross-node threat sharing
```

## Commands

```bash
orca status              # System health + security posture
orca report              # Full security report (plain English)
orca threats             # Active threats with scores
orca ban <ip>            # Manual ban
orca unban <ip>          # Remove ban
orca export              # Export blocklist (JSON + plaintext)
orca import              # Pull latest threat feeds
orca sync push           # Push threat DB to shared repo
orca sync pull           # Pull threat DB from shared repo
orca module list         # List installed modules
orca module enable <m>   # Enable a module
orca module disable <m>  # Disable a module
orca selftest            # Run all checks
```

## Alert Channels

```bash
# config/orca.conf
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

ORCA can export your threat intelligence as a public blocklist:

```bash
orca export --format=plaintext > blocklist.txt    # IP list
orca export --format=json > threat-feed.json      # Full intel
orca export --publish-github                       # Auto-push to GitHub Pages
```

Other ORCA users can import your feed:
```bash
# config/orca.conf
THREAT_FEEDS=(
    "https://raw.githubusercontent.com/kashifeqbal/orca-threats/main/blocklist.json"
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
