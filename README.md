# 🍯 PyShield Honeypot — Attacker Profiler

A lightweight honeypot system with attacker profiling, built in pure Python. Deploys fake SSH and HTTP services that log every credential attempt, HTTP probe, and attack pattern — then exports a structured JSON report that feeds directly into the PyShield SIEM pipeline.

---

## 📸 Preview

```
22:04:24 [INFO] honeypot: SSH attempt: 185.220.101.47:51234 tried user='root' pass='123456'
22:04:25 [INFO] honeypot: HTTP request: 185.220.101.47:51235 GET /wp-admin (UA: masscan/1.3)
22:04:55 [INFO] honeypot.reporter: Report written → score=42 | events=18 | attackers=3
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│               PyShield Honeypot                     │
│                                                     │
│  ┌──────────────────┐   ┌──────────────────────┐   │
│  │  SSH Honeypot    │   │   HTTP Honeypot       │   │
│  │  port 2222       │   │   port 8888           │   │
│  │                  │   │                       │   │
│  │  fake OpenSSH    │   │  fake admin panel     │   │
│  │  logs every      │   │  logs every path,     │   │
│  │  user+pass tried │   │  method, user-agent   │   │
│  └────────┬─────────┘   └──────────┬────────────┘   │
│           └──────────┬─────────────┘                │
│                      ▼                              │
│              ┌───────────────┐                      │
│              │  database.py  │                      │
│              │  SQLite WAL   │                      │
│              │  events table │                      │
│              │  profiles     │                      │
│              └───────┬───────┘                      │
│                      ▼                              │
│              ┌───────────────┐                      │
│              │  profiler.py  │                      │
│              │  geolocation  │                      │
│              │  pattern      │                      │
│              │  detection    │                      │
│              └───────┬───────┘                      │
│                      ▼                              │
│              ┌───────────────┐                      │
│              │  reporter.py  │                      │
│              │  every 30s    │                      │
│              └───────┬───────┘                      │
│                      │                              │
└──────────────────────┼──────────────────────────────┘
                       ▼
            honeypot_report.json
                       │
                       ▼
         ┌─────────────────────────┐
         │   PyShield SIEM         │
         │   (project6 pipeline)   │
         └─────────────────────────┘
```

---

## 🔍 What It Detects

| Pattern | Description |
|---|---|
| `credential_stuffing` | Many unique username+password combinations |
| `password_spray` | Same password tried against many usernames |
| `dictionary_attack` | Sequential common passwords from known wordlists |
| `directory_traversal` | HTTP paths containing `../` or URL-encoded variants |
| `admin_panel_probe` | Probing `/wp-admin`, `/.env`, `/backup`, `/phpmyadmin` etc. |
| `automated_scanner` | Known scanner user-agents (masscan, nikto, nuclei, etc.) |

---

## 🌍 Attacker Profiling

Each unique attacker IP is enriched with:
- **Country, City** — geographic origin
- **ISP** — hosting provider or residential
- **Proxy / Tor** — anonymization detection
- **Threat Level** — LOW / MEDIUM / HIGH based on activity volume
- **Attack Patterns** — behavioral fingerprint

Geolocation uses [ip-api.com](http://ip-api.com) free tier — no API key required.

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Mr20x20/pyshield-honeypot.git
cd pyshield-honeypot
```

### 2. Create virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the honeypot

```bash
python run.py
```

### 5. Test it locally

```bash
# Test SSH honeypot (uses paramiko for reliable cross-platform testing)
python test_ssh.py

# Test HTTP honeypot
curl.exe -i http://127.0.0.1:8888/admin
```

---

## 📁 Project Structure

```
pyshield-honeypot/
├── run.py              # Entry point — starts all threads
├── honeypot.py         # Fake SSH + HTTP servers
├── profiler.py         # Geolocation + attack pattern detection
├── reporter.py         # Builds and writes honeypot_report.json
├── database.py         # SQLite persistence layer
├── config.py           # All settings in one place
├── test_ssh.py         # Local SSH honeypot test script
├── requirements.txt
└── data/               # Auto-created on first run (not in repo)
    ├── honeypot.db
    └── honeypot_report.json
```

---

## ⚙️ Configuration

All settings are in `config.py`:

| Setting | Default | Description |
|---|---|---|
| `SSH_PORT` | 2222 | Fake SSH listener port |
| `HTTP_PORT` | 8888 | Fake HTTP listener port |
| `REPORT_INTERVAL` | 30s | How often report is written |
| `THREAT_THRESHOLD_SSH` | 3 | Attempts before flagging as threat |
| `ENABLE_GEOLOCATION` | True | IP geolocation enrichment |
| `MAX_REPORT_EVENTS` | 100 | Events included per report |

---

## 🔗 SIEM Integration

`honeypot_report.json` is designed to be consumed by the
[PyShield Dashboard](https://github.com/Mr20x20/pyshield-dashboard)
as a 5th sensor source. The report schema matches the existing
SIEM pipeline format.

Triggered event names passed to the SIEM:

| Event | Meaning |
|---|---|
| `honeypot_ssh_attempts` | Any SSH credential attempts logged |
| `honeypot_http_probes` | Any HTTP requests to fake panel |
| `honeypot_brute_force` | 10+ SSH attempts detected |
| `honeypot_multiple_sources` | 5+ unique attacker IPs |
| `honeypot_proxy_detected` | Attacker using proxy or Tor |
| `honeypot_credential_stuffing` | Credential stuffing pattern |
| `honeypot_password_spray` | Password spray pattern |
| `honeypot_directory_traversal` | Path traversal attempt |
| `honeypot_automated_scanner` | Known scanner tool detected |

---

## 📡 Output Schema

```json
{
  "source": "honeypot",
  "timestamp": "2026-06-22 22:04:55",
  "risk_score": 42,
  "stats": {
    "total_events": 18,
    "unique_ips": 3,
    "ssh_attempts": 14,
    "http_requests": 4,
    "top_usernames": [{"username": "root", "cnt": 6}],
    "top_passwords": [{"password": "123456", "cnt": 4}],
    "top_paths": [{"http_path": "/wp-admin", "cnt": 2}]
  },
  "triggered_events": ["honeypot_brute_force", "honeypot_proxy_detected"],
  "summary": ["• Honeypot: 18 total events from 3 unique IPs."],
  "top_attackers": [...],
  "recent_events": [...]
}
```

---

## 🔐 Security Notes

- This tool is designed for **authorized lab environments only**
- Never deploy on a public IP without understanding the legal implications
- Honeypot ports (2222, 8888) are non-privileged — no admin rights needed

---

## 🛠️ Tech Stack

- **Language:** Python 3.11+
- **SSH Protocol:** Paramiko
- **HTTP Server:** Raw Python sockets
- **Database:** SQLite with WAL mode
- **Geolocation:** ip-api.com (free tier)
- **Crypto:** cryptography (RSA host key via Paramiko)

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Mr20x20** — Security Engineering Enthusiast  
GitHub: [github.com/Mr20x20](https://github.com/Mr20x20)

---

## 🔗 Related Projects

- [PyShield Dashboard](https://github.com/Mr20x20/PyShield_Dashboard) — Real-time SIEM dashboard that consumes this honeypot's output
