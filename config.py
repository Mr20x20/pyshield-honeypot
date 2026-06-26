"""
config.py — PyShield Honeypot
Central configuration. All other modules import from here.
Change settings here only — never hardcode values elsewhere.
"""

from pathlib import Path

# ── Project root ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.resolve()

# ── Directories ───────────────────────────────────────────────────────────────
DATA_DIR = BASE_DIR / "data"
LOG_DIR  = BASE_DIR / "logs"

# Auto-created by run.py on startup — don't create manually
DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

# ── Database ──────────────────────────────────────────────────────────────────
DB_PATH = DATA_DIR / "honeypot.db"

# ── Output report (consumed by project6 SIEM) ─────────────────────────────────
HONEYPOT_REPORT = DATA_DIR / "honeypot_report.json"

# ── Raw log file ──────────────────────────────────────────────────────────────
LOG_FILE = LOG_DIR / "honeypot.log"

# ── SSH Honeypot settings ─────────────────────────────────────────────────────
# Port 2222 instead of 22 — real SSH likely runs on 22 on your machine.
# Attackers scanning port 2222 are specifically looking for misconfigured
# or backup SSH services, which is realistic honeypot behavior.
SSH_HOST = "0.0.0.0"     # listen on all interfaces
SSH_PORT = 2222

# RSA host key for the fake SSH server (paramiko needs this to complete
# the SSH handshake before the attacker even tries to log in)
SSH_HOST_KEY = DATA_DIR / "ssh_host_rsa.key"

# Fake banner — makes the honeypot look like a real Ubuntu server
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

# Always reject logins — but log every attempt first
SSH_AUTH_ALWAYS_FAIL = True

# How long to keep the connection open after a failed attempt (seconds)
# Longer = attacker tries more passwords = more intelligence gathered
SSH_LINGER_SECONDS = 2

# ── HTTP Honeypot settings ────────────────────────────────────────────────────
# Port 8080 — mimics a web admin panel or misconfigured web server
HTTP_HOST = "0.0.0.0"
HTTP_PORT = 8888

# Fake server header — makes it look like a real nginx server
HTTP_SERVER_HEADER = "nginx/1.24.0"

# ── Profiler settings ─────────────────────────────────────────────────────────
# How many failed attempts from one IP before it's flagged as a threat
THREAT_THRESHOLD_SSH  = 3
THREAT_THRESHOLD_HTTP = 10

# How many top attackers to include in the report
TOP_ATTACKERS_LIMIT = 20

# ── Reporter settings ─────────────────────────────────────────────────────────
# How often reporter rewrites honeypot_report.json (seconds)
REPORT_INTERVAL = 30

# Max events to include in the report (most recent N)
MAX_REPORT_EVENTS = 100

# ── Geolocation ───────────────────────────────────────────────────────────────
# Uses ip-api.com free tier (no API key needed, 45 requests/minute limit)
# You can Set it to False if you're offline or want faster performance
ENABLE_GEOLOCATION = True
GEO_API_URL = "http://ip-api.com/json/{ip}?fields=country,city,isp,proxy,hosting"

# Private/loopback IPs — skip geolocation for these
GEO_SKIP_RANGES = [
    "127.", "192.168.", "10.", "172.16.", "172.17.",
    "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
    "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.", "0.0.0.0",
]
