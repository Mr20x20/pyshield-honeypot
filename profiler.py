"""
profiler.py — PyShield Honeypot
Analyzes raw events and builds per-IP attacker profiles.

Two responsibilities:
  1. Geolocation enrichment — looks up country/ISP for each new IP
  2. Behavior analysis — detects attack patterns across events
"""

import logging
import time
import requests
from datetime import datetime

import database as db
from config import (
    ENABLE_GEOLOCATION, GEO_API_URL, GEO_SKIP_RANGES,
    TOP_ATTACKERS_LIMIT,
)

logger = logging.getLogger("honeypot.profiler")

# Track which IPs we've already geolocated so we don't re-query
_geolocated_ips: set = set()


# ── Public API ────────────────────────────────────────────────────────────────
def enrich_ip(ip: str) -> None:
    """
    Look up geolocation for an IP and store it in the database.
    Skips private/loopback IPs and IPs already looked up.
    Called after each new attacker IP is first seen.
    """
    if not ENABLE_GEOLOCATION:
        return

    if ip in _geolocated_ips:
        return

    # Skip private ranges — no point geolocating 192.168.x.x
    if any(ip.startswith(r) for r in GEO_SKIP_RANGES):
        logger.debug("Skipping geolocation for private IP: %s", ip)
        _geolocated_ips.add(ip)
        return

    try:
        url      = GEO_API_URL.format(ip=ip)
        response = requests.get(url, timeout=5)
        data     = response.json()

        if data.get("status") == "fail":
            logger.debug("Geolocation failed for %s: %s", ip, data.get("message"))
            _geolocated_ips.add(ip)
            return

        db.update_geo(
            ip         = ip,
            country    = data.get("country", "Unknown"),
            city       = data.get("city", "Unknown"),
            isp        = data.get("isp", "Unknown"),
            is_proxy   = bool(data.get("proxy", False)),
            is_hosting = bool(data.get("hosting", False)),
        )

        logger.info(
            "Geolocated %s → %s, %s | ISP: %s | proxy=%s hosting=%s",
            ip,
            data.get("city", "?"),
            data.get("country", "?"),
            data.get("isp", "?"),
            data.get("proxy", False),
            data.get("hosting", False),
        )

        _geolocated_ips.add(ip)

        # Rate limit: ip-api.com allows 45 requests/minute on free tier
        # 1.5s delay keeps us safely under that
        time.sleep(1.5)

    except requests.exceptions.Timeout:
        logger.debug("Geolocation timeout for %s", ip)
    except requests.exceptions.ConnectionError:
        logger.debug("Geolocation connection error for %s", ip)
    except Exception as e:
        logger.debug("Geolocation error for %s: %s", ip, e)


def analyze_recent_attackers() -> list[dict]:
    """
    Fetch top attackers and enrich any that haven't been geolocated yet.
    Returns a list of enriched attacker profile dicts.
    Called by reporter.py before building the report.
    """
    attackers = db.get_top_attackers(limit=TOP_ATTACKERS_LIMIT)

    for attacker in attackers:
        ip = attacker["ip"]
        if ip not in _geolocated_ips:
            enrich_ip(ip)
            # Re-fetch profile after geo enrichment
            updated = db.get_profile(ip)
            if updated:
                attacker.update(updated)

    return attackers


def detect_patterns(ip: str) -> list[str]:
    """
    Analyze behavior patterns for a single IP.
    Returns a list of pattern labels detected.

    Patterns we detect:
      - credential_stuffing : many unique username/password combos
      - password_spray      : same password tried with many usernames
      - directory_traversal : HTTP paths containing ../
      - admin_panel_probe   : probing common admin paths
      - automated_scanner   : very high request rate, generic user agents
    """
    profile = db.get_profile(ip)
    if not profile:
        return []

    patterns    = []
    events      = db.get_recent_events(limit=500)
    ip_events   = [e for e in events if e["attacker_ip"] == ip]
    ssh_events  = [e for e in ip_events if e["service"] == "ssh"]
    http_events = [e for e in ip_events if e["service"] == "http"]

    # ── SSH patterns ──────────────────────────────────────────────
    if ssh_events:
        usernames = [e["username"] for e in ssh_events if e["username"]]
        passwords = [e["password"] for e in ssh_events if e["password"]]

        unique_u = len(set(usernames))
        unique_p = len(set(passwords))

        # Credential stuffing: many different user+pass combos
        if unique_u >= 5 and unique_p >= 5:
            patterns.append("credential_stuffing")

        # Password spray: same password tried against many usernames
        if unique_p <= 2 and unique_u >= 5:
            patterns.append("password_spray")

        # Dictionary attack: sequential common passwords
        common_passwords = {
            "123456", "password", "admin", "root", "12345678",
            "qwerty", "abc123", "letmein", "monkey", "1234567890"
        }
        if len(set(passwords) & common_passwords) >= 3:
            patterns.append("dictionary_attack")

    # ── HTTP patterns ─────────────────────────────────────────────
    if http_events:
        paths      = [e["http_path"] for e in http_events if e["http_path"]]
        user_agents = [e["user_agent"] for e in http_events if e["user_agent"]]

        # Directory traversal attempt
        if any("../" in p or "%2e%2e" in p.lower() for p in paths):
            patterns.append("directory_traversal")

        # Admin panel probing: hitting many admin-like paths
        admin_keywords = [
            "/admin", "/wp-admin", "/phpmyadmin", "/manager",
            "/.env", "/config", "/backup", "/shell", "/cmd"
        ]
        admin_hits = sum(
            1 for p in paths
            if any(kw in p.lower() for kw in admin_keywords)
        )
        if admin_hits >= 3:
            patterns.append("admin_panel_probe")

        # Automated scanner: generic scanner user agents
        scanner_agents = [
            "masscan", "zgrab", "nmap", "nikto", "sqlmap",
            "nuclei", "dirbuster", "gobuster", "python-requests"
        ]
        if any(
            any(sa in ua.lower() for sa in scanner_agents)
            for ua in user_agents if ua
        ):
            patterns.append("automated_scanner")

    return patterns


def build_summary(stats: dict, attackers: list[dict]) -> list[str]:
    """
    Build human-readable summary lines for the SIEM report.
    Same format as mini_siem2.py summary lines.
    """
    summary = []

    if stats["total_events"] == 0:
        return ["• Honeypot active. No attacks recorded yet."]

    summary.append(
        f"• Honeypot: {stats['total_events']} total events "
        f"from {stats['unique_ips']} unique IPs."
    )

    if stats["ssh_attempts"] > 0:
        summary.append(
            f"• SSH: {stats['ssh_attempts']} credential attempts logged."
        )

    if stats["http_requests"] > 0:
        summary.append(
            f"• HTTP: {stats['http_requests']} requests to fake admin panel."
        )

    # Top credentials
    if stats["top_usernames"]:
        top_u = stats["top_usernames"][0]
        summary.append(
            f"• Most tried username: '{top_u['username']}' "
            f"({top_u['cnt']} times)."
        )

    if stats["top_passwords"]:
        top_p = stats["top_passwords"][0]
        summary.append(
            f"• Most tried password: '{top_p['password']}' "
            f"({top_p['cnt']} times)."
        )

    # High threat attackers
    high_threat = [a for a in attackers if a.get("threat_level") == "HIGH"]
    if high_threat:
        summary.append(
            f"• {len(high_threat)} HIGH-threat attacker(s) active."
        )

    # Proxy/hosting flagged IPs
    proxy_count = sum(1 for a in attackers if a.get("is_proxy"))
    if proxy_count > 0:
        summary.append(
            f"• {proxy_count} attacker(s) using proxy/Tor."
        )

    return summary
