"""
reporter.py — PyShield Honeypot
Builds and writes honeypot_report.json every REPORT_INTERVAL seconds.

Output schema is designed to be consumed by mini_siem2.py as a 5th source.
"""

import json
import logging
import time
from datetime import datetime

import database as db
import profiler
from config import HONEYPOT_REPORT, REPORT_INTERVAL, MAX_REPORT_EVENTS

logger = logging.getLogger("honeypot.reporter")


# ── Public API ────────────────────────────────────────────────────────────────
def build_report() -> dict:
    """
    Build the full honeypot report dict.
    Called by the reporter loop and also by run.py on demand.
    """
    stats     = db.get_stats()
    attackers = profiler.analyze_recent_attackers()
    events    = db.get_recent_events(limit=MAX_REPORT_EVENTS)
    summary   = profiler.build_summary(stats, attackers)

    # Detect patterns for each top attacker
    for attacker in attackers:
        attacker["patterns"] = profiler.detect_patterns(attacker["ip"])

    # Risk scoring — feeds directly into mini_siem2.py scoring rules
    # These event names match what mini_siem2 expects so it can score them
    triggered_events = _build_triggered_events(stats, attackers)
    risk_score       = _calculate_risk_score(stats, attackers)

    report = {
        "source":            "honeypot",
        "timestamp":         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score":        risk_score,
        "stats":             stats,
        "triggered_events":  triggered_events,
        "summary":           summary,
        "top_attackers":     attackers[:10],   # top 10 in report
        "recent_events":     events,
    }

    return report


def write_report(report: dict) -> None:
    """Write report dict to honeypot_report.json."""
    try:
        with open(HONEYPOT_REPORT, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        logger.info(
            "Report written → score=%d | events=%d | attackers=%d",
            report["risk_score"],
            report["stats"]["total_events"],
            report["stats"]["unique_ips"],
        )
    except Exception as e:
        logger.error("Failed to write report: %s", e)


def run_reporter_loop() -> None:
    """
    Runs forever in a background thread.
    Rebuilds and writes honeypot_report.json every REPORT_INTERVAL seconds.
    """
    logger.info("Reporter loop started (interval=%ds)", REPORT_INTERVAL)
    while True:
        try:
            report = build_report()
            write_report(report)
        except Exception as e:
            logger.exception("Reporter cycle failed: %s", e)
        time.sleep(REPORT_INTERVAL)


# ── Internals ─────────────────────────────────────────────────────────────────
def _build_triggered_events(stats: dict, attackers: list[dict]) -> list[str]:
    """
    Map honeypot activity to event name strings.
    These names are what mini_siem2.py will read and score.
    """
    events = []

    if stats["ssh_attempts"] > 0:
        events.append("honeypot_ssh_attempts")

    if stats["http_requests"] > 0:
        events.append("honeypot_http_probes")

    # Escalate if volume is high
    if stats["ssh_attempts"] >= 10:
        events.append("honeypot_brute_force")

    if stats["unique_ips"] >= 5:
        events.append("honeypot_multiple_sources")

    # Proxy/Tor usage
    proxy_count = sum(1 for a in attackers if a.get("is_proxy"))
    if proxy_count > 0:
        events.append("honeypot_proxy_detected")

    # Pattern-based events
    all_patterns = []
    for attacker in attackers:
        all_patterns.extend(attacker.get("patterns", []))

    if "credential_stuffing" in all_patterns:
        events.append("honeypot_credential_stuffing")
    if "password_spray" in all_patterns:
        events.append("honeypot_password_spray")
    if "directory_traversal" in all_patterns:
        events.append("honeypot_directory_traversal")
    if "automated_scanner" in all_patterns:
        events.append("honeypot_automated_scanner")

    return list(set(events))


def _calculate_risk_score(stats: dict, attackers: list[dict]) -> int:
    """
    Simple weighted scoring for the honeypot report itself.
    mini_siem2.py will do its own scoring — this is for the
    standalone honeypot report context.
    """
    score = 0

    # Volume-based
    score += min(stats["ssh_attempts"]  * 2, 30)   # cap at 30
    score += min(stats["http_requests"] * 1, 20)   # cap at 20
    score += stats["unique_ips"] * 3

    # Threat level distribution
    threat = stats.get("threat_dist", {})
    score += threat.get("MEDIUM", 0) * 5
    score += threat.get("HIGH",   0) * 10

    # Proxy/Tor usage is a strong signal
    proxy_count = sum(1 for a in attackers if a.get("is_proxy"))
    score += proxy_count * 8

    return score
