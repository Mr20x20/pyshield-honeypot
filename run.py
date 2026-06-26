"""
run.py — PyShield Honeypot
Entry point. Starts all components in background threads.

Usage:
    python run.py

What starts:
    1. Database initialised
    2. SSH honeypot server thread
    3. HTTP honeypot server thread
    4. Reporter loop thread (writes honeypot_report.json every 30s)

Press Ctrl+C to stop everything cleanly.
"""

import logging
import sys
import threading
import time
from pathlib import Path

# ── Logging setup ─────────────────────────────────────────────────────────────
# Set up before importing anything else so all modules use the same config
from config import LOG_FILE

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)

logger = logging.getLogger("honeypot.run")

# ── Imports after logging is configured ───────────────────────────────────────
import database as db
import reporter
from honeypot import start_ssh_server, start_http_server
from config import SSH_PORT, HTTP_PORT, HONEYPOT_REPORT


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    logger.info("=" * 55)
    logger.info("  PyShield Honeypot — Attacker Profiler")
    logger.info("=" * 55)

    # 1. Initialise database
    db.init_db()
    logger.info("Database ready")

    # 2. Write one immediate report so project6 SIEM has something to
    #    read even before the first REPORT_INTERVAL elapses
    initial_report = reporter.build_report()
    reporter.write_report(initial_report)
    logger.info("Initial report written to %s", HONEYPOT_REPORT)

    # 3. Start SSH honeypot thread
    ssh_thread = threading.Thread(
        target=start_ssh_server,
        daemon=True,
        name="ssh-honeypot",
    )
    ssh_thread.start()
    logger.info("SSH honeypot started on port %d", SSH_PORT)

    # 4. Start HTTP honeypot thread
    http_thread = threading.Thread(
        target=start_http_server,
        daemon=True,
        name="http-honeypot",
    )
    http_thread.start()
    logger.info("HTTP honeypot started on port %d", HTTP_PORT)

    # 5. Start reporter loop thread
    reporter_thread = threading.Thread(
        target=reporter.run_reporter_loop,
        daemon=True,
        name="reporter",
    )
    reporter_thread.start()
    logger.info("Reporter loop started")

    # ── Status summary ────────────────────────────────────────────
    logger.info("-" * 55)
    logger.info("  Honeypot is ACTIVE")
    logger.info("  SSH  listener : 0.0.0.0:%d", SSH_PORT)
    logger.info("  HTTP listener : 0.0.0.0:%d", HTTP_PORT)
    logger.info("  Report output : %s", HONEYPOT_REPORT)
    logger.info("  Log file      : %s", LOG_FILE)
    logger.info("-" * 55)
    logger.info("  Press Ctrl+C to stop")
    logger.info("=" * 55)

    # 6. Keep main thread alive — daemon threads die when main exits
    try:
        while True:
            # Print a heartbeat every 60s so you know it's still running
            time.sleep(60)
            _print_heartbeat()
    except KeyboardInterrupt:
        logger.info("Shutdown requested — stopping honeypot...")
        _final_report()
        logger.info("Goodbye.")
        sys.exit(0)


def _print_heartbeat() -> None:
    """Print a brief status line every 60 seconds."""
    try:
        stats = db.get_stats()
        logger.info(
            "♥ Heartbeat | events=%d | unique_ips=%d | "
            "ssh=%d | http=%d",
            stats["total_events"],
            stats["unique_ips"],
            stats["ssh_attempts"],
            stats["http_requests"],
        )
    except Exception:
        pass


def _final_report() -> None:
    """Write one last report on shutdown to capture final state."""
    try:
        report = reporter.build_report()
        reporter.write_report(report)
        logger.info("Final report written.")
    except Exception as e:
        logger.error("Could not write final report: %s", e)


if __name__ == "__main__":
    main()
