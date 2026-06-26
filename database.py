"""
database.py — PyShield Honeypot
SQLite persistence layer for attacker events and profiles.

Schema:
  events          : every individual connection/attempt
  attacker_profiles : aggregated per-IP statistics
"""

import sqlite3
import logging
from contextlib import contextmanager
from datetime import datetime

from config import DB_PATH

logger = logging.getLogger("honeypot.database")


# ── Bootstrap ──────────────────────────────────────────────────────────────────
def init_db() -> None:
    """Create tables if they don't exist. Safe to call on every startup."""
    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT    NOT NULL,
                service       TEXT    NOT NULL,  -- 'ssh' or 'http'
                attacker_ip   TEXT    NOT NULL,
                attacker_port INTEGER,
                event_type    TEXT    NOT NULL,  -- 'auth_attempt', 'http_request'
                username      TEXT,              -- SSH only
                password      TEXT,              -- SSH only
                http_method   TEXT,              -- HTTP only
                http_path     TEXT,              -- HTTP only
                user_agent    TEXT,              -- HTTP only
                extra         TEXT               -- JSON string for anything else
            );

            CREATE TABLE IF NOT EXISTS attacker_profiles (
                ip               TEXT PRIMARY KEY,
                first_seen       TEXT NOT NULL,
                last_seen        TEXT NOT NULL,
                ssh_attempts     INTEGER DEFAULT 0,
                http_requests    INTEGER DEFAULT 0,
                unique_usernames INTEGER DEFAULT 0,
                unique_passwords INTEGER DEFAULT 0,
                country          TEXT,
                city             TEXT,
                isp              TEXT,
                is_proxy         INTEGER DEFAULT 0,  -- 0 or 1
                is_hosting       INTEGER DEFAULT 0,
                threat_level     TEXT DEFAULT 'LOW'  -- LOW / MEDIUM / HIGH
            );

            CREATE INDEX IF NOT EXISTS idx_events_ip
                ON events(attacker_ip);

            CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON events(timestamp);

            CREATE INDEX IF NOT EXISTS idx_events_service
                ON events(service);
        """)
    logger.info("Database initialised at %s", DB_PATH)


# ── Write ──────────────────────────────────────────────────────────────────────
def log_ssh_attempt(ip: str, port: int, username: str, password: str) -> None:
    """Record one SSH credential attempt."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO events
                (timestamp, service, attacker_ip, attacker_port,
                 event_type, username, password)
            VALUES (?, 'ssh', ?, ?, 'auth_attempt', ?, ?)
            """,
            (now, ip, port, username, password),
        )
    _update_profile(ip, service="ssh", username=username, password=password)
    logger.debug("SSH attempt: %s tried %s:%s", ip, username, password)


def log_http_request(ip: str, port: int, method: str,
                     path: str, user_agent: str) -> None:
    """Record one HTTP request to the honeypot."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO events
                (timestamp, service, attacker_ip, attacker_port,
                 event_type, http_method, http_path, user_agent)
            VALUES (?, 'http', ?, ?, 'http_request', ?, ?, ?)
            """,
            (now, ip, port, method, path, user_agent),
        )
    _update_profile(ip, service="http")
    logger.debug("HTTP request: %s %s %s", ip, method, path)


def update_geo(ip: str, country: str, city: str,
               isp: str, is_proxy: bool, is_hosting: bool) -> None:
    """Store geolocation data for an attacker IP."""
    with _get_conn() as conn:
        conn.execute(
            """
            UPDATE attacker_profiles
            SET country=?, city=?, isp=?, is_proxy=?, is_hosting=?
            WHERE ip=?
            """,
            (country, city, isp, int(is_proxy), int(is_hosting), ip),
        )


# ── Read ───────────────────────────────────────────────────────────────────────
def get_recent_events(limit: int = 100) -> list[dict]:
    """Return the most recent N events, newest first."""
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_top_attackers(limit: int = 20) -> list[dict]:
    """Return top attackers sorted by total activity."""
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *,
                   (ssh_attempts + http_requests) AS total_attempts
            FROM   attacker_profiles
            ORDER  BY total_attempts DESC
            LIMIT  ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_profile(ip: str) -> dict | None:
    """Return the full profile for one IP."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM attacker_profiles WHERE ip = ?", (ip,)
        ).fetchone()
    return dict(row) if row else None


def get_stats() -> dict:
    """
    High-level statistics for the reporter.
    Returns total events, unique IPs, top credentials tried.
    """
    with _get_conn() as conn:
        total_events = conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        unique_ips = conn.execute(
            "SELECT COUNT(*) FROM attacker_profiles"
        ).fetchone()[0]

        ssh_attempts = conn.execute(
            "SELECT COUNT(*) FROM events WHERE service='ssh'"
        ).fetchone()[0]

        http_requests = conn.execute(
            "SELECT COUNT(*) FROM events WHERE service='http'"
        ).fetchone()[0]

        # Top 5 usernames tried
        top_usernames = conn.execute(
            """
            SELECT username, COUNT(*) as cnt
            FROM   events
            WHERE  username IS NOT NULL
            GROUP  BY username
            ORDER  BY cnt DESC
            LIMIT  5
            """
        ).fetchall()

        # Top 5 passwords tried
        top_passwords = conn.execute(
            """
            SELECT password, COUNT(*) as cnt
            FROM   events
            WHERE  password IS NOT NULL
            GROUP  BY password
            ORDER  BY cnt DESC
            LIMIT  5
            """
        ).fetchall()

        # Top 5 HTTP paths probed
        top_paths = conn.execute(
            """
            SELECT http_path, COUNT(*) as cnt
            FROM   events
            WHERE  http_path IS NOT NULL
            GROUP  BY http_path
            ORDER  BY cnt DESC
            LIMIT  5
            """
        ).fetchall()

        # Threat level distribution
        threat_dist = conn.execute(
            """
            SELECT threat_level, COUNT(*) as cnt
            FROM   attacker_profiles
            GROUP  BY threat_level
            """
        ).fetchall()

    return {
        "total_events":   total_events,
        "unique_ips":     unique_ips,
        "ssh_attempts":   ssh_attempts,
        "http_requests":  http_requests,
        "top_usernames":  [dict(r) for r in top_usernames],
        "top_passwords":  [dict(r) for r in top_passwords],
        "top_paths":      [dict(r) for r in top_paths],
        "threat_dist":    {r["threat_level"]: r["cnt"] for r in threat_dist},
    }


# ── Internal helpers ───────────────────────────────────────────────────────────
def _update_profile(ip: str, service: str,
                    username: str = None, password: str = None) -> None:
    """
    Upsert the attacker profile for this IP.
    SQLite's INSERT OR IGNORE + UPDATE pattern avoids race conditions.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with _get_conn() as conn:
        # Create profile if first time we see this IP
        conn.execute(
            """
            INSERT OR IGNORE INTO attacker_profiles
                (ip, first_seen, last_seen)
            VALUES (?, ?, ?)
            """,
            (ip, now, now),
        )

        # Increment the right counter
        if service == "ssh":
            conn.execute(
                "UPDATE attacker_profiles SET last_seen=?, ssh_attempts=ssh_attempts+1 WHERE ip=?",
                (now, ip),
            )
        else:
            conn.execute(
                "UPDATE attacker_profiles SET last_seen=?, http_requests=http_requests+1 WHERE ip=?",
                (now, ip),
            )

        # Recalculate unique usernames/passwords for this IP
        if username:
            unique_u = conn.execute(
                "SELECT COUNT(DISTINCT username) FROM events WHERE attacker_ip=? AND username IS NOT NULL",
                (ip,),
            ).fetchone()[0]
            unique_p = conn.execute(
                "SELECT COUNT(DISTINCT password) FROM events WHERE attacker_ip=? AND password IS NOT NULL",
                (ip,),
            ).fetchone()[0]
            conn.execute(
                "UPDATE attacker_profiles SET unique_usernames=?, unique_passwords=? WHERE ip=?",
                (unique_u, unique_p, ip),
            )

        # Recalculate threat level
        profile = conn.execute(
            "SELECT ssh_attempts, http_requests FROM attacker_profiles WHERE ip=?",
            (ip,),
        ).fetchone()

        if profile:
            total = profile["ssh_attempts"] + profile["http_requests"]
            if total >= 20:
                level = "HIGH"
            elif total >= 5:
                level = "MEDIUM"
            else:
                level = "LOW"
            conn.execute(
                "UPDATE attacker_profiles SET threat_level=? WHERE ip=?",
                (level, ip),
            )


@contextmanager
def _get_conn():
    """Yield a thread-safe WAL connection."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
