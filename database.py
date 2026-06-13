"""
database.py — Adaptive MFA System
Handles all SQLite database operations: schema creation, user management,
login history logging, and session tracking.
"""

import sqlite3
import os
import json
import numpy as np
from datetime import datetime, timezone
from contextlib import contextmanager

# ── Configuration ────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "mfa_system.db")

# ── Connection helper ─────────────────────────────────────────────────────────

@contextmanager
def get_db():
    """
    Context manager that yields a SQLite connection with row_factory set
    so rows behave like dicts (row['column_name']).
    Commits on clean exit, rolls back on exception, always closes.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row          # access columns by name
    conn.execute("PRAGMA foreign_keys = ON") # enforce FK constraints
    conn.execute("PRAGMA journal_mode = WAL") # better concurrent reads
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# ── Schema initialisation ─────────────────────────────────────────────────────

def init_db():
    """
    Create all tables and indexes if they don't already exist.
    Safe to call on every app start — uses IF NOT EXISTS throughout.
    """
    with get_db() as conn:
        conn.executescript("""
            -- ----------------------------------------------------------------
            -- Table: users
            -- Stores credentials, OTP secret, face encoding, and lock state.
            -- ----------------------------------------------------------------
            CREATE TABLE IF NOT EXISTS users (
                user_id        INTEGER PRIMARY KEY AUTOINCREMENT,
                username       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                email          TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                password_hash  TEXT    NOT NULL,          -- bcrypt hash, cost 12
                otp_secret     TEXT    NOT NULL,          -- base32 TOTP secret
                face_encoding  TEXT    DEFAULT NULL,      -- JSON array, 128-D vector
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until   TEXT    DEFAULT NULL,      -- ISO-8601 UTC datetime
                created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                last_login     TEXT    DEFAULT NULL
            );

            -- ----------------------------------------------------------------
            -- Table: login_history
            -- Immutable audit trail — never update rows, only insert.
            -- ----------------------------------------------------------------
            CREATE TABLE IF NOT EXISTS login_history (
                log_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
                timestamp   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                ip_address  TEXT    NOT NULL,
                device_hash TEXT    NOT NULL,             -- SHA-256 of User-Agent + Accept headers
                risk_score  INTEGER NOT NULL DEFAULT 0,
                risk_tier   TEXT    NOT NULL DEFAULT 'low' CHECK(risk_tier IN ('low','medium','high')),
                outcome     TEXT    NOT NULL DEFAULT 'pending'
                                CHECK(outcome IN ('success','failed','locked','pending'))
            );

            -- ----------------------------------------------------------------
            -- Table: sessions
            -- JWT tokens; is_active = 0 when logged out or expired.
            -- ----------------------------------------------------------------
            CREATE TABLE IF NOT EXISTS sessions (
                session_id  INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                token       TEXT    NOT NULL UNIQUE,      -- full JWT string
                created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                expires_at  TEXT    NOT NULL,             -- ISO-8601 UTC
                is_active   INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1))
            );

            -- ----------------------------------------------------------------
            -- Indexes for fast look-ups used in every request cycle
            -- ----------------------------------------------------------------
            CREATE INDEX IF NOT EXISTS idx_users_username      ON users(username);
            CREATE INDEX IF NOT EXISTS idx_users_email         ON users(email);
            CREATE INDEX IF NOT EXISTS idx_history_user_time   ON login_history(user_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_history_ip          ON login_history(ip_address, timestamp);
            CREATE INDEX IF NOT EXISTS idx_sessions_token      ON sessions(token);
            CREATE INDEX IF NOT EXISTS idx_sessions_user       ON sessions(user_id, is_active);
        """)
    print(f"[DB] Database ready → {DB_PATH}")


# ── User operations ───────────────────────────────────────────────────────────

def create_user(username: str, email: str, password_hash: str, otp_secret: str) -> int:
    """
    Insert a new user and return their user_id.
    Raises sqlite3.IntegrityError if username or email already exists.
    """
    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO users (username, email, password_hash, otp_secret)
            VALUES (?, ?, ?, ?)
            """,
            (username.strip(), email.strip().lower(), password_hash, otp_secret)
        )
        return cursor.lastrowid


def get_user_by_username(username: str) -> dict | None:
    """Return a user row as a dict, or None if not found."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username.strip(),)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    """Return a user row as a dict, or None if not found."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_email(email: str) -> dict | None:
    """Return a user row as a dict, or None if not found."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email.strip().lower(),)
        ).fetchone()
        return dict(row) if row else None


# ── Face encoding helpers ─────────────────────────────────────────────────────

def save_face_encoding(user_id: int, encoding: np.ndarray) -> None:
    """
    Persist a 128-D face encoding as a JSON array.
    Raw images are NEVER stored — only the numeric vector.
    """
    encoding_json = json.dumps(encoding.tolist())
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET face_encoding = ? WHERE user_id = ?",
            (encoding_json, user_id)
        )


def get_face_encoding(user_id: int) -> np.ndarray | None:
    """
    Retrieve stored face encoding as a numpy array, or None if not enrolled.
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT face_encoding FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
    if row and row["face_encoding"]:
        return np.array(json.loads(row["face_encoding"]))
    return None


# ── Failed-attempt / lockout management ──────────────────────────────────────

def increment_failed_attempts(user_id: int) -> int:
    """
    Increment failed_attempts counter and return the NEW count.
    Caller decides whether to trigger a lockout.
    """
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE user_id = ?",
            (user_id,)
        )
        row = conn.execute(
            "SELECT failed_attempts FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        return row["failed_attempts"]


def lock_user(user_id: int, locked_until: datetime) -> None:
    """Set the lockout expiry timestamp (UTC, ISO-8601)."""
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET locked_until = ? WHERE user_id = ?",
            (locked_until.strftime("%Y-%m-%dT%H:%M:%SZ"), user_id)
        )


def reset_failed_attempts(user_id: int) -> None:
    """Clear failed_attempts and locked_until after a successful login."""
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?",
            (user_id,)
        )


def is_user_locked(user: dict) -> bool:
    """
    Return True if the account is currently locked.
    Accepts a user dict as returned by get_user_by_*.
    """
    if not user.get("locked_until"):
        return False
    locked_until = datetime.strptime(user["locked_until"], "%Y-%m-%dT%H:%M:%SZ")
    locked_until = locked_until.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) < locked_until


def update_last_login(user_id: int) -> None:
    """Stamp the last_login field on successful authentication."""
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET last_login = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE user_id = ?",
            (user_id,)
        )


# ── Login history ─────────────────────────────────────────────────────────────

def log_login_attempt(
    user_id: int | None,
    ip_address: str,
    device_hash: str,
    risk_score: int,
    risk_tier: str,
    outcome: str = "pending"
) -> int:
    """
    Insert a login attempt record and return the new log_id.
    user_id may be None for attempts against non-existent usernames.
    """
    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO login_history (user_id, ip_address, device_hash, risk_score, risk_tier, outcome)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, ip_address, device_hash, risk_score, risk_tier, outcome)
        )
        return cursor.lastrowid


def update_login_outcome(log_id: int, outcome: str) -> None:
    """Update outcome once the full auth flow completes (success / failed / locked)."""
    with get_db() as conn:
        conn.execute(
            "UPDATE login_history SET outcome = ? WHERE log_id = ?",
            (outcome, log_id)
        )


def get_recent_failed_attempts(user_id: int, within_minutes: int = 30) -> int:
    """
    Count failed login attempts for a user in the last `within_minutes` minutes.
    Used by the risk engine to add +2 for brute-force signals.
    """
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM   login_history
            WHERE  user_id = ?
              AND  outcome  = 'failed'
              AND  timestamp >= strftime('%Y-%m-%dT%H:%M:%SZ',
                                 datetime('now', ? || ' minutes'))
            """,
            (user_id, f"-{within_minutes}")
        ).fetchone()
        return row["cnt"] if row else 0


def get_known_ips_for_user(user_id: int, within_days: int = 30) -> list[str]:
    """
    Return all distinct IP addresses that successfully logged in
    within the last `within_days` days. Used to detect unknown IPs.
    """
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT ip_address
            FROM   login_history
            WHERE  user_id  = ?
              AND  outcome   = 'success'
              AND  timestamp >= strftime('%Y-%m-%dT%H:%M:%SZ',
                                 datetime('now', ? || ' days'))
            """,
            (user_id, f"-{within_days}")
        ).fetchall()
        return [r["ip_address"] for r in rows]


def get_known_devices_for_user(user_id: int) -> list[str]:
    """
    Return all distinct device hashes that have ever succeeded for this user.
    Used to detect new/unrecognised devices (+3 risk points).
    """
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT device_hash
            FROM   login_history
            WHERE  user_id = ?
              AND  outcome  = 'success'
            """,
            (user_id,)
        ).fetchall()
        return [r["device_hash"] for r in rows]


# ── Session management ────────────────────────────────────────────────────────

def create_session(user_id: int, token: str, expires_at: datetime) -> int:
    """Insert a new active session and return its session_id."""
    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO sessions (user_id, token, expires_at)
            VALUES (?, ?, ?)
            """,
            (user_id, token, expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"))
        )
        return cursor.lastrowid


def get_session_by_token(token: str) -> dict | None:
    """Return a session row as a dict, or None if not found / inactive."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE token = ? AND is_active = 1", (token,)
        ).fetchone()
        return dict(row) if row else None


def invalidate_session(token: str) -> None:
    """Mark a single session as inactive (logout)."""
    with get_db() as conn:
        conn.execute(
            "UPDATE sessions SET is_active = 0 WHERE token = ?", (token,)
        )


def invalidate_all_sessions(user_id: int) -> None:
    """Invalidate every active session for a user (e.g. after password change)."""
    with get_db() as conn:
        conn.execute(
            "UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user_id,)
        )


# ── Utility ───────────────────────────────────────────────────────────────────

def get_db_stats() -> dict:
    """Return basic row counts — useful for a health-check endpoint."""
    with get_db() as conn:
        users    = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        history  = conn.execute("SELECT COUNT(*) FROM login_history").fetchone()[0]
        sessions = conn.execute("SELECT COUNT(*) FROM sessions WHERE is_active=1").fetchone()[0]
    return {"users": users, "login_events": history, "active_sessions": sessions}


# ── Entry point (run directly to initialise) ──────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("[DB] Stats:", get_db_stats())