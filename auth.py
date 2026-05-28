"""
auth.py — Adaptive MFA System
Handles user registration, password verification, account lockout,
and the /api/auth/password Flask route.

Depends on:
  database.py     — all DB operations
  risk_engine.py  — 5-signal risk scoring
"""

import logging
from datetime import datetime, timezone, timedelta

import bcrypt
import mfa_engine
from flask import Blueprint, request, jsonify, session

from mfa_engine import OTPManager, RiskEngine, AdaptiveMFA, SecretStore

from database import (
    create_user,
    get_user_by_username,
    get_user_by_email,
    increment_failed_attempts,
    lock_user,
    reset_failed_attempts,
    is_user_locked,
    update_last_login,
    log_login_attempt,
    update_login_outcome,
)
from risk_engine import calculate_risk, hash_device

logger = logging.getLogger(__name__)

# ── Blueprint ─────────────────────────────────────────────────────────────────

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# ── Constants ─────────────────────────────────────────────────────────────────

BCRYPT_COST         = 12          # work factor for bcrypt
MAX_FAILED_ATTEMPTS = 3           # lock account after this many failures
LOCKOUT_MINUTES     = 15          # how long the lockout lasts

# ── Session keys (imported by otp.py and face.py) ─────────────────────────────
SESSION_KEY_USER    = "user_id"   # Flask session key for authenticated user
SESSION_KEY_TIER    = "risk_tier" # risk tier stored mid-flow
SESSION_KEY_LOG     = "log_id"    # current login attempt log row


# ── Password utilities ────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """
    Hash a plaintext password with bcrypt (cost factor 12).
    Returns a UTF-8 string safe for DB storage.
    """
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=BCRYPT_COST)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """
    Safely compare a plaintext password against a stored bcrypt hash.
    Returns False (never raises) on any error.
    """
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ── Registration ──────────────────────────────────────────────────────────────

def register_user(username: str, email: str, plain_password: str) -> dict:
    """
    Create a new user account.

    Returns
    -------
    {"success": True,  "user_id": int}          on success
    {"success": False, "error":  str}            on validation / DB error
    """
    # ── Basic validation ──────────────────────────────────────────────────────
    username = username.strip()
    email    = email.strip().lower()

    if len(username) < 3:
        return {"success": False, "error": "Username must be at least 3 characters."}
    if len(plain_password) < 8:
        return {"success": False, "error": "Password must be at least 8 characters."}
    if "@" not in email:
        return {"success": False, "error": "Invalid email address."}

    # ── Duplicate check ───────────────────────────────────────────────────────
    if get_user_by_username(username):
        return {"success": False, "error": "Username already taken."}
    if get_user_by_email(email):
        return {"success": False, "error": "Email already registered."}

    # ── Create ────────────────────────────────────────────────────────────────
    password_hash = hash_password(plain_password)
    otp_secret    = mfa_engine.random_base32()   # unique TOTP secret per user

    try:
        user_id = create_user(username, email, password_hash, otp_secret)
        logger.info("[Auth] Registered new user: %s (id=%d)", username, user_id)
        return {"success": True, "user_id": user_id}
    except Exception as exc:
        logger.error("[Auth] Registration failed for %s: %s", username, exc)
        return {"success": False, "error": "Registration failed. Please try again."}


# ── Core login logic (used by route + tests) ──────────────────────────────────

def attempt_login(
    username:      str,
    plain_password: str,
    ip_address:    str,
    user_agent:    str,
    accept_header: str = "",
) -> dict:
    """
    Validate credentials, enforce lockout, score risk, and return an auth result.

    Returns
    -------
    {
        "success":    bool,
        "user_id":    int | None,
        "risk_score": int,
        "risk_tier":  str,          # "low" | "medium" | "high"
        "device_hash":str,
        "log_id":     int,
        "error":      str | None,
        "locked_until": str | None, # ISO-8601 if locked
    }
    """
    device_hash = hash_device(user_agent, accept_header)
    result = {
        "success":      False,
        "user_id":      None,
        "risk_score":   0,
        "risk_tier":    "low",
        "device_hash":  device_hash,
        "log_id":       None,
        "error":        None,
        "locked_until": None,
    }

    # ── Fetch user ────────────────────────────────────────────────────────────
    user = get_user_by_username(username.strip())
    if not user:
        # Don't reveal whether username exists
        log_id = log_login_attempt(None, ip_address, device_hash, 0, "low", "failed")
        result["error"]  = "Invalid username or password."
        result["log_id"] = log_id
        return result

    user_id = user["user_id"]

    # ── Lockout check ─────────────────────────────────────────────────────────
    if is_user_locked(user):
        locked_until_str = user["locked_until"]
        log_id = log_login_attempt(user_id, ip_address, device_hash, 0, "low", "locked")
        result["error"]        = "Account temporarily locked due to too many failed attempts."
        result["locked_until"] = locked_until_str
        result["log_id"]       = log_id
        return result

    # ── Risk scoring (run before password check so we always log a score) ─────
    risk = calculate_risk(user_id, ip_address, user_agent, accept_header)

    # ── Log the attempt (outcome = "pending" until password verified) ─────────
    log_id = log_login_attempt(
        user_id, ip_address, device_hash,
        risk.score, risk.tier, "pending"
    )
    result["log_id"]     = log_id
    result["risk_score"] = risk.score
    result["risk_tier"]  = risk.tier

    # ── Password verification ─────────────────────────────────────────────────
    if not verify_password(plain_password, user["password_hash"]):
        new_count = increment_failed_attempts(user_id)
        update_login_outcome(log_id, "failed")

        if new_count >= MAX_FAILED_ATTEMPTS:
            locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
            lock_user(user_id, locked_until)
            result["error"]        = (
                f"Too many failed attempts. "
                f"Account locked for {LOCKOUT_MINUTES} minutes."
            )
            result["locked_until"] = locked_until.strftime("%Y-%m-%dT%H:%M:%SZ")
            logger.warning("[Auth] Account locked: user_id=%d", user_id)
        else:
            remaining = MAX_FAILED_ATTEMPTS - new_count
            result["error"] = (
                f"Invalid username or password. "
                f"{remaining} attempt(s) remaining before lockout."
            )

        return result

    # ── Password correct ──────────────────────────────────────────────────────
    reset_failed_attempts(user_id)
    update_last_login(user_id)

    result["success"] = True
    result["user_id"] = user_id
    result["signals"] = risk.signals

    # For low-risk: mark success immediately
    if risk.tier == "low":
        update_login_outcome(log_id, "success")

    logger.info(
        "[Auth] Password verified: user_id=%d risk=%d tier=%s",
        user_id, risk.score, risk.tier
    )
    return result


# ── Flask route: POST /api/auth/password ──────────────────────────────────────

@auth_bp.route("/password", methods=["POST"])
def login_password():
    """
    Step 1 of the adaptive login flow.

    Request JSON
    ------------
    { "username": str, "password": str }

    Response JSON (success)
    -----------------------
    { "risk_score": int, "risk_tier": str, "message": str }

    Response JSON (error)
    ---------------------
    { "error": str, "locked_until": str | null }
    """
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    password =  data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    ip          = _get_client_ip()
    user_agent  = request.headers.get("User-Agent", "")
    accept_hdr  = request.headers.get("Accept", "")

    auth = attempt_login(username, password, ip, user_agent, accept_hdr)

    if not auth["success"]:
        payload = {"error": auth["error"]}
        if auth.get("locked_until"):
            payload["locked_until"] = auth["locked_until"]
        status = 423 if auth.get("locked_until") else 401
        return jsonify(payload), status

    # Stash in Flask session for subsequent OTP / face steps
    session[SESSION_KEY_USER] = auth["user_id"]
    session[SESSION_KEY_TIER] = auth["risk_tier"]
    session[SESSION_KEY_LOG]  = auth["log_id"]

    return jsonify({
        "risk_score": auth["risk_score"],
        "risk_tier":  auth["risk_tier"],
        "signals": auth.get("signals", {}),
        "message":    _tier_message(auth["risk_tier"]),
    }), 200


# ── Flask route: POST /api/auth/logout ───────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Clear Flask session and invalidate the DB session token."""
    from database import invalidate_all_sessions
    user_id = session.pop(SESSION_KEY_USER, None)
    session.clear()
    if user_id:
        invalidate_all_sessions(user_id)
    return jsonify({"message": "Logged out successfully."}), 200


# ── Flask route: POST /api/auth/register ─────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Request JSON
    ------------
    { "username": str, "email": str, "password": str }
    """
    data = request.get_json(silent=True) or {}
    res  = register_user(
        data.get("username", ""),
        data.get("email", ""),
        data.get("password", ""),
    )
    if res["success"]:
        session[SESSION_KEY_USER] = res["user_id"]
        session[SESSION_KEY_TIER] = "low"
        return jsonify({"message": "Account created.", "user_id": res["user_id"]}), 201
    return jsonify({"error": res["error"]}), 400


# ── Middleware helper: require authenticated session ──────────────────────────

def login_required(f):
    """
    Decorator for routes that need a completed, fully-verified session.
    Usage:
        @app.route('/dashboard')
        @login_required
        def dashboard(): ...
    """
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if SESSION_KEY_USER not in session:
            return jsonify({"error": "Authentication required."}), 401
        return f(*args, **kwargs)
    return decorated


# ── Private helpers ───────────────────────────────────────────────────────────

def _get_client_ip() -> str:
    """
    Extract the real client IP, honouring X-Forwarded-For when behind a proxy.
    Falls back to remote_addr.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def _tier_message(tier: str) -> str:
    messages = {
        "low":    "Low risk detected. Access granted.",
        "medium": "Medium risk detected. OTP verification required.",
        "high":   "High risk detected. OTP and facial verification required.",
    }
    return messages.get(tier, "Verification required.")


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    from database import init_db
    init_db()

    # Quick registration + login smoke test
    test_user = "ALLUGUVELLI SINDHU"
    test_pass = "Sindhu_29"
    test_email = "sunithapandu12345@gmail.com"

    print("\n── Registration ──")
    reg = register_user(test_user, test_email, test_pass)
    print(reg)

    print("\n── Login (correct password) ──")
    auth = attempt_login(test_user, test_pass, "127.0.0.1",
                         "Mozilla/5.0 TestBrowser", "text/html")
    print(f"  success={auth['success']}  tier={auth['risk_tier']}  score={auth['risk_score']}")

    print("\n── Login (wrong password) ──")
    bad = attempt_login(test_user, "wrongpass", "127.0.0.1",
                        "Mozilla/5.0 TestBrowser", "text/html")
    print(f"  success={bad['success']}  error={bad['error']}")
