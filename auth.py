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
import pyotp
from flask import Blueprint, request, jsonify, session

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

BCRYPT_COST         = 12
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_MINUTES     = 15

# ── Session keys (imported by otp.py and face.py) ─────────────────────────────
SESSION_KEY_USER = "user_id"
SESSION_KEY_TIER = "risk_tier"
SESSION_KEY_LOG  = "log_id"


# ── Password utilities ────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=BCRYPT_COST)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ── Registration ──────────────────────────────────────────────────────────────

def register_user(username: str, email: str, plain_password: str) -> dict:
    username = username.strip()
    email    = email.strip().lower()

    if len(username) < 3:
        return {"success": False, "error": "Username must be at least 3 characters."}
    if len(plain_password) < 8:
        return {"success": False, "error": "Password must be at least 8 characters."}
    if "@" not in email:
        return {"success": False, "error": "Invalid email address."}

    if get_user_by_username(username):
        return {"success": False, "error": "Username already taken."}
    if get_user_by_email(email):
        return {"success": False, "error": "Email already registered."}

    password_hash = hash_password(plain_password)
    otp_secret    = pyotp.random_base32()

    try:
        user_id = create_user(username, email, password_hash, otp_secret)
        logger.info("[Auth] Registered new user: %s (id=%d)", username, user_id)
        return {"success": True, "user_id": user_id}
    except Exception as exc:
        logger.error("[Auth] Registration failed for %s: %s", username, exc)
        return {"success": False, "error": "Registration failed. Please try again."}


# ── Core login logic ──────────────────────────────────────────────────────────

def attempt_login(
    username:       str,
    plain_password: str,
    ip_address:     str,
    user_agent:     str,
    accept_header:  str = "",
) -> dict:
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
        log_id = log_login_attempt(None, ip_address, device_hash, 0, "low", "failed")
        result["error"]  = "Invalid username or password."
        result["log_id"] = log_id
        return result

    user_id = user["user_id"]

    # ── Lockout check ─────────────────────────────────────────────────────────
    if is_user_locked(user):
        log_id = log_login_attempt(user_id, ip_address, device_hash, 0, "low", "locked")
        result["error"]        = "Account temporarily locked due to too many failed attempts."
        result["locked_until"] = user["locked_until"]
        result["log_id"]       = log_id
        return result

    # ── Risk scoring ──────────────────────────────────────────────────────────
    risk = calculate_risk(user_id, ip_address, user_agent, accept_header)

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
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    password =  data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    ip         = _get_client_ip()
    user_agent = request.headers.get("User-Agent", "")
    accept_hdr = request.headers.get("Accept", "")

    auth = attempt_login(username, password, ip, user_agent, accept_hdr)

    if not auth["success"]:
        payload = {"error": auth["error"]}
        if auth.get("locked_until"):
            payload["locked_until"] = auth["locked_until"]
        status = 423 if auth.get("locked_until") else 401
        return jsonify(payload), status

    session[SESSION_KEY_USER] = auth["user_id"]
    session[SESSION_KEY_TIER] = auth["risk_tier"]
    session[SESSION_KEY_LOG]  = auth["log_id"]

    return jsonify({
        "risk_score": auth["risk_score"],
        "risk_tier":  auth["risk_tier"],
        "signals":    auth.get("signals", {}),
        "message":    _tier_message(auth["risk_tier"]),
    }), 200


# ── Flask route: POST /api/auth/logout ───────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
def logout():
    from database import invalidate_all_sessions
    user_id = session.pop(SESSION_KEY_USER, None)
    session.clear()
    if user_id:
        invalidate_all_sessions(user_id)
    return jsonify({"message": "Logged out successfully."}), 200


# ── Flask route: POST /api/auth/register ─────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
def register():
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


# ── Middleware helper ─────────────────────────────────────────────────────────

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if SESSION_KEY_USER not in session:
            return jsonify({"error": "Authentication required."}), 401
        return f(*args, **kwargs)
    return decorated


# ── Private helpers ───────────────────────────────────────────────────────────

def _get_client_ip() -> str:
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