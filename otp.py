"""
otp.py — Adaptive MFA System
Handles TOTP generation (RFC 6238), OTP email delivery via Gmail SMTP,
and the /api/auth/otp + /api/auth/resend-otp Flask routes.

Depends on:
  database.py  — get_user_by_id
  auth.py      — SESSION_KEY_USER, SESSION_KEY_TIER, SESSION_KEY_LOG
"""

import logging
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone

import pyotp
from flask import Blueprint, request, jsonify, session

from database import get_user_by_id, update_login_outcome
from auth import SESSION_KEY_USER, SESSION_KEY_TIER, SESSION_KEY_LOG

logger = logging.getLogger(__name__)

# ── Blueprint ─────────────────────────────────────────────────────────────────

otp_bp = Blueprint("otp", __name__, url_prefix="/api/auth")

# ── Configuration (set these in environment variables) ────────────────────────
# In production never hardcode credentials — use a .env file with python-dotenv

GMAIL_ADDRESS  = os.environ.get("GMAIL_ADDRESS",  "your_email@gmail.com")
GMAIL_APP_PASS = os.environ.get("GMAIL_APP_PASS",  "your_app_password")   # 16-char App Password
OTP_ISSUER     = "AdaptiveMFA"
OTP_VALID_WINDOW = 1   # allow 1 step before/after (±30s tolerance)


# ── TOTP core ─────────────────────────────────────────────────────────────────

def generate_otp(otp_secret: str) -> str:
    """
    Generate the current 6-digit TOTP code for a user's secret.
    Valid for 30 seconds (RFC 6238 standard window).
    """
    totp = pyotp.TOTP(otp_secret)
    return totp.now()


def verify_otp(otp_secret: str, code: str) -> bool:
    """
    Verify a submitted OTP code against the user's secret.
    Allows ±1 window (90s total) to account for clock drift.
    Returns False on any error.
    """
    if not code or not code.strip().isdigit() or len(code.strip()) != 6:
        return False
    try:
        totp = pyotp.TOTP(otp_secret)
        return totp.verify(code.strip(), valid_window=OTP_VALID_WINDOW)
    except Exception as exc:
        logger.error("[OTP] Verification error: %s", exc)
        return False


# ── Email delivery ────────────────────────────────────────────────────────────

def send_otp_email(to_email: str, username: str, otp_code: str) -> bool:
    """
    Send a styled OTP email via Gmail SMTP (TLS on port 587).

    Returns True on success, False on any SMTP error.
    Requires:
      GMAIL_ADDRESS  — your Gmail address
      GMAIL_APP_PASS — 16-character App Password (not your Gmail password)
                       Generate at: myaccount.google.com/apppasswords
    """
    subject = f"Your SecureAuth verification code: {otp_code}"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── HTML email body ───────────────────────────────────────────────────────
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8"/>
      <style>
        body      {{ font-family: 'Segoe UI', Arial, sans-serif; background:#050a0e; margin:0; padding:0; }}
        .wrapper  {{ max-width:520px; margin:40px auto; background:#0c1419;
                     border:1px solid #1a2e3a; border-radius:4px; overflow:hidden; }}
        .topbar   {{ height:3px; background:linear-gradient(90deg,#00d4ff,#00ff9d); }}
        .body     {{ padding:36px 40px; }}
        .logo     {{ font-size:18px; font-weight:800; color:#e8f4f8;
                     letter-spacing:.1em; margin-bottom:28px; }}
        .logo span{{ color:#00d4ff; }}
        h2        {{ color:#e8f4f8; font-size:16px; margin:0 0 12px; font-weight:600; }}
        p         {{ color:#7a9aaa; font-size:14px; line-height:1.6; margin:0 0 20px; }}
        .otp-box  {{ background:#111d24; border:1px solid #1a2e3a; border-left:3px solid #00d4ff;
                     border-radius:2px; padding:20px; text-align:center; margin:24px 0; }}
        .otp-code {{ font-family:'Courier New',monospace; font-size:36px; font-weight:700;
                     color:#00d4ff; letter-spacing:.3em; }}
        .otp-note {{ color:#4a6a7a; font-size:12px; margin-top:8px; }}
        .warning  {{ background:rgba(255,71,87,.06); border-left:3px solid #ff4757;
                     border-radius:2px; padding:12px 16px; color:#ff8593;
                     font-size:13px; margin-top:20px; }}
        .footer   {{ background:#080f14; padding:16px 40px;
                     color:#2a4a5a; font-size:11px; letter-spacing:.04em; }}
      </style>
    </head>
    <body>
      <div class="wrapper">
        <div class="topbar"></div>
        <div class="body">
          <div class="logo">Secure<span>Auth</span></div>
          <h2>Your one-time verification code</h2>
          <p>Hi <strong style="color:#e8f4f8">{username}</strong>, a login attempt was detected
             for your account. Use the code below to complete verification.</p>
          <div class="otp-box">
            <div class="otp-code">{otp_code}</div>
            <div class="otp-note">Valid for 30 seconds &nbsp;·&nbsp; Do not share this code</div>
          </div>
          <p>Requested at <strong style="color:#e8f4f8">{now_str}</strong>.<br/>
             If you did not attempt to log in, please change your password immediately.</p>
          <div class="warning">
            ⚠ &nbsp;SecureAuth will never ask for this code over phone or email.
          </div>
        </div>
        <div class="footer">
          © {datetime.now().year} SecureAuth · Adaptive MFA System · Do not reply to this email
        </div>
      </div>
    </body>
    </html>
    """

    # ── Plain-text fallback ───────────────────────────────────────────────────
    text_body = (
        f"Hi {username},\n\n"
        f"Your SecureAuth verification code is: {otp_code}\n\n"
        f"Valid for 30 seconds. Do not share this code.\n\n"
        f"Requested at {now_str}.\n"
        f"If you did not attempt to log in, change your password immediately.\n"
    )

    # ── Build MIME message ────────────────────────────────────────────────────
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"SecureAuth <{GMAIL_ADDRESS}>"
    msg["To"]      = to_email
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    # ── Send via Gmail SMTP TLS ───────────────────────────────────────────────
    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(GMAIL_ADDRESS, GMAIL_APP_PASS)
            server.sendmail(GMAIL_ADDRESS, to_email, msg.as_string())
        logger.info("[OTP] Email sent to %s", to_email)
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error("[OTP] Gmail authentication failed — check GMAIL_APP_PASS")
    except smtplib.SMTPException as exc:
        logger.error("[OTP] SMTP error: %s", exc)
    except Exception as exc:
        logger.error("[OTP] Unexpected email error: %s", exc)
    return False


# ── Flask route: POST /api/auth/otp ──────────────────────────────────────────

@otp_bp.route("/otp", methods=["POST"])
def verify_otp_route():
    """
    Step 2 of the adaptive login flow — verify submitted OTP.

    Request JSON
    ------------
    { "otp": "123456" }

    Response JSON (success)
    -----------------------
    { "message": str, "next_step": "face" | "dashboard" }

    Response JSON (error)
    ---------------------
    { "error": str }
    """
    # Must have completed Step 1
    user_id = session.get(SESSION_KEY_USER)
    if not user_id:
        return jsonify({"error": "Session expired. Please log in again."}), 401

    data = request.get_json(silent=True) or {}
    code = (data.get("otp") or "").strip()

    if not code:
        return jsonify({"error": "OTP code is required."}), 400

    # Fetch user's TOTP secret
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    if not verify_otp(user["otp_secret"], code):
        return jsonify({"error": "Invalid or expired OTP. Please try again."}), 401

    # OTP verified — decide next step based on risk tier
    risk_tier = session.get(SESSION_KEY_TIER, "medium")
    log_id    = session.get(SESSION_KEY_LOG)

    if risk_tier == "high":
        # Face verification still required
        return jsonify({
            "message":   "OTP verified. Facial verification required.",
            "next_step": "face"
        }), 200
    else:
        # Medium risk — fully authenticated
        if log_id:
            update_login_outcome(log_id, "success")
        return jsonify({
            "message":   "OTP verified. Access granted.",
            "next_step": "dashboard"
        }), 200


# ── Flask route: POST /api/auth/resend-otp ───────────────────────────────────

@otp_bp.route("/resend-otp", methods=["POST"])
def resend_otp_route():
    """
    Regenerate and resend OTP to the user's registered email.
    Rate-limited to prevent abuse (max 3 resends per session).
    """
    user_id = session.get(SESSION_KEY_USER)
    if not user_id:
        return jsonify({"error": "Session expired. Please log in again."}), 401

    # Simple in-session rate limit
    resend_count = session.get("otp_resend_count", 0)
    if resend_count >= 3:
        return jsonify({"error": "Maximum resend limit reached. Please log in again."}), 429

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    otp_code = generate_otp(user["otp_secret"])
    sent     = send_otp_email(user["email"], user["username"], otp_code)

    if not sent:
        return jsonify({"error": "Failed to send OTP. Please try again."}), 500

    session["otp_resend_count"] = resend_count + 1
    logger.info("[OTP] Resent OTP to user_id=%d (resend #%d)", user_id, resend_count + 1)

    return jsonify({"message": "OTP resent successfully."}), 200


# ── Helper: send OTP during login (called by app.py after password verified) ──

def trigger_otp_for_user(user_id: int) -> bool:
    """
    Generate and email an OTP for a user.
    Called by app.py immediately after successful password verification
    when risk tier is medium or high.

    Returns True if email sent successfully.
    """
    user = get_user_by_id(user_id)
    if not user:
        logger.error("[OTP] trigger_otp_for_user: user_id=%d not found", user_id)
        return False

    otp_code = generate_otp(user["otp_secret"])
    return send_otp_email(user["email"], user["username"], otp_code)


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    # Generate a random secret and test OTP generation + verification
    secret = pyotp.random_base32()
    code   = generate_otp(secret)

    print(f"\n── OTP Smoke Test ──")
    print(f"  Secret     : {secret}")
    print(f"  Generated  : {code}")
    print(f"  Valid now  : {verify_otp(secret, code)}")
    print(f"  Wrong code : {verify_otp(secret, '000000')}")

    # Optional: test email sending
    if len(sys.argv) > 1:
        to = sys.argv[1]
        print(f"\n── Sending test email to {to} ──")
        ok = send_otp_email(to, "TestUser", code)
        print(f"  Sent: {ok}")
        print("  (Make sure GMAIL_ADDRESS and GMAIL_APP_PASS env vars are set)")
