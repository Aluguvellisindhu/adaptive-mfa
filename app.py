"""
app.py — Adaptive MFA System
Flask entry point. Registers all blueprints, initialises the database,
and serves all HTML pages.

Run with:
    python app.py
"""

import os
import logging
from datetime import datetime, timezone, timedelta

from flask import Flask, render_template, session, jsonify, redirect, url_for, request

# ── Import all modules ────────────────────────────────────────────────────────
from database import init_db, get_db_stats
from auth import auth_bp, login_required, SESSION_KEY_USER, SESSION_KEY_TIER
from otp import otp_bp, trigger_otp_for_user
from face import face_auth_bp, face_enroll_bp

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # ── Secret key (use env var in production) ────────────────────────────────
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production-32chars!")
    app.config.update(
        SESSION_COOKIE_HTTPONLY = True,
        SESSION_COOKIE_SAMESITE = "Lax",
        SESSION_COOKIE_SECURE   = False,   # set True in production (HTTPS)
        PERMANENT_SESSION_LIFETIME = timedelta(hours=8),
    )

    # ── Register blueprints ───────────────────────────────────────────────────
    app.register_blueprint(auth_bp)        # /api/auth/password, /register, /logout
    app.register_blueprint(otp_bp)         # /api/auth/otp, /api/auth/resend-otp
    app.register_blueprint(face_auth_bp)   # /api/auth/face
    app.register_blueprint(face_enroll_bp) # /api/face/enroll, /api/face/status

    # ── Initialise database on startup ────────────────────────────────────────
    with app.app_context():
        init_db()
        stats = get_db_stats()
        logger.info(
            "Database ready — users=%d login_events=%d active_sessions=%d",
            stats["users"], stats["login_events"], stats["active_sessions"]
        )

    # ── HTML page routes ──────────────────────────────────────────────────────

    @app.route("/")
    def index():
        """Redirect root to login or dashboard depending on session."""
        if session.get(SESSION_KEY_USER):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login")
    def login():
        """Serve the adaptive login page."""
        if session.get(SESSION_KEY_USER):
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.route("/register")
    def register_page():
        """Serve the registration page."""
        return render_template("register.html")

    @app.route("/enroll")
    def enroll_page():
        """Face enrollment page — only accessible after registration."""
        if not session.get(SESSION_KEY_USER):
            return redirect(url_for("login"))
        return render_template("enroll.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        """Protected dashboard — only reachable after full MFA."""
        return render_template("dashboard.html")

    # ── Trigger OTP after password verified ───────────────────────────────────
    # Override the /api/auth/password response to also send OTP email
    # when risk tier is medium or high.

    @app.after_request
    def send_otp_after_password(response):
        """
        Hook: after a successful /api/auth/password call,
        automatically trigger OTP email if tier is medium or high.
        """
        if (
            request.path == "/api/auth/password"
            and request.method == "POST"
            and response.status_code == 200
        ):
            user_id   = session.get(SESSION_KEY_USER)
            risk_tier = session.get(SESSION_KEY_TIER)
            if user_id and risk_tier in ("medium", "high"):
                sent = trigger_otp_for_user(user_id)
                if not sent:
                    logger.warning("[App] OTP email failed for user_id=%d", user_id)
        return response

    # ── Health check ──────────────────────────────────────────────────────────

    @app.route("/api/health")
    def health():
        """Quick health check endpoint."""
        stats = get_db_stats()
        return jsonify({
            "status":    "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database":  stats,
        }), 200

    # ── Error handlers ────────────────────────────────────────────────────────

    @app.errorhandler(401)
    def unauthorized(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required."}), 401
        return redirect(url_for("login"))

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Endpoint not found."}), 404
        return render_template("login.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        logger.error("[App] Internal server error: %s", e)
        return jsonify({"error": "Internal server error."}), 500

    return app


# ── Run ───────────────────────────────────────────────────────────────────────

app = create_app()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )
    from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("login.html")