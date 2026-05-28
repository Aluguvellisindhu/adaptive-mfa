"""
╔══════════════════════════════════════════════════════════════════╗
║     ADAPTIVE MFA — PyOTP Integration                            ║
║     Risk-Based OTP Enforcement with TOTP & HOTP                 ║
╚══════════════════════════════════════════════════════════════════╝

Modules:
  1. OTPManager       — TOTP / HOTP generation & verification
  2. RiskEngine       — Contextual risk scoring (0–10)
  3. AdaptiveMFA      — Orchestrates face + risk + OTP decision
  4. SecretStore      — Encrypted secret key management
  5. QRProvisioning   — QR code generation for authenticator apps
  6. Demo             — End-to-end simulation
"""
import pyotp
import mfa_engine
import time
import hashlib
import hmac
import base64
import json
import os
import datetime
import qrcode
import io
from dataclasses import dataclass, field
from typing import Optional, Dict, Any


# ══════════════════════════════════════════════════════════════════
# 1. DATA MODELS
# ══════════════════════════════════════════════════════════════════

@dataclass
class RiskSignal:
    name: str
    triggered: bool
    weight: int          # points contributed when triggered
    description: str

@dataclass
class RiskProfile:
    score: int           # 0–10
    tier: str            # low | medium | high
    signals: list
    timestamp: str

@dataclass
class AuthResult:
    success: bool
    method: str          # password | password+otp | password+otp+face
    risk_profile: RiskProfile
    otp_required: bool
    face_required: bool
    message: str
    session_token: Optional[str] = None


# ══════════════════════════════════════════════════════════════════
# 2. SECRET STORE  (simplified — use HSM / Vault in production)
# ══════════════════════════════════════════════════════════════════

class SecretStore:
    """
    Manages per-user TOTP/HOTP secret keys.
    In production: encrypt secrets at rest with AES-256-GCM
    and store in a dedicated secrets manager (AWS Secrets Manager,
    HashiCorp Vault, Azure Key Vault).
    """

    def __init__(self):
        self._store: Dict[str, Dict] = {}  # user_id → {totp_secret, hotp_secret, hotp_counter}

    # ── Enroll a new user ─────────────────────────────────────────
    def enroll(self, user_id: str) -> Dict[str, str]:
        """Generate fresh TOTP and HOTP secrets for a user."""
        totp_secret = pyotp.random_base32()   # 160-bit (32 chars base32)
        hotp_secret = pyotp.random_base32()

        self._store[user_id] = {
            "totp_secret": totp_secret,
            "hotp_secret": hotp_secret,
            "hotp_counter": 0,
            "enrolled_at": datetime.datetime.utcnow().isoformat(),
        }

        print(f"\n  ✅ Enrolled user '{user_id}'")
        print(f"     TOTP Secret : {totp_secret}")
        print(f"     HOTP Secret : {hotp_secret}")
        return {"totp_secret": totp_secret, "hotp_secret": hotp_secret}

    def get_totp_secret(self, user_id: str) -> Optional[str]:
        return self._store.get(user_id, {}).get("totp_secret")

    def get_hotp_secret(self, user_id: str) -> Optional[str]:
        return self._store.get(user_id, {}).get("hotp_secret")

    def get_hotp_counter(self, user_id: str) -> int:
        return self._store.get(user_id, {}).get("hotp_counter", 0)

    def increment_hotp_counter(self, user_id: str):
        if user_id in self._store:
            self._store[user_id]["hotp_counter"] += 1

    def is_enrolled(self, user_id: str) -> bool:
        return user_id in self._store


# ══════════════════════════════════════════════════════════════════
# 3. OTP MANAGER  (TOTP + HOTP)
# ══════════════════════════════════════════════════════════════════

class OTPManager:
    """
    Handles TOTP (time-based) and HOTP (counter-based) OTP
    generation, provisioning URIs, and verification.

    TOTP — RFC 6238  (default: SHA1, 6 digits, 30s window)
    HOTP — RFC 4226
    """

    TOTP_INTERVAL  = 30      # seconds per window
    TOTP_DIGITS    = 6       # OTP length
    TOTP_VALID_WIN = 1       # ±1 window tolerance for clock drift

    def __init__(self, store: SecretStore):
        self.store = store

    # ─────────────────────────────────────────────────────────────
    # TOTP  (authenticator apps: Google Authenticator, Authy, etc.)
    # ─────────────────────────────────────────────────────────────

    def get_totp(self, user_id: str) -> pyotp.TOTP:
        secret = self.store.get_totp_secret(user_id)
        if not secret:
            raise ValueError(f"User '{user_id}' not enrolled")
        return pyotp.TOTP(
            secret,
            interval=self.TOTP_INTERVAL,
            digits=self.TOTP_DIGITS,
        )

    def generate_totp(self, user_id: str) -> str:
        """Generate the current TOTP code (for demo/testing)."""
        return self.get_totp(user_id).now()

    def verify_totp(self, user_id: str, token: str) -> bool:
        """
        Verify a TOTP token.
        valid_window=1 allows ±30s clock drift between client and server.
        """
        try:
            totp = self.get_totp(user_id)
            result = totp.verify(token, valid_window=self.TOTP_VALID_WIN)
            return result
        except Exception:
            return False

    def totp_remaining_seconds(self, user_id: str) -> int:
        """Seconds until current TOTP window expires."""
        totp = self.get_totp(user_id)
        return totp.interval - (int(time.time()) % totp.interval)

    def totp_provisioning_uri(self, user_id: str, issuer: str = "SecureAuth") -> str:
        """
        Returns the otpauth:// URI for QR code generation.
        Format: otpauth://totp/ISSUER:user@example.com?secret=XXX&issuer=ISSUER
        """
        totp = self.get_totp(user_id)
        return totp.provisioning_uri(name=user_id, issuer_name=issuer)

    # ─────────────────────────────────────────────────────────────
    # HOTP  (SMS / Email OTP — counter-based, single-use)
    # ─────────────────────────────────────────────────────────────

    def get_hotp(self, user_id: str) -> pyotp.HOTP:
        secret = self.store.get_hotp_secret(user_id)
        if not secret:
            raise ValueError(f"User '{user_id}' not enrolled")
        return pyotp.HOTP(secret, digits=self.TOTP_DIGITS)

    def generate_hotp(self, user_id: str) -> str:
        """Generate the next HOTP code and advance counter."""
        counter = self.store.get_hotp_counter(user_id)
        hotp = self.get_hotp(user_id)
        code = hotp.at(counter)
        # NOTE: counter is only incremented AFTER successful verification
        # (or when generating for delivery — do not double-increment)
        return code

    def verify_hotp(self, user_id: str, token: str) -> bool:
        """
        Verify an HOTP token.
        Looks ahead up to 5 counters to handle missed increments.
        """
        counter = self.store.get_hotp_counter(user_id)
        hotp = self.get_hotp(user_id)
        for offset in range(5):   # look-ahead window
            if hotp.verify(token, counter + offset):
                # Sync counter to the matched position + 1
                for _ in range(offset + 1):
                    self.store.increment_hotp_counter(user_id)
                return True
        return False

    def hotp_provisioning_uri(self, user_id: str, issuer: str = "SecureAuth") -> str:
        counter = self.store.get_hotp_counter(user_id)
        hotp = self.get_hotp(user_id)
        return hotp.provisioning_uri(name=user_id, issuer_name=issuer, initial_count=counter)


# ══════════════════════════════════════════════════════════════════
# 4. QR PROVISIONING
# ══════════════════════════════════════════════════════════════════

class QRProvisioning:
    """
    Generates QR codes for authenticator app setup.
    Saves as PNG; also returns base64 for embedding in HTML.
    """

    @staticmethod
    def generate(uri: str, filename: str = "otp_qr.png") -> str:
        """
        Generate a QR code PNG from the provisioning URI.
        Returns the base64-encoded PNG string.
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=8,
            border=3,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Save to file
        save_path = f"/mnt/user-data/outputs/{filename}"
        img.save(save_path)

        # Also encode to base64
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode()

        print(f"\n  📱 QR code saved → {save_path}")
        print(f"     URI: {uri[:70]}…")
        return b64


# ══════════════════════════════════════════════════════════════════
# 5. RISK ENGINE
# ══════════════════════════════════════════════════════════════════

class RiskEngine:
    """
    Evaluates contextual risk signals and computes a score 0–10.

    Signals & Weights:
      new_device        +3  — unrecognized device fingerprint
      unknown_location  +2  — geo outside user's normal region
      brute_force       +3  — repeated failed login attempts
      off_hours         +1  — login between 23:00–05:00
      unseen_ip         +1  — IP not seen in last 30 days

    Tiers:
      0–3   → LOW     (no OTP)
      4–6   → MEDIUM  (TOTP / HOTP required)
      7–10  → HIGH    (OTP + facial recognition)
    """

    SIGNAL_DEFINITIONS = {
        "new_device":        RiskSignal("new_device",        False, 3, "Unrecognized device fingerprint"),
        "unknown_location":  RiskSignal("unknown_location",  False, 2, "New geographic region"),
        "brute_force":       RiskSignal("brute_force",       False, 3, "Repeated failed login attempts"),
        "off_hours":         RiskSignal("off_hours",         False, 1, "Login outside normal hours (23:00–05:00)"),
        "unseen_ip":         RiskSignal("unseen_ip",         False, 1, "IP not seen in past 30 days"),
    }

    def evaluate(self, context: Dict[str, Any]) -> RiskProfile:
        """
        Evaluate a login context dict and return a RiskProfile.

        context keys (all bool):
          new_device, unknown_location, brute_force, off_hours, unseen_ip
        """
        total = 0
        fired = []

        for key, signal in self.SIGNAL_DEFINITIONS.items():
            triggered = bool(context.get(key, False))
            s = RiskSignal(
                name=signal.name,
                triggered=triggered,
                weight=signal.weight,
                description=signal.description,
            )
            if triggered:
                total += signal.weight
            fired.append(s)

        total = min(10, total)

        if total <= 3:
            tier = "low"
        elif total <= 6:
            tier = "medium"
        else:
            tier = "high"

        return RiskProfile(
            score=total,
            tier=tier,
            signals=fired,
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        )


# ══════════════════════════════════════════════════════════════════
# 6. ADAPTIVE MFA ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════

class AdaptiveMFA:
    """
    Main orchestrator for the Adaptive MFA flow.

    Decision Tree:
      LOW  risk  → password only                 (no OTP)
      MED  risk  → password + TOTP/HOTP          (step-up OTP)
      HIGH risk  → password + OTP + face ID      (full MFA)

    Usage:
      mfa = AdaptiveMFA()
      mfa.enroll_user("alice@example.com")
      result = mfa.authenticate("alice@example.com", context={...}, provided_otp="123456")
    """

    def __init__(self):
        self.store   = SecretStore()
        self.otp     = OTPManager(self.store)
        self.risk    = RiskEngine()
        self.qr      = QRProvisioning()
        self._sessions: Dict[str, Dict] = {}

    # ── Enrollment ────────────────────────────────────────────────
    def enroll_user(self, user_id: str, save_qr: bool = True) -> Dict:
        """
        Enroll a new user: generate secrets and optionally save QR.
        Returns enrollment info including provisioning URI.
        """
        secrets  = self.store.enroll(user_id)
        totp_uri = self.otp.totp_provisioning_uri(user_id)
        hotp_uri = self.otp.hotp_provisioning_uri(user_id)

        qr_b64 = None
        if save_qr:
            safe_id = user_id.replace("@", "_at_").replace(".", "_")
            qr_b64  = self.qr.generate(totp_uri, filename=f"totp_qr_{safe_id}.png")

        return {
            "user_id":         user_id,
            "totp_secret":     secrets["totp_secret"],
            "hotp_secret":     secrets["hotp_secret"],
            "totp_uri":        totp_uri,
            "hotp_uri":        hotp_uri,
            "qr_base64":       qr_b64,
        }

    # ── Step 1: Assess Risk ───────────────────────────────────────
    def assess_risk(self, user_id: str, context: Dict[str, Any]) -> RiskProfile:
        """Evaluate login context and return risk profile."""
        return self.risk.evaluate(context)

    # ── Step 2: Determine OTP need ───────────────────────────────
    def otp_required(self, risk: RiskProfile) -> bool:
        return risk.tier in ("medium", "high")

    def face_required(self, risk: RiskProfile) -> bool:
        return risk.tier == "high"

    # ── Step 3: Generate OTP for delivery ────────────────────────
    def generate_otp_for_delivery(self, user_id: str, method: str = "totp") -> str:
        """
        Generate an OTP to send to the user (SMS/email = HOTP,
        authenticator app = user reads TOTP themselves).
        Returns the code string.
        """
        if not self.store.is_enrolled(user_id):
            raise ValueError(f"User '{user_id}' is not enrolled in MFA")

        if method == "totp":
            code = self.otp.generate_totp(user_id)
            secs = self.otp.totp_remaining_seconds(user_id)
            print(f"\n  🔐 TOTP for {user_id}: {code}  (expires in {secs}s)")
        else:  # hotp / sms / email
            code = self.otp.generate_hotp(user_id)
            print(f"\n  📱 HOTP for {user_id}: {code}  (single-use)")

        return code

    # ── Step 4: Full Authentication ───────────────────────────────
    def authenticate(
        self,
        user_id:         str,
        context:         Dict[str, Any],
        provided_otp:    Optional[str] = None,
        otp_method:      str = "totp",     # totp | hotp
        face_verified:   bool = False,
        face_confidence: float = 0.0,
    ) -> AuthResult:
        """
        Full adaptive authentication flow.

        Args:
            user_id:          user identifier
            context:          risk signal dict (see RiskEngine)
            provided_otp:     OTP entered by user (None if not yet provided)
            otp_method:       'totp' or 'hotp'
            face_verified:    result from facial recognition service
            face_confidence:  match confidence score (0.0–1.0)

        Returns:
            AuthResult with success status and session token if granted.
        """
        if not self.store.is_enrolled(user_id):
            return AuthResult(
                success=False, method="none",
                risk_profile=RiskProfile(0,"low",[],datetime.datetime.utcnow().isoformat()),
                otp_required=False, face_required=False,
                message=f"User '{user_id}' not enrolled in MFA system."
            )

        # ① Risk assessment
        profile = self.assess_risk(user_id, context)
        otp_req  = self.otp_required(profile)
        face_req = self.face_required(profile)

        # ② OTP verification (if required)
        if otp_req:
            if provided_otp is None:
                return AuthResult(
                    success=False, method="pending_otp",
                    risk_profile=profile,
                    otp_required=True, face_required=face_req,
                    message=f"OTP required (risk={profile.score}/10, tier={profile.tier}). Please provide OTP."
                )
            # Verify OTP
            if otp_method == "totp":
                otp_ok = self.otp.verify_totp(user_id, provided_otp)
            else:
                otp_ok = self.otp.verify_hotp(user_id, provided_otp)

            if not otp_ok:
                return AuthResult(
                    success=False, method="otp_failed",
                    risk_profile=profile,
                    otp_required=True, face_required=face_req,
                    message="❌ OTP verification failed. Invalid or expired token."
                )

        # ③ Facial recognition (if required)
        if face_req:
            MIN_CONFIDENCE = 0.85
            if not face_verified or face_confidence < MIN_CONFIDENCE:
                return AuthResult(
                    success=False, method="face_failed",
                    risk_profile=profile,
                    otp_required=True, face_required=True,
                    message=f"❌ Facial recognition failed. Confidence {face_confidence:.2f} < {MIN_CONFIDENCE}"
                )

        # ④ Determine auth method label
        if not otp_req:
            method_label = "password"
        elif not face_req:
            method_label = "password + OTP"
        else:
            method_label = "password + OTP + face ID"

        # ⑤ Issue session token
        token = self._issue_session_token(user_id, profile)

        return AuthResult(
            success=True,
            method=method_label,
            risk_profile=profile,
            otp_required=otp_req,
            face_required=face_req,
            message=f"✅ Authentication successful via [{method_label}]",
            session_token=token,
        )

    def _issue_session_token(self, user_id: str, profile: RiskProfile) -> str:
        """Generate a simple session token (use JWT in production)."""
        raw = f"{user_id}:{profile.score}:{profile.tier}:{time.time()}"
        token = hashlib.sha256(raw.encode()).hexdigest()[:32]
        self._sessions[token] = {
            "user_id":  user_id,
            "tier":     profile.tier,
            "score":    profile.score,
            "issued_at": datetime.datetime.utcnow().isoformat(),
            "expires_at": (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat(),
        }
        return token

    def validate_session(self, token: str) -> Optional[Dict]:
        """Validate a session token. Returns session info or None."""
        return self._sessions.get(token)


# ══════════════════════════════════════════════════════════════════
# 7. DEMO — END-TO-END SIMULATION
# ══════════════════════════════════════════════════════════════════

def separator(title: str = ""):
    line = "─" * 64
    if title:
        print(f"\n╔{line}╗")
        print(f"║  {title:<62}║")
        print(f"╚{line}╝")
    else:
        print(f"\n{'─'*66}")

def print_profile(profile: RiskProfile):
    colors = {"low": "🟢", "medium": "🟡", "high": "🔴"}
    print(f"\n  Risk Score : {profile.score}/10  {colors.get(profile.tier,'⚪')} {profile.tier.upper()}")
    print(f"  Timestamp  : {profile.timestamp}")
    print("  Signals    :")
    for s in profile.signals:
        status = "▲ TRIGGERED" if s.triggered else "  clear    "
        pts    = f"+{s.weight}pt" if s.triggered else "    "
        print(f"    {status} {pts}  {s.description}")

def print_result(result: AuthResult):
    icon = "✅" if result.success else "❌"
    print(f"\n  {icon} {result.message}")
    if result.session_token:
        print(f"  🎟  Session Token : {result.session_token}")
    print(f"  Auth Method    : {result.method}")
    print(f"  OTP Required   : {result.otp_required}")
    print(f"  Face Required  : {result.face_required}")


def run_demo():
    print("\n" + "═"*66)
    print("  ADAPTIVE MFA — PyOTP Demo")
    print("  Facial Recognition + Risk-Based OTP Enforcement")
    print("═"*66)

    mfa = AdaptiveMFA()

    # ── Enroll users ─────────────────────────────────────────────
    separator("STEP 1 — Enroll Users")
    mfa.enroll_user("alice@example.com")
    mfa.enroll_user("bob@example.com")
    mfa.enroll_user("charlie@example.com")

    # ── SCENARIO A: LOW RISK  (trusted device, known location) ───
    separator("SCENARIO A — Low Risk Login (Alice)")
    ctx_low = {
        "new_device":       False,
        "unknown_location": False,
        "brute_force":      False,
        "off_hours":        False,
        "unseen_ip":        False,
    }
    profile_a = mfa.assess_risk("alice@example.com", ctx_low)
    print_profile(profile_a)

    result_a = mfa.authenticate(
        "alice@example.com",
        context=ctx_low,
        # No OTP provided — not required
    )
    print_result(result_a)

    # ── SCENARIO B: MEDIUM RISK  (new device + new IP) ───────────
    separator("SCENARIO B — Medium Risk Login (Bob) — OTP Required")
    ctx_med = {
        "new_device":       True,   # +3
        "unknown_location": False,
        "brute_force":      False,
        "off_hours":        False,
        "unseen_ip":        True,   # +1  → total 4 → MEDIUM
    }
    profile_b = mfa.assess_risk("bob@example.com", ctx_med)
    print_profile(profile_b)

    # First call — no OTP yet
    result_no_otp = mfa.authenticate("bob@example.com", context=ctx_med)
    print_result(result_no_otp)

    # Generate OTP and verify
    print("\n  Generating TOTP for delivery to user…")
    otp_code = mfa.generate_otp_for_delivery("bob@example.com", method="totp")

    result_b = mfa.authenticate(
        "bob@example.com",
        context=ctx_med,
        provided_otp=otp_code,
        otp_method="totp",
    )
    print_result(result_b)

    # Simulate wrong OTP
    separator("SCENARIO B2 — Wrong OTP (Bob)")
    result_wrong = mfa.authenticate(
        "bob@example.com",
        context=ctx_med,
        provided_otp="000000",
        otp_method="totp",
    )
    print_result(result_wrong)

    # ── SCENARIO C: HIGH RISK  (brute force + unknown location) ──
    separator("SCENARIO C — High Risk Login (Charlie) — OTP + Face Required")
    ctx_high = {
        "new_device":       True,   # +3
        "unknown_location": True,   # +2
        "brute_force":      True,   # +3  → total 8 → HIGH
        "off_hours":        False,
        "unseen_ip":        False,
    }
    profile_c = mfa.assess_risk("charlie@example.com", ctx_high)
    print_profile(profile_c)

    # Generate HOTP for SMS delivery
    print("\n  Generating HOTP (SMS delivery)…")
    hotp_code = mfa.generate_otp_for_delivery("charlie@example.com", method="hotp")

    # Attempt with OTP but no face
    result_no_face = mfa.authenticate(
        "charlie@example.com",
        context=ctx_high,
        provided_otp=hotp_code,
        otp_method="hotp",
        face_verified=False,
        face_confidence=0.0,
    )
    print("\n  → Without face verification:")
    print_result(result_no_face)

    # Full success: OTP + face
    # Re-generate HOTP (counter advanced, so generate again)
    hotp_code2 = mfa.generate_otp_for_delivery("charlie@example.com", method="hotp")
    result_c = mfa.authenticate(
        "charlie@example.com",
        context=ctx_high,
        provided_otp=hotp_code2,
        otp_method="hotp",
        face_verified=True,
        face_confidence=0.97,
    )
    print("\n  → With face verification (confidence=0.97):")
    print_result(result_c)

    # ── SCENARIO D: Max risk (all signals) ───────────────────────
    separator("SCENARIO D — All Signals Triggered")
    ctx_max = {k: True for k in RiskEngine.SIGNAL_DEFINITIONS}
    profile_d = mfa.assess_risk("alice@example.com", ctx_max)
    print_profile(profile_d)

    # ── TOTP Properties ──────────────────────────────────────────
    separator("TOTP PROPERTIES")
    user = "alice@example.com"
    code = mfa.generate_otp_for_delivery(user, method="totp")
    secs = mfa.otp.totp_remaining_seconds(user)
    uri  = mfa.otp.totp_provisioning_uri(user)

    print(f"\n  Current TOTP  : {code}")
    print(f"  Expires in    : {secs}s")
    print(f"  Window size   : {OTPManager.TOTP_INTERVAL}s")
    print(f"  Digits        : {OTPManager.TOTP_DIGITS}")
    print(f"\n  Provisioning URI:")
    print(f"  {uri}")
    print(f"\n  Verify '{code}' → {mfa.otp.verify_totp(user, code)}")
    print(f"  Verify '000000' → {mfa.otp.verify_totp(user, '000000')}")

    # ── Session Validation ───────────────────────────────────────
    separator("SESSION TOKEN VALIDATION")
    if result_b.session_token:
        session = mfa.validate_session(result_b.session_token)
        print(f"\n  Token   : {result_b.session_token}")
        print(f"  Session : {json.dumps(session, indent=4)}")

    # ── Summary Table ────────────────────────────────────────────
    separator("SUMMARY")
    rows = [
        ("Alice",   "Low",    0,  "Password only",            result_a.success),
        ("Bob",     "Medium", 4,  "Password + TOTP",          result_b.success),
        ("Charlie", "High",   8,  "Password + HOTP + Face",   result_c.success),
    ]
    print(f"\n  {'User':<10} {'Tier':<10} {'Score':>6}  {'Method':<32} {'Auth':>6}")
    print("  " + "─"*62)
    for name, tier, score, method, ok in rows:
        icon = "✅" if ok else "❌"
        print(f"  {name:<10} {tier:<10} {score:>5}/10  {method:<32} {icon}")

    print("\n" + "═"*66)
    print("  Demo complete. QR codes saved to /mnt/user-data/outputs/")
    print("═"*66 + "\n")


if __name__ == "__main__":
    run_demo()
