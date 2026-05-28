"""
risk_engine.py — Adaptive MFA System
Calculates a risk score (0–10) from 5 signals and returns the auth tier.

Signals & weights:
  +3  New / unrecognised device fingerprint
  +3  Unusual geographic location (IP not seen before)
  +2  3+ failed login attempts in last 30 minutes
  +1  Login between 23:00 – 05:00 (user's local time, fallback UTC)
  +1  IP address not seen in last 30 days

Tiers:
  Low    (0–3)  → password only
  Medium (4–6)  → password + OTP
  High   (7+)   → password + OTP + face recognition
"""

import hashlib
import logging
import requests
from datetime import datetime, timezone, time as dtime
from dataclasses import dataclass, field

from database import (
    get_recent_failed_attempts,
    get_known_ips_for_user,
    get_known_devices_for_user,
)

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

TIER_LOW    = "low"
TIER_MEDIUM = "medium"
TIER_HIGH   = "high"

SCORE_MEDIUM_THRESHOLD = 1
SCORE_HIGH_THRESHOLD   = 7

# Off-hours window that adds +1 risk (23:00 – 05:00)
OFF_HOUR_START = 23
OFF_HOUR_END   = 5

# How many failed attempts in the window triggers +2
FAILED_ATTEMPT_THRESHOLD = 3
FAILED_ATTEMPT_WINDOW    = 30  # minutes

# IP history window for "known IP" signal
IP_HISTORY_DAYS = 30

# GeoIP provider (free, no key required for basic use)
GEOIP_URL = "https://ipapi.co/{ip}/json/"
GEOIP_TIMEOUT = 3  # seconds — never block login on slow GeoIP


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class RiskResult:
    score:        int
    tier:         str
    signals:      dict = field(default_factory=dict)
    ip_country:   str  = ""
    ip_city:      str  = ""

    def to_dict(self) -> dict:
        return {
            "risk_score":  self.score,
            "risk_tier":   self.tier,
            "signals":     self.signals,
            "ip_country":  self.ip_country,
            "ip_city":     self.ip_city,
        }


# ── Public entry point ────────────────────────────────────────────────────────

def calculate_risk(
    user_id:     int,
    ip_address:  str,
    user_agent:  str,
    accept_header: str = "",
) -> RiskResult:
    """
    Evaluate all 5 risk signals for this login attempt and return a RiskResult.

    Parameters
    ----------
    user_id       : int   — authenticated user's DB id
    ip_address    : str   — remote IP from Flask request
    user_agent    : str   — User-Agent header
    accept_header : str   — Accept header (used in device fingerprint)
    """
    score   = 0
    signals = {}

    # ── Signal 1: New device fingerprint (+3) ────────────────────────────────
    device_hash = _hash_device(user_agent, accept_header)
    known_devices = get_known_devices_for_user(user_id)
    new_device = device_hash not in known_devices

    if new_device:
        score += 3
        signals["new_device"] = {"triggered": True, "points": 3,
                                  "detail": "Unrecognised device fingerprint"}
    else:
        signals["new_device"] = {"triggered": False, "points": 0,
                                  "detail": "Known device"}

    # ── Signal 2: Unknown geographic location (+3) ────────────────────────────
    geo = _get_geo(ip_address)
    known_ips   = get_known_ips_for_user(user_id, within_days=IP_HISTORY_DAYS)
    unknown_geo = ip_address not in known_ips  # simplified: treat new IP as new geo

    if unknown_geo:
        score += 3
        signals["unknown_location"] = {
            "triggered": True, "points": 3,
            "detail": f"New IP {ip_address} ({geo.get('city','?')}, {geo.get('country_name','?')})"
        }
    else:
        signals["unknown_location"] = {"triggered": False, "points": 0,
                                        "detail": "Known location"}

    # ── Signal 3: Brute-force / repeated failures (+2) ────────────────────────
    recent_fails = get_recent_failed_attempts(user_id, within_minutes=FAILED_ATTEMPT_WINDOW)
    brute_force  = recent_fails >= FAILED_ATTEMPT_THRESHOLD

    if brute_force:
        score += 2
        signals["brute_force"] = {
            "triggered": True, "points": 2,
            "detail": f"{recent_fails} failed attempts in last {FAILED_ATTEMPT_WINDOW} min"
        }
    else:
        signals["brute_force"] = {"triggered": False, "points": 0,
                                   "detail": f"{recent_fails} recent failures"}

    # ── Signal 4: Off-hours login (+1) ────────────────────────────────────────
    off_hours = _is_off_hours()

    if off_hours:
        score += 1
        signals["off_hours"] = {"triggered": True, "points": 1,
                                  "detail": "Login between 23:00–05:00"}
    else:
        signals["off_hours"] = {"triggered": False, "points": 0,
                                  "detail": "Normal business hours"}

    # ── Signal 5: IP not seen in last 30 days (+1) ────────────────────────────
    ip_unseen = ip_address not in known_ips

    if ip_unseen:
        score += 1
        signals["unseen_ip"] = {"triggered": True, "points": 1,
                                  "detail": f"IP {ip_address} not seen in {IP_HISTORY_DAYS} days"}
    else:
        signals["unseen_ip"] = {"triggered": False, "points": 0,
                                  "detail": "IP seen recently"}

    # ── Cap at 10, derive tier ────────────────────────────────────────────────
    score = min(score, 10)
    tier  = _score_to_tier(score)

    logger.info(
        "[RiskEngine] user=%s ip=%s score=%d tier=%s signals=%s",
        user_id, ip_address, score, tier,
        {k: v["triggered"] for k, v in signals.items()}
    )

    return RiskResult(
        score      = score,
        tier       = tier,
        signals    = signals,
        ip_country = geo.get("country_name", ""),
        ip_city    = geo.get("city", ""),
    )


# ── Tier helper (usable standalone) ──────────────────────────────────────────

def _score_to_tier(score: int) -> str:
    if score >= SCORE_HIGH_THRESHOLD:
        return TIER_HIGH
    if score >= SCORE_MEDIUM_THRESHOLD:
        return TIER_MEDIUM
    return TIER_LOW


def tier_from_score(score: int) -> str:
    """Public alias — call this if you already have a score and just need the tier."""
    return _score_to_tier(score)


# ── Device fingerprinting ─────────────────────────────────────────────────────

def _hash_device(user_agent: str, accept_header: str) -> str:
    """
    Produce a stable SHA-256 hex fingerprint from browser signals.
    Raw headers are never stored — only this hash reaches the DB.
    """
    raw = f"{user_agent.strip()}|{accept_header.strip()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def hash_device(user_agent: str, accept_header: str = "") -> str:
    """Public alias used by auth.py when logging attempts."""
    return _hash_device(user_agent, accept_header)


# ── GeoIP lookup ──────────────────────────────────────────────────────────────

def _get_geo(ip_address: str) -> dict:
    """
    Fetch city/country for an IP via ipapi.co (free tier, no key needed).
    Returns an empty dict on any failure so login is never blocked by GeoIP.
    Skips lookup for loopback / private addresses.
    """
    if _is_private_ip(ip_address):
        return {"city": "localhost", "country_name": "Local"}

    try:
        resp = requests.get(
            GEOIP_URL.format(ip=ip_address),
            timeout=GEOIP_TIMEOUT,
            headers={"User-Agent": "AdaptiveMFA/1.0"}
        )
        if resp.ok:
            return resp.json()
    except Exception as exc:
        logger.warning("[RiskEngine] GeoIP lookup failed for %s: %s", ip_address, exc)

    return {}


def _is_private_ip(ip: str) -> bool:
    """Quick check for loopback / RFC-1918 / IPv6 loopback addresses."""
    private_prefixes = (
        "127.", "10.", "192.168.",
        "::1", "localhost",
    )
    # 172.16.0.0/12
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        except (IndexError, ValueError):
            pass
    return any(ip.startswith(p) for p in private_prefixes)


# ── Off-hours detection ───────────────────────────────────────────────────────

def _is_off_hours(now: datetime | None = None) -> bool:
    """
    Return True if the current UTC hour falls in the off-hours window (23:00–05:00).
    An optional `now` datetime can be injected for unit-testing.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    hour = now.hour
    # Window wraps midnight: 23, 0, 1, 2, 3, 4
    return hour >= OFF_HOUR_START or hour < OFF_HOUR_END


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    from database import init_db

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    init_db()

    # Provide a user_id that exists in your DB; default to 1 for quick testing
    uid = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    ip  = sys.argv[2] if len(sys.argv) > 2 else "8.8.8.8"

    result = calculate_risk(
        user_id=uid,
        ip_address=ip,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        accept_header="text/html,application/xhtml+xml",
    )

    print(f"\n{'─'*42}")
    print(f"  Risk Score : {result.score}/10")
    print(f"  Tier       : {result.tier.upper()}")
    print(f"  Location   : {result.ip_city}, {result.ip_country}")
    print(f"{'─'*42}")
    for name, sig in result.signals.items():
        status = "▲ TRIGGERED" if sig["triggered"] else "  ok"
        print(f"  {status}  +{sig['points']}pt  {name}: {sig['detail']}")
    print(f"{'─'*42}\n")