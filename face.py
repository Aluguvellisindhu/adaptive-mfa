"""
face.py — Adaptive MFA System
Handles facial recognition enrollment and verification using the
face_recognition library (FaceNet 128-D embeddings, no custom training).

Flow:
  Enrollment  → /api/face/enroll   (during registration, saves 128-D vector)
  Verification → /api/auth/face    (Step 3 of high-risk login, compares vectors)

Depends on:
  database.py  — save_face_encoding, get_face_encoding, get_user_by_id
  auth.py      — SESSION_KEY_USER, SESSION_KEY_TIER, SESSION_KEY_LOG
"""

import logging
import base64
import io
import numpy as np
from flask import Blueprint, request, jsonify, session

# face_recognition uses dlib under the hood — pre-trained FaceNet model
import face_recognition
from PIL import Image

from database import (
    save_face_encoding,
    get_face_encoding,
    get_user_by_id,
    update_login_outcome,
)
from auth import SESSION_KEY_USER, SESSION_KEY_TIER, SESSION_KEY_LOG

logger = logging.getLogger(__name__)

# ── Blueprints ────────────────────────────────────────────────────────────────

face_auth_bp   = Blueprint("face_auth",   __name__, url_prefix="/api/auth")
face_enroll_bp = Blueprint("face_enroll", __name__, url_prefix="/api/face")

# ── Configuration ─────────────────────────────────────────────────────────────

FACE_MATCH_TOLERANCE = 0.45 # lower = stricter (0.4 very strict, 0.6 lenient)
MAX_IMAGE_SIZE       = (640, 480)   # resize large frames before processing
MIN_FACE_CONFIDENCE  = 0.9    # minimum detection confidence


# ── Core: decode base64 image ─────────────────────────────────────────────────

def decode_base64_image(data_url: str) -> np.ndarray | None:
    """
    Convert a base64 data URL (from WebRTC canvas capture) to an RGB numpy array.
    Accepts:  "data:image/jpeg;base64,/9j/4AAQ..."
              or raw base64 string without the prefix.
    Returns numpy array or None on failure.
    """
    try:
        # Strip the data URL prefix if present
        if "," in data_url:
            data_url = data_url.split(",", 1)[1]

        image_bytes = base64.b64decode(data_url)
        image       = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        image = image.point(lambda x: x * 1.5)
        from PIL import ImageEnhance
        image = ImageEnhance.Brightness(image).enhance(1.5)
        image = ImageEnhance.Contrast(image).enhance(1.5)

        # Resize if too large — speeds up detection significantly
        image.thumbnail(MAX_IMAGE_SIZE, Image.LANCZOS)

        return np.array(image)
    except Exception as exc:
        logger.error("[Face] Image decode failed: %s", exc)
        return None


# ── Core: extract face encoding ───────────────────────────────────────────────

def extract_encoding(image_array: np.ndarray) -> np.ndarray | None:
    try:
        # Try multiple upsampling levels for dark images
        for upsample in [2, 1, 0]:
            face_locations = face_recognition.face_locations(
                image_array,
                model="hog",
                number_of_times_to_upsample=upsample
            )
            if face_locations:
                break

        if len(face_locations) == 0:
            # Try CNN model as last resort
            try:
                face_locations = face_recognition.face_locations(
                    image_array, model="cnn"
                )
            except:
                pass

        if len(face_locations) == 0:
            logger.warning("[Face] No face detected in image")
            return None

        # Use first face if multiple detected
        face_locations = [face_locations[0]]

        encodings = face_recognition.face_encodings(
            image_array,
            known_face_locations=face_locations,
            model="large"
        )

        if not encodings:
            return None

        return encodings[0]

    except Exception as exc:
        logger.error("[Face] Encoding extraction failed: %s", exc)
        return None
    


# ── Core: compare encodings ───────────────────────────────────────────────────

def compare_faces(stored_encoding: np.ndarray, live_encoding: np.ndarray) -> dict:
    """
    Compare a stored face encoding against a live capture.

    Returns
    -------
    {
        "match":    bool,
        "distance": float,   # 0.0 = identical, 1.0 = completely different
        "confidence": float  # 0–100 percentage
    }
    """
    try:
        # face_distance returns Euclidean distance in 128-D space
        distance = face_recognition.face_distance(
            [stored_encoding], live_encoding
        )[0]

        match      = bool(distance <= FACE_MATCH_TOLERANCE)
        # Convert distance to a 0–100 confidence score
        confidence = round(max(0.0, (1.0 - distance) * 100), 1)

        return {
            "match":      match,
            "distance":   round(float(distance), 4),
            "confidence": confidence,
        }
    except Exception as exc:
        logger.error("[Face] Comparison failed: %s", exc)
        return {"match": False, "distance": 1.0, "confidence": 0.0}


# ── Enrollment ────────────────────────────────────────────────────────────────

def enroll_face(user_id: int, image_data_url: str) -> dict:
    """
    Process a webcam capture and save the face encoding for a user.
    Called during registration or from the /api/face/enroll route.

    Returns
    -------
    {"success": True}
    {"success": False, "error": str}
    """
    image_array = decode_base64_image(image_data_url)
    if image_array is None:
        return {"success": False, "error": "Could not decode image. Please try again."}

    encoding = extract_encoding(image_array)
    if encoding is None:
        return {
            "success": False,
            "error": (
                "No face detected. Please ensure your face is clearly visible, "
                "well-lit, and centred in the frame."
            )
        }

    save_face_encoding(user_id, encoding)
    logger.info("[Face] Enrolled face for user_id=%d", user_id)
    return {"success": True}


# ── Verification ──────────────────────────────────────────────────────────────

def verify_face(user_id: int, image_data_url: str) -> dict:
    """
    Verify a live webcam frame against the stored encoding for a user.

    Returns
    -------
    {
        "success":    bool,
        "match":      bool,
        "confidence": float,
        "error":      str | None
    }
    """
    # Load stored encoding
    stored_encoding = get_face_encoding(user_id)
    if stored_encoding is None:
        return {
            "success": False, "match": False, "confidence": 0.0,
            "error": "No face enrolled for this account. Please contact support."
        }

    # Decode live image
    image_array = decode_base64_image(image_data_url)
    if image_array is None:
        return {
            "success": False, "match": False, "confidence": 0.0,
            "error": "Could not decode image. Please try again."
        }

    # Extract live encoding
    live_encoding = extract_encoding(image_array)
    if live_encoding is None:
        return {
            "success": False, "match": False, "confidence": 0.0,
            "error": (
                "No face detected in the capture. Please ensure good lighting "
                "and that your face is centred in the frame."
            )
        }

    # Compare
    result = compare_faces(stored_encoding, live_encoding)
    logger.info(
        "[Face] Verification user_id=%d match=%s distance=%.4f confidence=%.1f%%",
        user_id, result["match"], result["distance"], result["confidence"]
    )

    return {
        "success":    result["match"],
        "match":      result["match"],
        "confidence": result["confidence"],
        "error":      None if result["match"] else (
            f"Face not recognised (confidence: {result['confidence']}%). "
            f"Please try again in better lighting."
        )
    }


# ── Flask route: POST /api/auth/face ─────────────────────────────────────────

@face_auth_bp.route("/face", methods=["POST"])
def verify_face_route():
    """
    Step 3 of the adaptive login flow — facial verification.

    Request JSON
    ------------
    { "image": "data:image/jpeg;base64,..." }

    Response JSON (success)
    -----------------------
    { "message": str, "confidence": float }

    Response JSON (error)
    ---------------------
    { "error": str }
    """
    user_id = session.get(SESSION_KEY_USER)
    if not user_id:
        return jsonify({"error": "Session expired. Please log in again."}), 401

    # Must be high-risk tier to reach this step
    risk_tier = session.get(SESSION_KEY_TIER)
    if risk_tier != "high":
        return jsonify({"error": "Face verification not required for this session."}), 400

    data      = request.get_json(silent=True) or {}
    image_url = data.get("image", "")

    if not image_url:
        return jsonify({"error": "No image data received."}), 400

    result = verify_face(user_id, image_url)

    if not result["success"]:
        return jsonify({"error": result["error"]}), 401

    # Face verified — mark login as fully successful
    log_id = session.get(SESSION_KEY_LOG)
    if log_id:
        update_login_outcome(log_id, "success")

    return jsonify({
        "message":    "Face verified. Access granted.",
        "confidence": result["confidence"],
    }), 200


# ── Flask route: POST /api/face/enroll ───────────────────────────────────────

@face_enroll_bp.route("/enroll", methods=["POST"])
def enroll_face_route():
    """
    Enroll a face during registration or profile setup.

    Request JSON
    ------------
    { "image": "data:image/jpeg;base64,..." }

    Response JSON (success)
    -----------------------
    { "message": "Face enrolled successfully." }
    """
    user_id = session.get(SESSION_KEY_USER)
    if not user_id:
        return jsonify({"error": "Authentication required."}), 401

    data      = request.get_json(silent=True) or {}
    image_url = data.get("image", "")

    if not image_url:
        return jsonify({"error": "No image data received."}), 400

    result = enroll_face(user_id, image_url)

    if not result["success"]:
        return jsonify({"error": result["error"]}), 400

    return jsonify({"message": "Face enrolled successfully."}), 200


# ── Flask route: GET /api/face/status ────────────────────────────────────────

@face_enroll_bp.route("/status", methods=["GET"])
def face_status_route():
    """Check whether the current user has a face enrolled."""
    user_id = session.get(SESSION_KEY_USER)
    if not user_id:
        return jsonify({"error": "Authentication required."}), 401

    encoding = get_face_encoding(user_id)
    return jsonify({"enrolled": encoding is not None}), 200


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    print("\n── face.py smoke test ──")
    print("  face_recognition library imported successfully ✓")
    print("  All functions defined:")
    print("    decode_base64_image()  ✓")
    print("    extract_encoding()     ✓")
    print("    compare_faces()        ✓")
    print("    enroll_face()          ✓")
    print("    verify_face()          ✓")
    print()
    print("  To test with a real image:")
    print("    1. Run app.py")
    print("    2. Register a user at http://127.0.0.1:5000/register")
    print("    3. Enroll face at http://127.0.0.1:5000/enroll")
    print("    4. Trigger a high-risk login to test Step 3")
    print()

    # Test encoding comparison with random vectors
    print("── Encoding comparison test ──")
    enc_a = np.random.rand(128)
    enc_b = enc_a + np.random.normal(0, 0.01, 128)   # very similar
    enc_c = np.random.rand(128)                        # completely different

    r1 = compare_faces(enc_a, enc_b)
    r2 = compare_faces(enc_a, enc_c)
    print(f"  Similar faces  → match={r1['match']} distance={r1['distance']} confidence={r1['confidence']}%")
    print(f"  Different faces→ match={r2['match']} distance={r2['distance']} confidence={r2['confidence']}%")
