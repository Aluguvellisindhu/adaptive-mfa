# ============================================================
#   REAL-TIME FACE RECOGNITION USING FACENET + WEBCAM
# ============================================================
#
# HOW IT WORKS:
#   1. Webcam captures live video frames
#   2. MTCNN detects faces in each frame
#   3. FaceNet converts each face into 128 numbers (embedding)
#   4. Embeddings are compared to known faces in database
#   5. Name is displayed on screen if match is found
#
# INSTALL REQUIRED LIBRARIES (run these in terminal first):
#   pip install facenet-pytorch
#   pip install opencv-python
#   pip install torch torchvision
#   pip install pillow
#   pip install numpy
#
# ============================================================

import cv2                          # For webcam and drawing on screen
import torch                        # Deep learning framework
import numpy as np                  # For numerical operations
from PIL import Image               # For image processing
from facenet_pytorch import MTCNN, InceptionResnetV1  # FaceNet models


# ============================================================
# STEP 1: LOAD THE MODELS
# ============================================================

print("Loading models... please wait.")

# MTCNN = Face Detector
# It finds WHERE the face is in the image (draws a box around it)
mtcnn = MTCNN(
    image_size=160,        # Resize detected face to 160x160 pixels
    margin=20,             # Add 20px padding around the face
    keep_all=True,         # Detect ALL faces in frame (not just one)
    min_face_size=40,      # Ignore faces smaller than 40 pixels
    thresholds=[0.6, 0.7, 0.7],  # Confidence thresholds for detection
    factor=0.709,          # Scale factor for image pyramid
    post_process=True      # Normalize pixel values
)

# InceptionResnetV1 = FaceNet Model
# It converts a detected face into 128 numbers (embedding)
facenet_model = InceptionResnetV1(
    pretrained='vggface2'  # Pre-trained on VGGFace2 dataset (3.3M images)
).eval()                   # Set to evaluation mode (not training)

print("Models loaded successfully!")


# ============================================================
# STEP 2: CREATE YOUR FACE DATABASE
# ============================================================
# This dictionary stores known people and their face embeddings
# Key   = Person's name (string)
# Value = Their 128-number face embedding (tensor)

known_face_database = {}  # Empty at start, we will fill it below


def register_face_from_image(name, image_path):
    """
    Register a known person's face from an image file.

    Parameters:
        name       : Person's name (e.g., "Alice")
        image_path : Path to their photo (e.g., "alice.jpg")

    What it does:
        - Loads the photo
        - Detects the face in it
        - Extracts the 128-number embedding
        - Saves it in the database
    """
    # Load image using PIL
    img = Image.open(image_path).convert('RGB')

    # Detect and crop the face from the image
    # face_tensor will be a 160x160 face image as a tensor
    face_tensor = mtcnn(img)

    if face_tensor is None:
        print(f"No face found in {image_path}. Please use a clear face photo.")
        return

    # If multiple faces detected, use the first one
    if face_tensor.ndim == 4:
        face_tensor = face_tensor[0]

    # Add batch dimension: shape becomes [1, 3, 160, 160]
    face_tensor = face_tensor.unsqueeze(0)

    # Pass the face through FaceNet to get 128 numbers
    with torch.no_grad():  # No need to calculate gradients (saves memory)
        embedding = facenet_model(face_tensor)  # Output: 128 numbers

    # Save in database
    known_face_database[name] = embedding
    print(f"✅ Registered: {name}")


def register_face_from_webcam(name):
    """
    Register a known person's face directly from webcam.

    Parameters:
        name : Person's name (e.g., "Bob")

    What it does:
        - Opens webcam
        - Waits for you to press SPACE to capture
        - Detects face and saves embedding
    """
    cap = cv2.VideoCapture(0)  # Open default webcam (0 = first camera)
    print(f"\nRegistering face for: {name}")
    print("Look at the camera and press SPACE to capture your face.")
    print("Press Q to cancel.\n")

    while True:
        ret, frame = cap.read()  # Read one frame from webcam
        if not ret:
            print("Cannot read from webcam.")
            break

        # Show live webcam feed
        cv2.putText(frame, f"Registering: {name}", (20, 40),
                    cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
        cv2.putText(frame, "Press SPACE to capture | Q to cancel", (20, 80),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1)
        cv2.imshow("Register Face", frame)

        key = cv2.waitKey(1) & 0xFF

        if key == ord('q'):  # Q = cancel
            break

        elif key == ord(' '):  # SPACE = capture this frame
            # Convert BGR (OpenCV format) to RGB (PIL format)
            img_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img_pil = Image.fromarray(img_rgb)

            # Detect face in captured frame
            face_tensor = mtcnn(img_pil)

            if face_tensor is None:
                print("No face detected. Try again with better lighting.")
                continue

            # If multiple faces, use the first
            if face_tensor.ndim == 4:
                face_tensor = face_tensor[0]

            face_tensor = face_tensor.unsqueeze(0)

            # Extract 128-number embedding
            with torch.no_grad():
                embedding = facenet_model(face_tensor)

            # Save in database
            known_face_database[name] = embedding
            print(f"✅ Face registered for: {name}")
            break

    cap.release()
    cv2.destroyAllWindows()


# ============================================================
# STEP 3: FACE COMPARISON FUNCTION
# ============================================================

def find_matching_person(unknown_embedding, threshold=0.9):
    """
    Compare an unknown face's embedding against all known faces.

    Parameters:
        unknown_embedding : 128 numbers of the unknown face
        threshold         : Maximum distance to consider a match
                            (lower = stricter matching)
                            Recommended: 0.8 to 1.0

    Returns:
        name     : Name of matched person (or "Unknown")
        distance : How different the faces are (smaller = more similar)

    How distance works:
        Distance = 0.0  → Exact same face (perfect match)
        Distance < 0.9  → Same person (match!)
        Distance > 0.9  → Different person (no match)
    """
    best_match_name = "Unknown"
    best_match_distance = float('inf')  # Start with infinity

    # Compare unknown face against every known face in database
    for name, known_embedding in known_face_database.items():

        # Calculate Euclidean distance between two 128-number vectors
        # Small distance = similar faces = same person
        distance = torch.dist(unknown_embedding, known_embedding).item()

        # Keep track of the closest match
        if distance < best_match_distance:
            best_match_distance = distance
            best_match_name = name

    # If best distance is still too large, call it Unknown
    if best_match_distance > threshold:
        best_match_name = "Unknown"

    return best_match_name, best_match_distance


# ============================================================
# STEP 4: REAL-TIME RECOGNITION FROM WEBCAM
# ============================================================

def start_realtime_recognition():
    """
    Main function: Opens webcam and recognizes faces in real time.

    What happens every frame:
        1. Capture frame from webcam
        2. Detect all faces using MTCNN
        3. For each face:
           a. Extract 128-number embedding using FaceNet
           b. Compare to database
           c. Draw box and name on screen
    """
    if len(known_face_database) == 0:
        print("\n⚠️  No faces registered yet!")
        print("Please register at least one face before starting recognition.")
        return

    print("\n🎥 Starting real-time face recognition...")
    print("Press Q to quit.\n")

    # Open webcam
    cap = cv2.VideoCapture(0)

    # Set webcam resolution
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

    while True:
        # ── Capture one frame ──────────────────────────────
        ret, frame = cap.read()
        if not ret:
            print("Cannot read from webcam.")
            break

        # ── Convert frame for processing ───────────────────
        # OpenCV uses BGR color, but PIL/FaceNet needs RGB
        img_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        img_pil = Image.fromarray(img_rgb)

        # ── Detect faces in this frame ─────────────────────
        # boxes = list of [x1, y1, x2, y2] coordinates for each face
        # face_tensors = cropped 160x160 face images
        boxes, _ = mtcnn.detect(img_pil)       # Get bounding boxes
        face_tensors = mtcnn(img_pil)           # Get cropped face tensors

        # ── Process each detected face ─────────────────────
        if boxes is not None and face_tensors is not None:

            for i, (box, face_tensor) in enumerate(zip(boxes, face_tensors)):

                # Skip if face tensor is missing
                if face_tensor is None:
                    continue

                # Add batch dimension for FaceNet input
                face_input = face_tensor.unsqueeze(0)

                # Extract 128-number embedding for this face
                with torch.no_grad():
                    embedding = facenet_model(face_input)

                # Compare embedding to known faces in database
                name, distance = find_matching_person(embedding)

                # ── Draw results on screen ─────────────────
                x1, y1, x2, y2 = [int(coord) for coord in box]

                # Choose box color:
                # Green = recognized, Red = unknown
                if name == "Unknown":
                    box_color = (0, 0, 255)    # Red in BGR
                else:
                    box_color = (0, 255, 0)    # Green in BGR

                # Draw rectangle around the face
                cv2.rectangle(frame, (x1, y1), (x2, y2), box_color, 2)

                # Show name and distance above the box
                label = f"{name} ({distance:.2f})"
                cv2.rectangle(frame, (x1, y1 - 30), (x2, y1), box_color, -1)
                cv2.putText(frame, label, (x1 + 5, y1 - 8),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)

        # ── Show FPS and instructions ──────────────────────
        cv2.putText(frame, "Press Q to quit", (10, 30),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (200, 200, 200), 1)

        # ── Display the frame ──────────────────────────────
        cv2.imshow("Real-Time Face Recognition (FaceNet)", frame)

        # Press Q to quit
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    # Cleanup
    cap.release()
    cv2.destroyAllWindows()
    print("Recognition stopped.")


# ============================================================
# STEP 5: MAIN PROGRAM - RUN THIS
# ============================================================

if __name__ == "__main__":

    print("=" * 55)
    print("   REAL-TIME FACE RECOGNITION USING FACENET")
    print("=" * 55)

    # ----------------------------------------------------------
    # OPTION A: Register faces from image files
    # Uncomment and edit these lines with your actual image paths
    # ----------------------------------------------------------
    # register_face_from_image("Alice", "alice.jpg")
    # register_face_from_image("Bob",   "bob.jpg")

    # ----------------------------------------------------------
    # OPTION B: Register faces directly from webcam
    # The webcam opens, you look at it, press SPACE to capture
    # ----------------------------------------------------------
    print("\nHow many people do you want to register?")
    num_people = int(input("Enter number: "))

    for i in range(num_people):
        person_name = input(f"\nEnter name for person {i+1}: ")
        register_face_from_webcam(person_name)

    # ----------------------------------------------------------
    # START REAL-TIME RECOGNITION
    # ----------------------------------------------------------
    start_realtime_recognition()