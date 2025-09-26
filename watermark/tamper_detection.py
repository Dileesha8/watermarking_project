import cv2, hmac, hashlib
from PIL import Image
import imagehash

class TamperDetector:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key

    def compute_phash(self, frame):
        # Convert frame (numpy BGR) to PIL for perceptual hash
        img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
        return str(imagehash.phash(img))

    def compute_hmac(self, digest):
        return hmac.new(self.secret_key, digest.encode(), hashlib.sha256).hexdigest()

    def generate_auth_code(self, frame):
        ph = self.compute_phash(frame)
        return self.compute_hmac(ph)[:16]  # 16 hex chars (~64 bits) to embed
