import cv2, hmac, hashlib
from PIL import Image
import imagehash

class TamperDetector:
    def __init__(self, secret_key: bytes):
        """
        secret_key: a private key used to compute HMAC for authentication.
        """
        self.secret_key = secret_key

    def compute_phash(self, frame):
        """
        Compute perceptual hash of a frame (resistant to compression but sensitive to tampering).
        """
        img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
        return str(imagehash.phash(img))

    def compute_hmac(self, digest: str):
        """
        Compute HMAC of the pHash using the secret key.
        """
        return hmac.new(self.secret_key, digest.encode(), hashlib.sha256).hexdigest()

    def generate_auth_code(self, frame, length: int = 16):
        """
        Generate a short authentication code to embed inside the watermark.
        """
        ph = self.compute_phash(frame)
        return self.compute_hmac(ph)[:length]   # use first 16 hex chars (~64 bits)
