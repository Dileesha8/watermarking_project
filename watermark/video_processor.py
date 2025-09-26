import cv2
import numpy as np
import os
import logging
from typing import Callable, Optional
from watermark.tamper_detector import TamperDetector   # ✅ NEW IMPORT

logger = logging.getLogger(__name__)

class VideoProcessor:
    """
    Video processing class for embedding watermarks in video files.
    Handles frame-by-frame processing with progress tracking.
    """

    def __init__(self):
        pass

    def get_video_info(self, video_path):
        """Get basic information about a video file"""
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                logger.error(f"Could not open video file: {video_path}")
                return None

            info = {
                'frame_count': int(cap.get(cv2.CAP_PROP_FRAME_COUNT)),
                'fps': cap.get(cv2.CAP_PROP_FPS),
                'width': int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)),
                'height': int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)),
                'codec': int(cap.get(cv2.CAP_PROP_FOURCC))
            }

            cap.release()
            logger.debug(f"Video info for {video_path}: {info}")
            return info
        except Exception as e:
            logger.error(f"Error getting video info for {video_path}: {e}")
            return None

    def embed_watermark_in_video(self, input_path, output_path, watermark_text,
                                 strength, watermarker, progress_callback: Optional[Callable] = None):
        """Embed watermark + dynamic authentication code in a video file"""
        try:
            cap = cv2.VideoCapture(input_path)
            if not cap.isOpened():
                return False

            fps = cap.get(cv2.CAP_PROP_FPS)
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

            if total_frames == 0:
                cap.release()
                return False

            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
            if not out.isOpened():
                cap.release()
                return False

            frame_count = 0
            td = TamperDetector(secret_key=b"your_strong_secret_key")

            while True:
                ret, frame = cap.read()
                if not ret:
                    break

                frame_count += 1
                try:
                    auth_code = td.generate_auth_code(frame)
                    payload = f"{watermark_text}|{auth_code}"
                    watermarked_frame = watermarker.embed_watermark(frame, payload, strength)
                    out.write(watermarked_frame)
                except Exception as e:
                    logger.warning(f"Error processing frame {frame_count}: {e}")
                    out.write(frame)

                if progress_callback:
                    progress_callback(frame_count, total_frames, "Processing")

            cap.release()
            out.release()

            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                logger.info(f"Video processing completed successfully: {output_path}")
                return True
            else:
                logger.error(f"Output video file is empty or missing: {output_path}")
                return False

        except Exception as e:
            logger.error(f"Error processing video {input_path}: {e}", exc_info=True)
            return False

    def extract_watermark_from_video(self, video_path, watermark_length, watermarker,
                                     frame_sample_rate=30):
        """Extract watermark from a video file by sampling frames"""
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return None

            frame_count = 0
            extracted_texts = []

            while True:
                ret, frame = cap.read()
                if not ret:
                    break

                if frame_count % frame_sample_rate == 0:
                    try:
                        extracted_text = watermarker.extract_watermark(frame, watermark_length)
                        if extracted_text and "Error" not in extracted_text:
                            extracted_texts.append(extracted_text)
                    except Exception as e:
                        logger.warning(f"Error extracting from frame {frame_count}: {e}")

                frame_count += 1
                if len(extracted_texts) >= 10:
                    break

            cap.release()

            if extracted_texts:
                from collections import Counter
                counter = Counter(extracted_texts)
                return counter.most_common(1)[0][0]
            else:
                return None

        except Exception as e:
            logger.error(f"Error extracting watermark from video: {e}")
            return None

    def validate_video_file(self, file_path):
        """Validate that a file is a readable video"""
        try:
            cap = cv2.VideoCapture(file_path)
            if not cap.isOpened():
                return False
            ret, frame = cap.read()
            cap.release()
            return ret and frame is not None
        except Exception:
            return False

    def get_video_duration(self, video_path):
        """Get video duration in seconds"""
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return 0
            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_count = cap.get(cv2.CAP_PROP_FRAME_COUNT)
            cap.release()
            return frame_count / fps if fps > 0 else 0
        except Exception:
            return 0

    def verify_tamper(self, video_path, watermark_length, watermarker,
                      secret_key: bytes, auth_len: int = 16, frame_sample_rate: int = 30):
        """Verify tamper detection by sampling frames"""
        td = TamperDetector(secret_key)
        tampered_frames = []

        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            logger.error(f"Could not open video file: {video_path}")
            return None

        frame_id = 0
        while True:
            ret, frame = cap.read()
            if not ret:
                break

            if frame_id % frame_sample_rate == 0:
                try:
                    extracted_text = watermarker.extract_watermark(frame, watermark_length)
                    if extracted_text and "|" in extracted_text:
                        wm_text, auth_code = extracted_text.split("|")
                        expected_code = td.generate_auth_code(frame, length=auth_len)
                        if auth_code != expected_code:
                            tampered_frames.append(frame_id)
                except Exception as e:
                    logger.warning(f"Error verifying frame {frame_id}: {e}")
                    tampered_frames.append(frame_id)

            frame_id += 1

        cap.release()
        logger.info(f"Tamper verification completed. Tampered frames: {tampered_frames}")
        return tampered_frames
