from watermark.video_processor import VideoProcessor
from watermark.dct_watermark import DCTWatermark  # your existing class

# Create processor and watermark objects
vp = VideoProcessor()
wm = DCTWatermark()

# ---- Embed ----
vp.embed_watermark_in_video(
    input_path="input.mp4",      # <-- your original video path
    output_path="output.mp4",    # <-- path for watermarked video
    watermark_text="MyWatermark",
    strength=5,
    watermarker=wm
)

# ---- Verify ----
tampered_frames = vp.verify_tamper(
    video_path="output.mp4",
    watermark_length=len("MyWatermark"),  # ✅ original watermark text length
    watermarker=wm,
    secret_key=b"your_strong_secret_key"
)

if tampered_frames:
    print("⚠️ Tampering detected in frames:", tampered_frames)
else:
    print("✅ Video is authentic")
