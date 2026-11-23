"""Local speech-to-text (faster-whisper) running entirely on this PC.

Privacy: audio arrives as raw 16 kHz mono PCM, is transcribed in memory and discarded. Nothing is written to disk, nothing is logged
(not the audio, not the text), and the model is loaded with local_files_only so this module can never reach out to a model hub at run time."""
import os
import threading
from pathlib import Path

import numpy as np

MODEL_NAME = os.environ.get("SENTINEL_WHISPER_MODEL", "base.en")
MODEL_DIR = Path(os.environ.get("SENTINEL_WHISPER_DIR", Path(__file__).resolve().parent.parent / "models"))
MAX_SECONDS = 60
RATE = 16000
_model = None
_lock = threading.Lock()


def _load():
    global _model
    if _model is None:
        os.environ["HF_HUB_OFFLINE"] = "1"
        from faster_whisper import WhisperModel
        _model = WhisperModel(MODEL_NAME, device="cpu", compute_type="int8", download_root=str(MODEL_DIR), local_files_only=True)
    return _model


def status():
    try:
        import faster_whisper  # noqa: F401
    except Exception:
        return {"available": False, "reason": "faster-whisper is not installed on the host (pip install faster-whisper).", "model": MODEL_NAME}
    if not any(MODEL_DIR.glob("models--*whisper*" + MODEL_NAME.split("/")[-1] + "*")) and not any(MODEL_DIR.glob("*" + MODEL_NAME + "*")):
        return {"available": False, "reason": f"the local Whisper model '{MODEL_NAME}' is not downloaded into {MODEL_DIR.name}/.", "model": MODEL_NAME}
    return {"available": True, "model": MODEL_NAME, "local": True, "max_seconds": MAX_SECONDS}


def transcribe(pcm16: bytes) -> str:
    if len(pcm16) < RATE * 2 * 0.3:
        raise ValueError("recording too short")
    if len(pcm16) > RATE * 2 * MAX_SECONDS:
        raise ValueError(f"recording longer than {MAX_SECONDS}s")
    audio = np.frombuffer(pcm16[: len(pcm16) // 2 * 2], dtype="<i2").astype(np.float32) / 32768.0
    with _lock:
        segs, _ = _load().transcribe(audio, language="en", beam_size=1, vad_filter=False, condition_on_previous_text=False)
        return " ".join(s.text.strip() for s in segs).strip()[:300]
