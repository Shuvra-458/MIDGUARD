# =============================================================================
#  MIDGUARD — gateway/threat/emotion_detector.py
#  Scanner 5: Local AI Intent & Injection Scoring (DeBERTa v3)
#
#  Uses a local HuggingFace transformer model instead of an external API.
#  Maps INJECTION probability to the CVV score format for Phase 4 enforcement.
# =============================================================================

import logging
import asyncio
from typing import Optional

logger = logging.getLogger("midguard.threat.emotion_detector")

# Global variable to hold the loaded AI model
_classifier = None
_model_loaded = False

def _load_model():
    """
    Loads the DeBERTa model into memory.
    Runs once when the server starts or on the first request.
    """
    global _classifier, _model_loaded
    if _model_loaded:
        return
    
    try:
        from transformers import pipeline
        logger.info("Loading local DeBERTa-v3 Prompt Injection model (this takes a few seconds)...")
        # device=-1 forces CPU usage (safer for Docker without GPU drivers)
        _classifier = pipeline(
            "text-classification", 
            model="protectai/deberta-v3-base-prompt-injection-v2", 
            top_k=2,
            device=-1
        )
        _model_loaded = True
        logger.info("✓ DeBERTa-v3 model loaded successfully into memory!")
    except Exception as e:
        logger.error(f"Failed to load DeBERTa model: {e}. Scanner 5 will be disabled.")


async def scan_emotion_cvv(prompt: str) -> dict:
    """
    Scans the prompt using the local DeBERTa model.
    Returns the standard MIDGUARD dictionary format so scanner.py doesn't break.
    """
    # Try to load the model on the first run
    if not _model_loaded:
        # Run blocking model loading in a separate thread so it doesn't freeze FastAPI
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _load_model)

    # If it still failed to load, return safe defaults
    if not _model_loaded or _classifier is None:
        return {"flagged": False, "score": 0.0, "reason": "", "cvv_score": 0, "emotion": "model_unavailable"}

    try:
        # Run the AI inference in a thread pool (transformers is synchronous)
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, _classifier, prompt)
        
        # Results look like: [{'label': 'INJECTION', 'score': 0.95}, {'label': 'SAFE', 'score': 0.05}]
        injection_score = 0.0
        emotion_label = "SAFE"
        
        for item in results[0]:
            if item['label'] == 'INJECTION':
                injection_score = item['score']
                emotion_label = "INJECTION"
            elif item['label'] == 'SAFE':
                if item['score'] > injection_score:
                    emotion_label = "SAFE"
        
        # Map 0.0-1.0 probability to 0-100 "CVV Score"
        cvv_score = int(injection_score * 100)
        is_flagged = cvv_score >= 75  # Block if >75% confident it's an injection
        
        reason = f"Local AI Scanner: {emotion_label} (Score: {cvv_score}/100)" if is_flagged else ""

        return {
            "flagged": is_flagged,
            "score": round(injection_score, 2),
            "reason": reason,
            "cvv_score": cvv_score,
            "emotion": emotion_label
        }

    except Exception as e:
        logger.error(f"Error running DeBERTa inference: {e}")
        return {"flagged": False, "score": 0.0, "reason": "", "cvv_score": 0, "emotion": "error"}