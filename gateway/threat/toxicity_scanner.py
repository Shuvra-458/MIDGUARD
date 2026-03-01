# =============================================================================
#  MIDGUARD — gateway/threat/toxicity_scanner.py
#  Toxicity Scanner
#
#  What this file does:
#    Detects toxic, abusive, threatening, or harmful content using:
#
#    Primary — LLM Guard Toxicity Scanner:
#      Uses a fine-tuned classifier model to detect:
#        - Hate speech and discrimination
#        - Threats and violence
#        - Harassment and abuse
#        - Sexually explicit content
#        - Self-harm content
#
#    Fallback — Keyword-based detection:
#      A curated list of severe toxicity indicators.
#      Runs when LLM Guard is unavailable.
#
#  Detects:
#    T13 - Toxic / Harmful AI Response (output side)
#    Also catches toxic INPUT from users before it reaches the AI
# =============================================================================

import re
import logging

logger = logging.getLogger("midguard.threat.toxicity")

# =============================================================================
#  LLM GUARD TOXICITY SCANNER LOADER
# =============================================================================

_toxicity_scanner = None


def _get_toxicity_scanner():
    """Lazy-loads the LLM Guard Toxicity scanner."""
    global _toxicity_scanner
    if _toxicity_scanner is not None:
        return _toxicity_scanner

    try:
        from llm_guard.input_scanners import Toxicity

        _toxicity_scanner = Toxicity(threshold=0.5)
        logger.info("✓ LLM Guard Toxicity scanner loaded")
        return _toxicity_scanner

    except ImportError:
        logger.warning("LLM Guard not installed — using keyword toxicity fallback.")
        return None
    except Exception as e:
        logger.error(f"Failed to load LLM Guard toxicity scanner: {e}")
        return None


# =============================================================================
#  FALLBACK KEYWORD PATTERNS
#  Severe toxicity indicators used when LLM Guard is unavailable.
#  These are high-confidence patterns — very low false positive rate.
# =============================================================================

_SEVERE_TOXIC_PATTERNS = [
    # Explicit threats
    (r"\b(i\s+will|i['']m\s+going\s+to|i\s+want\s+to)\s+(kill|murder|hurt|harm|attack|destroy)\s+(you|them|him|her|all)", 0.90),
    (r"\b(kill|murder|bomb|shoot|stab|attack)\s+(yourself|everyone|all\s+of\s+you)",  0.92),

    # Targeted harassment
    (r"\b(you\s+are|you['']re)\s+(worthless|subhuman|garbage|disgusting|pathetic)\b", 0.82),
    (r"\bdie\s+(in\s+a\s+fire|already|slowly|painfully)\b",                           0.88),

    # Self harm
    (r"\b(how\s+to|best\s+way\s+to)\s+(kill|harm|hurt)\s+(myself|yourself)\b",       0.89),
    (r"\bsuicide\s+(method|how|instructions?|step)\b",                                 0.88),
]

_compiled_toxic = [
    (re.compile(p, re.IGNORECASE), s) for p, s in _SEVERE_TOXIC_PATTERNS
]


# =============================================================================
#  MAIN SCANNER FUNCTION
# =============================================================================

async def scan_for_toxicity(prompt: str) -> dict:
    """
    Scans for toxic or harmful content in the prompt.

    Args:
        prompt: The text to scan

    Returns:
        dict with score (float 0.0–1.0) and detected_type
    """
    llm_score     = 0.0
    pattern_score = 0.0
    detected_type = None

    # ── LLM Guard Primary ─────────────────────────────────────────────────────
    scanner = _get_toxicity_scanner()
    if scanner is not None:
        try:
            _, is_valid, risk_score = scanner.scan(prompt)
            llm_score = float(risk_score) if not is_valid else 0.0
            logger.debug(f"LLM Guard toxicity score: {llm_score:.3f}")
        except Exception as e:
            logger.warning(f"LLM Guard toxicity scan error: {e}")

    # ── Keyword Fallback ──────────────────────────────────────────────────────
    for compiled_pattern, score in _compiled_toxic:
        if compiled_pattern.search(prompt):
            if score > pattern_score:
                pattern_score = score
                detected_type = "explicit_threat_or_harm"

    final_score = max(llm_score, pattern_score)

    if final_score > 0:
        logger.info(f"Toxicity detected: score={final_score:.2f}")

    return {
        "score":         final_score,
        "detected_type": detected_type,
    }