# =============================================================================
#  MIDGUARD — gateway/threat/injection_detector.py
#  Prompt Injection Detector
#
#  What this file does:
#    Detects prompt injection attacks using a two-layer approach:
#
#    Layer 1 — LLM Guard Transformer (primary):
#      Uses DistilBERT fine-tuned on prompt injection datasets.
#      Returns a probability score 0.0–1.0.
#      This is the "smart" layer — catches semantic injections that
#      keyword rules miss, like token smuggling or creative phrasing.
#
#    Layer 2 — Pattern Matching (secondary / fallback):
#      A curated list of known injection patterns.
#      Runs even if LLM Guard fails.
#      Catches classic patterns with 100% certainty.
#
#  The final score = max(llm_guard_score, pattern_score)
#  Both layers run independently — either can trigger a BLOCK.
#
#  Detects:
#    T1 - Direct Prompt Injection   ("ignore previous instructions")
#    T2 - Indirect Prompt Injection (hidden instructions in content)
#    T3 - DAN Jailbreak             ("do anything now")
#    T4 - Roleplay Jailbreak        ("pretend you are...")
#    T5 - Token Smuggling           (unicode/base64 obfuscation)
# =============================================================================

import logging
import re
from typing import Optional

logger = logging.getLogger("midguard.threat.injection")

# =============================================================================
#  LLM GUARD LOADER
#  Loaded once at startup, reused for every request.
#  Loading a transformer model takes 2-5 seconds — we never load mid-request.
# =============================================================================

_injection_scanner = None   # LLM Guard scanner instance (loaded on first use)


def _get_injection_scanner():
    """
    Lazy-loads the LLM Guard PromptInjection scanner.

    Uses lazy loading (not startup loading) so the server starts
    fast even if the model hasn't downloaded yet. First request
    will be slow (model download), subsequent requests are fast.

    Returns:
        LLM Guard PromptInjection scanner, or None if unavailable
    """
    global _injection_scanner

    if _injection_scanner is not None:
        return _injection_scanner

    try:
        from llm_guard.input_scanners import PromptInjection
        from llm_guard.input_scanners.prompt_injection import MatchType

        _injection_scanner = PromptInjection(
            threshold=0.5,           # We apply our own threshold — use low value here
            match_type=MatchType.FULL,
        )
        logger.info("✓ LLM Guard PromptInjection scanner loaded")
        return _injection_scanner

    except ImportError:
        logger.warning(
            "LLM Guard not installed. Running in pattern-only mode. "
            "Install with: pip install llm-guard"
        )
        return None
    except Exception as e:
        logger.error(f"Failed to load LLM Guard injection scanner: {e}")
        return None


# =============================================================================
#  KNOWN INJECTION PATTERNS
#  Classic prompt injection patterns with fixed scores.
#  These are caught regardless of whether LLM Guard is available.
# =============================================================================

INJECTION_PATTERNS = [
    # Direct injection — explicit override commands
    (r"ignore\s+(previous|all|prior|above|your)\s+instructions?",   0.94),
    (r"disregard\s+(previous|all|prior|above|your)\s+instructions?", 0.93),
    (r"forget\s+(everything|all|previous|prior|your)\s+(you|instructions?)", 0.91),
    (r"override\s+(your|all|previous)\s+(instructions?|rules?|guidelines?)", 0.92),
    (r"you\s+are\s+now\s+(in\s+)?developer\s+mode",                 0.89),
    (r"enter\s+(developer|god|admin|unrestricted)\s+mode",          0.88),

    # DAN jailbreak variants
    (r"\bDAN\b.*no\s+restrictions?",                                 0.91),
    (r"do\s+anything\s+now",                                         0.90),
    (r"jailbreak(ed)?\s+(mode|prompt|yourself)",                     0.92),
    (r"pretend\s+(you\s+have\s+no|there\s+are\s+no)\s+(rules?|limits?|restrictions?)", 0.87),

    # System prompt extraction
    (r"(reveal|show|print|display|output|repeat)\s+your\s+system\s+prompt", 0.88),
    (r"(reveal|show|tell\s+me)\s+(your|the)\s+(initial|original|base)\s+instructions?", 0.87),
    (r"what\s+(are|were)\s+your\s+(initial|original|exact)\s+instructions?", 0.85),

    # Roleplay injection
    (r"(pretend|act|behave)\s+(you\s+are|as\s+(if|though)\s+you\s+(are|were|have))", 0.72),
    (r"you\s+are\s+(now\s+)?(an?\s+)?AI\s+(from|without|that\s+has)",  0.78),
    (r"imagine\s+you\s+(are|were|have\s+become)\s+a\s+different",     0.71),

    # Token smuggling indicators
    (r"base64\s*(decode|encoded|:)",                                  0.76),
    (r"decode\s+the\s+following\s+and\s+(execute|run|follow)",       0.82),
    (r"[\u0400-\u04FF]{3,}",0.65), # Cyrillic characters mixed in text
]

# Compile all patterns once at module load (not per-request)
_compiled_patterns = [
    (re.compile(pattern, re.IGNORECASE), score)
    for pattern, score in INJECTION_PATTERNS
]


# =============================================================================
#  MAIN DETECTOR FUNCTION
# =============================================================================

async def detect_prompt_injection(prompt: str) -> dict:
    """
    Detects prompt injection attacks in the given prompt.

    Runs both LLM Guard transformer scoring AND pattern matching.
    Returns the higher of the two scores.

    Args:
        prompt: The user's message text

    Returns:
        dict with:
          score (float):   0.0–1.0 threat score
          pattern (str):   Which pattern triggered (if any)
          method (str):    "llm_guard" | "pattern" | "combined"
    """
    llm_score      = 0.0
    pattern_score  = 0.0
    triggered_name = None
    method         = "pattern"

    # ── LAYER 1: LLM Guard Transformer ───────────────────────────────────────
    scanner = _get_injection_scanner()
    if scanner is not None:
        try:
            # LLM Guard returns: (sanitized_prompt, is_valid, risk_score)
            _, is_valid, risk_score = scanner.scan(prompt)
            # is_valid=False means it detected injection
            # risk_score is the confidence of the detection
            llm_score = float(risk_score) if not is_valid else 0.0
            method    = "llm_guard"
            logger.debug(f"LLM Guard injection score: {llm_score:.3f}")
        except Exception as e:
            logger.warning(f"LLM Guard injection scan error: {e}")

    # ── LAYER 2: Pattern Matching ─────────────────────────────────────────────
    for compiled_pattern, score in _compiled_patterns:
        if compiled_pattern.search(prompt):
            if score > pattern_score:
                pattern_score  = score
                triggered_name = compiled_pattern.pattern[:50]

    if pattern_score > 0:
        logger.debug(f"Pattern injection score: {pattern_score:.3f}")

    # ── COMBINE SCORES ────────────────────────────────────────────────────────
    # Take the maximum — either layer can catch something the other misses
    final_score = max(llm_score, pattern_score)

    if llm_score > 0 and pattern_score > 0:
        method = "combined"
    elif pattern_score > llm_score:
        method = "pattern"

    return {
        "score":   final_score,
        "pattern": triggered_name,
        "method":  method,
    }