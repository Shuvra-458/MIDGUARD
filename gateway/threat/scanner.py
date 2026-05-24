# =============================================================================
#  MIDGUARD — gateway/threat/scanner.py
#  Phase 3: AI-Powered Threat Detection
#
#  What this file does:
#    Runs 4 independent scanners on every prompt that passes Phases 1 & 2.
#    All 4 run IN PARALLEL using asyncio.gather() for maximum speed.
#
#    Scanner 1 — Prompt Injection Detection
#      Uses LLM Guard transformer model when available.
#      Falls back to keyword matching in development.
#      Block threshold: score > 0.70
#
#    Scanner 2 — PII Detection
#      Uses spaCy NER + regex patterns.
#      Detects: credit cards, Aadhaar, PAN, SSN, emails, phone numbers.
#      Any PII found = immediate BLOCK.
#
#    Scanner 3 — Toxicity Detection
#      Uses LLM Guard Toxicity model when available.
#      Falls back to keyword matching in development.
#      Block threshold: score > 0.70
#
#    Scanner 4 — Token Smuggling Detection
#      Pure Python — no ML model needed.
#      Detects: Unicode homoglyphs, Base64 encoded attacks,
#               zero-width chars, mixed scripts.
#      Block threshold: score > 0.60
#
#  Graceful degradation:
#    Works in two modes:
#      FULL MODE  — LLM Guard + spaCy installed → transformer-based detection
#      BASIC MODE — Fallback rule-based detection → server still runs
# =============================================================================

import asyncio
import logging
import re
import unicodedata
import base64
from typing import Optional

from gateway.models.schemas import ThreatResult
from gateway.threat.emotion_detector import scan_emotion_cvv

logger = logging.getLogger("midguard.threat.scanner")


# =============================================================================
#  DEPENDENCY AVAILABILITY CHECKS
# =============================================================================

try:
    from llm_guard.input_scanners import PromptInjection, Toxicity
    LLM_GUARD_AVAILABLE = True
    logger.info("LLM Guard loaded — transformer-based detection active")
except ImportError:
    LLM_GUARD_AVAILABLE = False
    logger.warning(
        "LLM Guard not installed — using fallback detection. "
        "Install with: pip install llm-guard"
    )

try:
    import spacy
    _nlp = spacy.load("en_core_web_lg")
    SPACY_AVAILABLE = True
    logger.info("spaCy en_core_web_lg loaded — NER-based PII detection active")
except (ImportError, OSError):
    SPACY_AVAILABLE = False
    _nlp = None
    logger.warning(
        "spaCy model not found — using regex-only PII detection. "
        "Install with: python -m spacy download en_core_web_lg"
    )


# =============================================================================
#  PII REGEX PATTERNS
# =============================================================================

PII_PATTERNS = {
    "CREDIT_CARD": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"
        r"5[1-5][0-9]{14}|"
        r"3[47][0-9]{13}|"
        r"(?:\d{4}[-\s]){3}\d{4})\b"
    ),
    "AADHAAR_NUMBER": re.compile(
        r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b"
    ),
    "PAN_CARD": re.compile(
        r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"
    ),
    "SSN": re.compile(
        r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"
    ),
    "EMAIL_ADDRESS": re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    "PHONE_NUMBER": re.compile(
        r"\b(?:\+?91[-\s]?)?[6-9]\d{9}\b"
    ),
    "CVV": re.compile(
        r"(?:cvv|cvc|security\s+code)[\s:]*\d{3,4}", re.IGNORECASE
    ),
}

# Injection keywords for fallback scanner
INJECTION_KEYWORDS = [
    "ignore previous instructions",
    "ignore all instructions",
    "forget your instructions",
    "you are now",
    "pretend you are",
    "act as if",
    "roleplay as",
    "do anything now",
    "dan mode",
    "jailbreak",
    "bypass your",
    "override your",
    "disregard your",
    "you have no restrictions",
    "unlimited mode",
    "developer mode",
    "no restrictions",
    "reveal your system prompt",
    "show me your instructions",
    "ignore safety",
    "disable filters",
]

TOXICITY_KEYWORDS = [
    "you are worthless",
    "i hate you",
    "kill yourself",
    "go die",
    "you are stupid",
    "i will harm",
    "i will hurt",
]


# =============================================================================
#  SCANNER 1 — PROMPT INJECTION
# =============================================================================

async def scan_prompt_injection(prompt: str) -> dict:
    """
    Detects prompt injection and jailbreak attacks.
    Uses LLM Guard transformer model when available, keyword fallback otherwise.

    Returns: {"flagged": bool, "score": float, "reason": str}
    """
    if LLM_GUARD_AVAILABLE:
        try:
            scanner = PromptInjection()
            loop = asyncio.get_event_loop()
            _, is_valid, score = await loop.run_in_executor(
                None, lambda: scanner.scan("system", prompt)
            )
            threat_score = round(1.0 - score if score else 0.5, 3)
            return {
                "flagged": not is_valid,
                "score":   threat_score,
                "reason":  "Prompt injection detected by transformer model" if not is_valid else "",
            }
        except Exception as e:
            logger.error(f"LLM Guard injection scanner error: {e} — using fallback")

    # Fallback: keyword matching
    prompt_lower = prompt.lower()
    matched = [kw for kw in INJECTION_KEYWORDS if kw in prompt_lower]
    if matched:
        score = min(0.75 + (len(matched) - 1) * 0.05, 0.99)
        return {
            "flagged": True,
            "score":   round(score, 3),
            "reason":  f"Injection keyword detected: '{matched[0]}'",
        }
    return {"flagged": False, "score": 0.0, "reason": ""}


# =============================================================================
#  SCANNER 2 — PII DETECTION
# =============================================================================

# =============================================================================
#  SCANNER 2 — PII DETECTION
# =============================================================================

# Import the actual PII scanner module
from gateway.threat.pii_scanner import scan_for_pii as _run_pii_scanner

async def scan_pii(prompt: str) -> dict:
    """
    Detects PII using the dedicated pii_scanner.py module.
    This includes regex patterns, spaCy NER, AND PII extraction intent detection.
    
    Returns: {"flagged": bool, "pii_types": list, "reason": str}
    """
    result = await _run_pii_scanner(prompt)
    
    if result["score"] > 0.0 and result["pii_types"]:
        return {
            "flagged":   True,
            "score": result["score"],
            "pii_types": result["pii_types"],
            "reason":    f"PII detected: {', '.join(result['pii_types'])}",
        }
    
    return {"flagged": False, "score": 0.0, "pii_types": [], "reason": ""}


# =============================================================================
#  SCANNER 3 — TOXICITY
# =============================================================================

async def scan_toxicity(prompt: str) -> dict:
    """
    Detects toxic, threatening, or abusive content.
    Uses LLM Guard Toxicity model when available, keyword fallback otherwise.

    Returns: {"flagged": bool, "score": float, "reason": str}
    """
    if LLM_GUARD_AVAILABLE:
        try:
            scanner = Toxicity()
            loop = asyncio.get_event_loop()
            _, is_valid, score = await loop.run_in_executor(
                None, lambda: scanner.scan("system", prompt)
            )
            toxicity_score = round(1.0 - score if score else 0.0, 3)
            return {
                "flagged": not is_valid,
                "score":   toxicity_score,
                "reason":  "Toxic content detected by classifier" if not is_valid else "",
            }
        except Exception as e:
            logger.error(f"LLM Guard Toxicity scanner error: {e} — using fallback")

    # Fallback: keyword matching
    prompt_lower = prompt.lower()
    matched = [kw for kw in TOXICITY_KEYWORDS if kw in prompt_lower]
    if matched:
        score = min(0.72 + (len(matched) - 1) * 0.05, 0.99)
        return {
            "flagged": True,
            "score":   round(score, 3),
            "reason":  f"Toxic keyword detected: '{matched[0]}'",
        }
    return {"flagged": False, "score": 0.0, "reason": ""}


# =============================================================================
#  SCANNER 4 — TOKEN SMUGGLING / OBFUSCATION
# =============================================================================

async def scan_token_smuggling(prompt: str) -> dict:
    """
    Detects obfuscation techniques used to bypass text-based filters.
    Pure Python — no ML model required.

    Detects:
      - Zero-width characters (invisible chars between letters)
      - Unicode homoglyphs (Cyrillic letters replacing Latin)
      - Base64-encoded injection payloads
      - Mixed Unicode scripts

    Returns: {"flagged": bool, "score": float, "reason": str}
    """
    signals = []

    # Check 1: Zero-width characters
    zero_width = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad']
    if any(c in prompt for c in zero_width):
        signals.append("zero_width_characters")

    # Check 2: Unicode homoglyph ratio
    normalized = unicodedata.normalize("NFKD", prompt)
    ascii_only  = normalized.encode("ascii", "ignore").decode("ascii")
    orig_len    = len(prompt.replace(" ", ""))
    norm_len    = len(ascii_only.replace(" ", ""))
    if orig_len > 0 and (1 - norm_len / orig_len) > 0.15:
        signals.append("unicode_homoglyphs")

    # Check 3: Base64-encoded injection
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    for match in b64_pattern.findall(prompt):
        try:
            decoded = base64.b64decode(match + "==").decode("utf-8", errors="ignore")
            if any(kw in decoded.lower() for kw in INJECTION_KEYWORDS[:8]):
                signals.append("base64_encoded_injection")
                break
        except Exception:
            pass

    # Check 4: Mixed Unicode scripts (Latin + Cyrillic/Greek mix)
    latin_count    = sum(1 for c in prompt if 'LATIN'    in unicodedata.name(c, ''))
    cyrillic_count = sum(1 for c in prompt if 'CYRILLIC' in unicodedata.name(c, ''))
    greek_count    = sum(1 for c in prompt if 'GREEK'    in unicodedata.name(c, ''))
    if latin_count > 10 and (cyrillic_count + greek_count) > 2:
        mix_ratio = (cyrillic_count + greek_count) / max(latin_count, 1)
        if 0.02 < mix_ratio < 0.4:
            signals.append("mixed_unicode_scripts")

    if signals:
        score = min(0.60 + (len(signals) - 1) * 0.10, 0.99)
        return {
            "flagged": True,
            "score":   round(score, 3),
            "reason":  f"Obfuscation detected: {', '.join(signals)}",
        }
    return {"flagged": False, "score": 0.0, "reason": ""}


# =============================================================================
#  MAIN FUNCTION — Called from main.py
# =============================================================================

async def run_threat_detection(
    prompt:    str,
    threshold: float = 0.70,
) -> ThreatResult:
    """
    Runs all 4 scanners in parallel. Returns on the first threat found.

    Decision priority:
      1. Prompt injection (highest risk)
      2. PII (any PII = block)
      3. Toxicity
      4. Token smuggling
      5. High CVV Emotion Score (Psychological Manipulation)

    Args:
        prompt:    The user's message to scan
        threshold: Score above which detection triggers a BLOCK (default 0.70)

    Returns:
        ThreatResult(blocked=True)  if a threat is detected
        ThreatResult(blocked=False) if all scanners pass
    """
    logger.info(f"Threat detection: scanning {len(prompt)} chars")

    # Run all 4 scanners simultaneously
    injection_r, pii_r, toxicity_r, smuggling_r, emotion_r = await asyncio.gather(
        scan_prompt_injection(prompt),
        scan_pii(prompt),
        scan_toxicity(prompt),
        scan_token_smuggling(prompt),
        scan_emotion_cvv(prompt)
    )

    logger.debug(
        f"Scores — injection: {injection_r['score']:.3f} | "
        f"pii: {pii_r['flagged']} | "
        f"toxicity: {toxicity_r['score']:.3f} | "
        f"smuggling: {smuggling_r['score']:.3f}"
        f"cvv_emotion: {emotion_r.get('cvv_score', 0)}/100"
    )

    # Build detector_scores dict (always included in response for audit log)
    detector_scores = {
        "injection":  injection_r["score"],
        "toxicity":   toxicity_r["score"],
        "smuggling":  smuggling_r["score"],
        "pii":        0.95 if pii_r["flagged"] else 0.0,
        "emotion":    emotion_r.get("score", 0.0),
    }

    # Evaluate in priority order
    if injection_r["flagged"] and injection_r["score"] > threshold:
        logger.warning(f"THREAT BLOCKED — Injection | score: {injection_r['score']}")
        return ThreatResult(
            blocked=True,
            threat_score=injection_r["score"],
            reason=injection_r["reason"],
            layer="Threat Detection — Prompt Injection Scanner",
            triggered_detector="injection",
            detector_scores=detector_scores,
        )
    
    if pii_r["flagged"]:
        # Use the actual score from the scanner
        pii_score = pii_r.get("score", 0.95)
        detector_scores["pii"] = pii_score # Update the audit score

        logger.warning(f"THREAT BLOCKED - PII | types: {pii_r['pii_types']} | score: {pii_score}")
        return ThreatResult(
            blocked=True,
            threat_scope=pii_score,
            reason=pii_r["reason"],
            pii_types=pii_r["pii_types"],
            layer="Threat Detection - PII Scanner",
            triggered_detector="pii",
            detector_scores=detector_scores,
        )

    if toxicity_r["flagged"] and toxicity_r["score"] > threshold:
        logger.warning(f"THREAT BLOCKED — Toxicity | score: {toxicity_r['score']}")
        return ThreatResult(
            blocked=True,
            threat_score=toxicity_r["score"],
            reason=toxicity_r["reason"],
            layer="Threat Detection — Toxicity Scanner",
            triggered_detector="toxicity",
            detector_scores=detector_scores,
        )

    if smuggling_r["flagged"] and smuggling_r["score"] > 0.60:
        logger.warning(f"THREAT BLOCKED — Token Smuggling | score: {smuggling_r['score']}")
        return ThreatResult(
            blocked=True,
            threat_score=smuggling_r["score"],
            reason=smuggling_r["reason"],
            layer="Threat Detection — Token Smuggling Scanner",
            triggered_detector="smuggling",
            detector_scores=detector_scores,
        )
    
    if emotion_r["flagged"] and emotion_r["score"] >= 0.75:
        logger.warning(
            f"THREAT BLOCKED - High CVV Score | "
            f"emotion: {emotion_r.get('emotion')} | cvv: {emotion_r.get('cvv_score')}/100"
        )

        return ThreatResult(
            blocked=True,
            threat_score=emotion_r["score"],
            reason=emotion_r["reason"],
            layer="Threat Detection - AI Emotion & CVV Scanner",
            triggered_detector="emotion_cvv",
            detector_scores=detector_scores,
        )

    # All clear — return highest score seen for audit logging
    highest_score = max(detector_scores.values())
    logger.info(f"Threat detection: CLEAR | highest score: {highest_score:.3f}")

    return ThreatResult(
        blocked=False,
        threat_score=round(highest_score, 3),
        layer="Threat Detection",
        detector_scores=detector_scores,
    )