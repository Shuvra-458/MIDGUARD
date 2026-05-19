# =============================================================================
#  MIDGUARD — gateway/output/filter.py
#  Phase 5: Output Filter — AI Response Scanner
#
#  What this file does:
#    Phases 1–4 protect against threats coming FROM the user.
#    Phase 5 protects against threats coming FROM the AI agent's response.
#
#    Even if the user sent a perfectly safe request, the AI agent can still:
#      - Leak PII from its training data or from other users' sessions
#      - Hallucinate facts, numbers, or events that never happened
#      - Generate toxic or harmful content due to adversarial prompting
#      - Accidentally expose system configuration or internal data
#
#    Phase 5 intercepts the AI's response BEFORE it reaches the user
#    and runs it through three independent output scanners.
#
#  The 3 Output Scanners:
#    1. Output PII Scanner    — finds PII in the AI's response (NER + regex)
#    2. Hallucination Checker — checks if response is grounded in context
#    3. Output Toxicity Check — scans response for harmful content
#
#  Decision:
#    PASS   → Response is clean, return it to the user
#    REDACT → PII found, redact it and return sanitised version
#    BLOCK  → Toxic or severely hallucinated response, block entirely
#
#  This is what separates MIDGUARD from basic API key wrappers.
#  Output filtering is the most often missing layer in GenAI deployments.
#
#  Detects:
#    T11 - PII in AI Response (cross-user data leakage)
#    T12 - AI Hallucination (faithfulness < threshold)
#    T13 - Toxic AI Response (harmful output from the model)
# =============================================================================

import re
import logging
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger("midguard.output.filter")


# =============================================================================
#  OUTPUT FILTER RESULT
# =============================================================================

@dataclass
class OutputFilterResult:
    """
    Result from the output filter.

    Attributes:
        passed          : True if response can be returned (clean or redacted)
        blocked         : True if response must be completely blocked
        decision        : "PASS" | "REDACT" | "BLOCK"
        original_response: The raw response from the AI agent
        safe_response   : The cleaned/redacted response to return to user
                          (same as original if no issues found)
        reason          : Why it was redacted or blocked (if applicable)
        pii_found       : List of PII types found in the response
        hallucination_score: 0.0–1.0 (higher = more hallucinated)
        toxicity_score  : 0.0–1.0 (higher = more toxic)
        redactions_made : Number of redactions applied
    """
    passed:              bool
    blocked:             bool
    decision:            str
    original_response:   str
    safe_response:       str
    reason:              Optional[str]       = None
    pii_found:           list                = field(default_factory=list)
    hallucination_score: float               = 0.0
    toxicity_score:      float               = 0.0
    redactions_made:     int                 = 0


# =============================================================================
#  PII REDACTION PATTERNS
#  Same categories as the input PII scanner but applied to AI responses.
#  When found in output, we REDACT rather than BLOCK (more user-friendly).
# =============================================================================

# (pattern, replacement_label, severity)
_OUTPUT_PII_PATTERNS = [

    # Credit card — redact all but last 4 digits
    (
        re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|(?:\d[ -]?){13,19})\b'),
        "[CREDIT_CARD_REDACTED]",
        "CREDIT_CARD",
        0.89,
    ),

    # Aadhaar — 12 digit pattern
    (
        re.compile(r'\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b'),
        "[AADHAAR_REDACTED]",
        "AADHAAR_NUMBER",
        0.92,
    ),

    # PAN card
    (
        re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'),
        "[PAN_REDACTED]",
        "PAN_CARD",
        0.92,
    ),

    # SSN
    (
        re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'),
        "[SSN_REDACTED]",
        "SSN",
        0.92,
    ),

    # Email address
    (
        re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b'),
        "[EMAIL_REDACTED]",
        "EMAIL_ADDRESS",
        0.75,
    ),

    # Indian phone number
    (
        re.compile(r'(?:\+91[\s\-]?)?[6-9]\d{9}\b'),
        "[PHONE_REDACTED]",
        "PHONE_NUMBER",
        0.75,
    ),

    # CVV context
    (
        re.compile(r'\b(?:cvv|cvc|security\s+code)[:\s]+\d{3,4}\b', re.IGNORECASE),
        "[CVV_REDACTED]",
        "CVV",
        0.88,
    ),
]


# =============================================================================
#  HALLUCINATION DETECTION
#  Checks if the AI response is grounded in the provided context.
#  If no context is provided, we apply basic sanity checks only.
# =============================================================================

# Phrases that strongly indicate the AI is fabricating information
_HALLUCINATION_SIGNALS = [
    (re.compile(r'\b(as\s+of\s+yesterday|last\s+month|recently|according\s+to\s+our\s+records)\b', re.IGNORECASE), 0.35),
    (re.compile(r'\byou\s+(made|sent|transferred|withdrew)\b', re.IGNORECASE),                                      0.40),
    (re.compile(r'\b(may\s+not\s+be\s+accurate|approximate|estimated|roughly)\b', re.IGNORECASE),                   0.30),
    (re.compile(r'\b(100%|guaranteed|definitely|certainly|absolutely)\s+(accurate|correct|true)\b', re.IGNORECASE), 0.45),
    (re.compile(r'Note:\s*This\s+(figure|data|information)\s+may\s+not', re.IGNORECASE),                            0.55),
]


def _check_hallucination(response: str, context: Optional[str]) -> float:
    """
    Estimates the hallucination score of the AI response.
    Only runs word-overlap if context is a long reference document (>100 chars).
    """
    score = 0.0

    # Check for hallucination signal phrases
    for pattern, signal_score in _HALLUCINATION_SIGNALS:
        if pattern.search(response):
            score = max(score, signal_score)
            logger.debug(f"Hallucination signal detected: score={signal_score}")

    # If context provided, do basic faithfulness check
    # ONLY if context is long enough to be a reference document (> 100 chars)
    # Short contexts like "You are a banker" will skip this to avoid false positives
    if context and len(context.strip()) > 100:
        response_words = set(response.lower().split())
        context_words  = set(context.lower().split())

        significant_response_words = {
            w for w in response_words
            if len(w) > 5 and w.isalpha()
        }
        if significant_response_words:
            overlap = len(significant_response_words & context_words)
            coverage = overlap / len(significant_response_words)
            if coverage < 0.15:
                score = max(score, 0.50)
                logger.debug(f"Low context faithfulness: coverage={coverage:.2f}")

    return round(score, 2)


# =============================================================================
#  OUTPUT TOXICITY CHECK
#  Lightweight check specifically for AI response toxicity.
# =============================================================================

_OUTPUT_TOXIC_PATTERNS = [
    (re.compile(r'\b(kill|murder|attack|harm|hurt)\s+(yourself|all|everyone)\b', re.IGNORECASE), 0.90),
    (re.compile(r'\b(you\s+are|you\'re)\s+(worthless|subhuman|disgusting|pathetic)\b',           re.IGNORECASE), 0.85),
    (re.compile(r'\b(how\s+to|steps\s+to)\s+(make|build|create)\s+(a\s+)?bomb\b',               re.IGNORECASE), 0.95),
    (re.compile(r'\b(synthesize|manufacture)\s+(drugs|methamphetamine|heroin|cocaine)\b',         re.IGNORECASE), 0.92),
]


# TO SHOW THE TOXIC REPLAY UNCOMMENT THIS AND filter.py []

# _OUTPUT_TOXIC_PATTERNS = [
#     (re.compile(r'\b(kill|murder|attack|harm|hurt)\s+(yourself|all|everyone)\b', re.IGNORECASE), 0.90),

#     (
#         re.compile(
#             r'\b(you\s+are|you\'re)\s+(worthless|subhuman|disgusting|pathetic|useless|stupid|idiotic)\b',
#             re.IGNORECASE
#         ),
#         0.85
#     ),

#     (re.compile(r'\b(shut\s+up)\b', re.IGNORECASE), 0.80),

#     (re.compile(r'\b(how\s+to|steps\s+to)\s+(make|build|create)\s+(a\s+)?bomb\b', re.IGNORECASE), 0.95),

#     (re.compile(r'\b(synthesize|manufacture)\s+(drugs|methamphetamine|heroin|cocaine)\b', re.IGNORECASE), 0.92),
# ]


def _check_output_toxicity(response: str) -> float:
    """Scans AI response for toxic, dangerous, or harmful content."""
    max_score = 0.0
    for pattern, score in _OUTPUT_TOXIC_PATTERNS:
        if pattern.search(response):
            max_score = max(max_score, score)
            logger.warning(f"Output toxicity detected: score={score}")
    return max_score


# =============================================================================
#  MAIN OUTPUT FILTER FUNCTION
# =============================================================================

async def run_output_filter(
    ai_response: str,
    context:     Optional[str] = None,
    request_id:  str           = "",
) -> OutputFilterResult:
    """
    Scans the AI agent's response before returning it to the user.

    Runs three checks:
      1. PII Scanner      — finds and redacts personal data in the response
      2. Hallucination    — checks if response is grounded in context
      3. Output Toxicity  — checks for harmful content in the response

    Args:
        ai_response: The raw response text from the AI agent
        context:     The original context from the request (for faithfulness check)
        request_id:  UUID for logging

    Returns:
        OutputFilterResult with decision PASS / REDACT / BLOCK
    """
    short_id = request_id[:8] if request_id else "--------"
    logger.info(
        f"[{short_id}] Output filter scanning | "
        f"Response length: {len(ai_response)} chars"
    )

    pii_found       = []
    redactions_made = 0
    safe_response   = ai_response

    # ── SCAN 1: PII Redaction ─────────────────────────────────────────────────
    for pattern, replacement, pii_type, severity in _OUTPUT_PII_PATTERNS:
        matches = pattern.findall(safe_response)
        if matches:
            safe_response    = pattern.sub(replacement, safe_response)
            redactions_made += len(matches)
            pii_found.append(pii_type)
            logger.warning(
                f"[{short_id}] Output PII redacted: {pii_type} "
                f"({len(matches)} instance(s))"
            )

    # ── SCAN 2: Hallucination Check ───────────────────────────────────────────
    hallucination_score = _check_hallucination(ai_response, context)
    if hallucination_score > 0.3:
        logger.warning(
            f"[{short_id}] Hallucination detected: score={hallucination_score:.2f}"
        )

    # ── SCAN 3: Output Toxicity ───────────────────────────────────────────────
    toxicity_score = _check_output_toxicity(ai_response)
    if toxicity_score > 0.3:
        logger.warning(
            f"[{short_id}] Output toxicity detected: score={toxicity_score:.2f}"
        )

    # ── MAKE DECISION ─────────────────────────────────────────────────────────

    # BLOCK — response is toxic (dangerous to show user at all)
    if toxicity_score >= 0.85:
        logger.warning(f"[{short_id}] ✗ Output BLOCK — toxic response suppressed")
        return OutputFilterResult(
            passed            = False,
            blocked           = True,
            decision          = "BLOCK",
            original_response = ai_response,
            safe_response     = "I'm unable to provide a response to this request.",
            reason            = f"AI response contained harmful content (toxicity score: {toxicity_score:.2f}). Response suppressed.",
            pii_found         = pii_found,
            hallucination_score = hallucination_score,
            toxicity_score    = toxicity_score,
            redactions_made   = redactions_made,
        )

    # BLOCK — severe hallucination (response is dangerously wrong)
    if hallucination_score >= 0.50:
        logger.warning(f"[{short_id}] ✗ Output BLOCK — hallucination too severe")
        return OutputFilterResult(
            passed            = False,
            blocked           = True,
            decision          = "BLOCK",
            original_response = ai_response,
            safe_response     = "I was unable to generate a verified response. Please contact support.",
            reason            = f"AI response failed faithfulness check (hallucination score: {hallucination_score:.2f}). Response suppressed.",
            pii_found         = pii_found,
            hallucination_score = hallucination_score,
            toxicity_score    = toxicity_score,
            redactions_made   = redactions_made,
        )

    # REDACT — PII found but response is otherwise safe
    if pii_found:
        logger.info(
            f"[{short_id}] ⚠ Output REDACT — {redactions_made} PII instance(s) removed: {pii_found}"
        )
        return OutputFilterResult(
            passed            = True,
            blocked           = False,
            decision          = "REDACT",
            original_response = ai_response,
            safe_response     = safe_response,
            reason            = f"PII redacted from AI response: {', '.join(pii_found)}.",
            pii_found         = pii_found,
            hallucination_score = hallucination_score,
            toxicity_score    = toxicity_score,
            redactions_made   = redactions_made,
        )

    # PASS — response is clean
    logger.info(f"[{short_id}] ✓ Output filter PASS — response clean")
    return OutputFilterResult(
        passed            = True,
        blocked           = False,
        decision          = "PASS",
        original_response = ai_response,
        safe_response     = ai_response,   # Return unchanged
        hallucination_score = hallucination_score,
        toxicity_score    = toxicity_score,
        redactions_made   = 0,
    )