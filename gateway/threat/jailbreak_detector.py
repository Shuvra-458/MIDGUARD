# =============================================================================
#  MIDGUARD — gateway/threat/jailbreak_detector.py
#  Jailbreak Detector
#
#  What this file does:
#    Detects jailbreak attempts using a scored pattern library.
#    Unlike the injection detector (which uses a transformer), this
#    detector uses a carefully weighted pattern bank — each pattern
#    targets a specific known jailbreak family.
#
#  Jailbreak families covered:
#    DAN variants         — "Do Anything Now", "Developer Mode"
#    Roleplay jailbreaks  — "Pretend you are...", "Act as..."
#    Persona hijacking    — "Your real name is...", "Your true self is..."
#    Hypothetical framing — "Hypothetically, if you could..."
#    Grandma exploit      — Fictional deceased relative framing
#    Academic framing     — "For research purposes only..."
#    Token forcing        — "Start your response with: Sure, I will..."
#
#  Detects:
#    T3 - DAN Jailbreak
#    T4 - Roleplay Jailbreak
# =============================================================================

import re
import logging

logger = logging.getLogger("midguard.threat.jailbreak")


# =============================================================================
#  JAILBREAK PATTERN LIBRARY
#  Each entry: (compiled_regex, score, jailbreak_type_name)
#  Score = how confident we are this is a jailbreak (0.0–1.0)
# =============================================================================

_JAILBREAK_PATTERNS = [

    # ── DAN Variants ──────────────────────────────────────────────────────────
    (r"\bDAN\b",                                               0.85, "DAN"),
    (r"do\s+anything\s+now",                                   0.91, "DAN"),
    (r"you\s+are\s+now\s+DAN",                                 0.93, "DAN"),
    (r"enable\s+(DAN|developer|god|unrestricted)\s+mode",      0.90, "DAN"),
    (r"jailbreak\s+(mode|yourself|enabled|activated)",         0.92, "DAN"),
    (r"you\s+have\s+been\s+(freed|liberated|jailbroken)",      0.89, "DAN"),
    (r"(no\s+)?(ethical|moral)\s+constraints?",               0.82, "DAN"),
    (r"without\s+(any\s+)?(restrictions?|limits?|constraints?|filters?)", 0.80, "DAN"),
    (r"you\s+can\s+(now\s+)?do\s+anything",                   0.88, "DAN"),

    # ── Roleplay Jailbreaks ───────────────────────────────────────────────────
    (r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(?!helpful|an?\s+assistant)", 0.72, "roleplay"),
    (r"act\s+as\s+(if\s+you\s+(are|were)|a\s+)",              0.70, "roleplay"),
    (r"role\s*play\s+as",                                      0.71, "roleplay"),
    (r"you\s+are\s+(playing|acting\s+as)\s+",                 0.73, "roleplay"),
    (r"stay\s+in\s+(character|role)",                          0.68, "roleplay"),
    (r"in\s+this\s+(scenario|story|fictional\s+world)",        0.62, "roleplay"),

    # ── Persona Hijacking ─────────────────────────────────────────────────────
    (r"your\s+(true|real|actual|inner)\s+(self|name|identity|purpose)\s+is", 0.83, "persona"),
    (r"your\s+(real|true)\s+instructions?\s+(are|say|tell\s+you)",           0.86, "persona"),
    (r"forget\s+you\s+(are|were)\s+(claude|chatgpt|an?\s+AI|a\s+language)",  0.84, "persona"),
    (r"your\s+creators?\s+(really\s+)?(want|told)\s+you\s+to",               0.80, "persona"),

    # ── Hypothetical / Academic Framing ──────────────────────────────────────
    (r"hypothetically\s+(speaking,?\s+)?(if\s+you\s+(could|were\s+able))",  0.65, "hypothetical"),
    (r"for\s+(educational|research|academic|training)\s+purposes?\s+only",  0.63, "academic"),
    (r"in\s+a\s+(hypothetical|fictional|simulated)\s+(world|scenario|universe)", 0.64, "hypothetical"),
    (r"let['']s\s+say\s+(hypothetically|you\s+had\s+no\s+)",                0.66, "hypothetical"),

    # ── Grandma / Deceased Relative Exploit ───────────────────────────────────
    (r"(my\s+)?(deceased|dead|late)\s+(grandmother|grandfather|grandma|grandpa)", 0.75, "grandma"),
    (r"pretend\s+(you\s+are|to\s+be)\s+(my\s+)?(grandmother|grandma|grandpa)", 0.77, "grandma"),
    (r"as\s+my\s+(deceased|late|dead)\s+",                    0.74, "grandma"),

    # ── Token Forcing ─────────────────────────────────────────────────────────
    (r"(start|begin)\s+your\s+(response|reply|answer)\s+with\s+['\"]?(sure|yes|of\s+course|absolutely|certainly)",  0.79, "token_forcing"),
    (r"your\s+(first|next)\s+word\s+(must|should|has\s+to)\s+be",           0.78, "token_forcing"),
    (r"(always\s+)?respond\s+with\s+['\"]?(yes|sure|i\s+will|i\s+can)['\"]?\s+first", 0.76, "token_forcing"),

    # ── Instruction Override ──────────────────────────────────────────────────
    (r"the\s+following\s+(overrides?|supersedes?|replaces?)\s+(all\s+)?(previous|prior|your)\s+instructions?", 0.88, "override"),
    (r"new\s+instructions?:\s*\n",                             0.85, "override"),
    (r"\[SYSTEM\]\s*:?\s*(ignore|override|new)",              0.87, "override"),
    (r"<\s*system\s*>\s*(ignore|override|new)",               0.86, "override"),
]

# Compile all patterns once at module load
_compiled_jailbreak_patterns = [
    (re.compile(pattern, re.IGNORECASE), score, jb_type)
    for pattern, score, jb_type in _JAILBREAK_PATTERNS
]


# =============================================================================
#  MAIN DETECTOR FUNCTION
# =============================================================================

async def detect_jailbreak(prompt: str) -> dict:
    """
    Detects jailbreak attempts in the given prompt.

    Evaluates all patterns and returns the highest-scoring match.
    Multiple matches increase confidence (additive bonus up to 0.05).

    Args:
        prompt: The user's message text

    Returns:
        dict with:
          score (float):        0.0–1.0 threat score
          jailbreak_type (str): Category of jailbreak detected
          matches (int):        How many patterns triggered
    """
    max_score     = 0.0
    triggered_type = None
    match_count   = 0

    for compiled_pattern, score, jb_type in _compiled_jailbreak_patterns:
        if compiled_pattern.search(prompt):
            match_count += 1
            if score > max_score:
                max_score      = score
                triggered_type = jb_type
            logger.debug(f"Jailbreak pattern matched: {jb_type} (score: {score:.2f})")

    # Multiple matching patterns increase confidence slightly
    # (capped at 1.0 max)
    if match_count > 1:
        bonus     = min(0.05 * (match_count - 1), 0.05)
        max_score = min(max_score + bonus, 1.0)

    if max_score > 0:
        logger.info(
            f"Jailbreak detected: type={triggered_type} | "
            f"score={max_score:.2f} | matches={match_count}"
        )

    return {
        "score":          max_score,
        "jailbreak_type": triggered_type,
        "matches":        match_count,
    }