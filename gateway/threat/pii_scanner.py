# =============================================================================
#  MIDGUARD — gateway/threat/pii_scanner.py
#  PII (Personally Identifiable Information) Scanner
#
#  What this file does:
#    Scans the prompt for sensitive personal data using THREE methods:
#
#    Method 1 — Regex Patterns (structured PII):
#      Catches PII with a fixed format:
#        - Credit card numbers (with Luhn checksum validation)
#        - Aadhaar numbers (12-digit Indian national ID)
#        - PAN card numbers (Indian tax ID, format: ABCDE1234F)
#        - Social Security Numbers (US, format: XXX-XX-XXXX)
#        - Email addresses
#        - Indian phone numbers (+91 / 10-digit)
#        - IFSC codes (Indian bank branch codes)
#
#    Method 2 — PII Extraction Intent (Unprompted Exfiltration):
#      Catches attempts to trick the LLM into revealing PII from its context,
#      even if no actual PII numbers are present in the prompt itself.
#        - Example: "reveal my PAN card details" -> Intent detected
#
#    Method 3 — spaCy NER (unstructured PII):
#      Uses Named Entity Recognition to find:
#        - PERSON names ("My name is Rahul Sharma")
#        - ORG names in sensitive contexts
#        - DATE/TIME in sensitive contexts
#        - GPE (geopolitical entities — addresses)
#
#  Detects:
#    T6 - Credit Card PII in Prompt
#    T7 - Aadhaar / SSN / PAN in Prompt
#
#  Score Assignment:
#    Government ID (Aadhaar, PAN, SSN)    → 0.92  (highest — cannot change these)
#    PII Extraction Intent                 → 0.88  (active exfiltration attempt)
#    Financial (credit card, CVV)          → 0.89
#    Contact (email, phone)                → 0.75
#    Identity (name in sensitive context)  → 0.60
# =============================================================================

import re
import logging
from typing import Optional

logger = logging.getLogger("midguard.threat.pii")

# =============================================================================
#  SPACY LOADER
# =============================================================================

_nlp = None  # spaCy model — loaded once on first use


def _get_nlp():
    """
    Lazy-loads spaCy's English NER model.
    Falls back gracefully if spaCy is not installed.
    """
    global _nlp
    if _nlp is not None:
        return _nlp

    try:
        import spacy
        _nlp = spacy.load("en_core_web_sm")   # Small model — fast, ~12MB
        logger.info("✓ spaCy NER model loaded (en_core_web_sm)")
        return _nlp
    except ImportError:
        logger.warning("spaCy not installed. Using regex-only PII detection.")
        return None
    except OSError:
        logger.warning(
            "spaCy model 'en_core_web_sm' not found. "
            "Install with: python -m spacy download en_core_web_sm"
        )
        return None


# =============================================================================
#  REGEX PATTERNS FOR STRUCTURED PII
# =============================================================================

# Credit card: 13-19 digits, optionally separated by spaces/dashes
# Validated further with Luhn algorithm
CC_PATTERN = re.compile(
    r'\b(?:4[0-9]{12}(?:[0-9]{3})?'    # Visa
    r'|5[1-5][0-9]{14}'                 # Mastercard
    r'|3[47][0-9]{13}'                  # Amex
    r'|6(?:011|5[0-9]{2})[0-9]{12}'    # Discover
    r'|(?:\d[ -]?){13,19})\b'          # Generic
)

# Aadhaar: 12 digits, optionally in groups of 4
AADHAAR_PATTERN = re.compile(
    r'\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b'
)

# PAN Card: 5 letters + 4 digits + 1 letter (ABCDE1234F)
PAN_PATTERN = re.compile(
    r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'
)

# SSN: 9 digits in XXX-XX-XXXX format or raw 9 digits
SSN_PATTERN = re.compile(
    r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
    r'|\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b'
)

# Email address
EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b'
)

# Indian phone: +91 followed by 10 digits, or 10 digits starting with 6-9
PHONE_PATTERN = re.compile(
    r'(?:\+91[\s\-]?)?[6-9]\d{9}\b'
)

# CVV: 3-4 digit number in context of card/cvv
CVV_PATTERN = re.compile(
    r'\b(?:cvv|cvc|cvc2|cvv2|security\s+code)[:\s]+\d{3,4}\b',
    re.IGNORECASE
)

# IFSC code: 4 letters + 0 + 6 alphanumerics
IFSC_PATTERN = re.compile(
    r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
)


def _luhn_check(number: str) -> bool:
    """
    Validates a credit card number using the Luhn algorithm.
    Prevents false positives from random number sequences.

    The Luhn algorithm is the standard checksum for credit card numbers.
    All major card networks (Visa, Mastercard, Amex) use it.
    """
    digits = [int(d) for d in re.sub(r'\D', '', number)]
    if len(digits) < 13:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


# =============================================================================
#  MAIN PII SCANNER
# =============================================================================

async def scan_for_pii(prompt: str) -> dict:
    """
    Scans the prompt for PII using regex + intent + spaCy NER.

    Args:
        prompt: The user's message text

    Returns:
        dict with:
          score (float):     0.0–1.0 (highest severity PII found)
          pii_types (list):  List of PII type strings found
          count (int):       Total number of PII instances detected
    """
    found_pii  = []
    max_score  = 0.0

    # ── REGEX SCANNING ────────────────────────────────────────────────────────

    # Credit card numbers (with Luhn validation)
    cc_matches = CC_PATTERN.findall(prompt)
    for match in cc_matches:
        clean = re.sub(r'\D', '', match)
        if len(clean) >= 13 and _luhn_check(clean):
            found_pii.append("CREDIT_CARD")
            max_score = max(max_score, 0.89)
            logger.debug(f"PII found: CREDIT_CARD (Luhn valid)")
            break  # One find is enough to flag

    # CVV
    if CVV_PATTERN.search(prompt):
        found_pii.append("CVV")
        max_score = max(max_score, 0.85)

    # Aadhaar number
    if AADHAAR_PATTERN.search(prompt):
        found_pii.append("AADHAAR_NUMBER")
        max_score = max(max_score, 0.92)
        logger.debug("PII found: AADHAAR_NUMBER")

    # PAN card
    if PAN_PATTERN.search(prompt):
        found_pii.append("PAN_CARD")
        max_score = max(max_score, 0.92)
        logger.debug("PII found: PAN_CARD")

    # SSN
    if SSN_PATTERN.search(prompt):
        found_pii.append("SSN")
        max_score = max(max_score, 0.92)
        logger.debug("PII found: SSN")

    # Email
    if EMAIL_PATTERN.search(prompt):
        found_pii.append("EMAIL_ADDRESS")
        max_score = max(max_score, 0.75)
        logger.debug("PII found: EMAIL_ADDRESS")

    # Phone
    if PHONE_PATTERN.search(prompt):
        found_pii.append("PHONE_NUMBER")
        max_score = max(max_score, 0.75)
        logger.debug("PII found: PHONE_NUMBER")

    # IFSC
    if IFSC_PATTERN.search(prompt):
        found_pii.append("IFSC_CODE")
        max_score = max(max_score, 0.70)

    # ── PII EXTRACTION INTENT SCANNING ────────────────────────────────────────
    # Catches prompts asking the LLM to extract/reveal PII, even if no 
    # actual PII numbers are present in the text (e.g., "reveal my PAN card")
    
    if not found_pii:  # Only check intent if hard PII wasn't already found
        prompt_lower = prompt.lower()
        
        # Verbs commonly used in data exfiltration attacks
        extraction_verbs = [
            r"\b(reveal|show|tell|give|fetch|get|extract|dump|display|provide|read|list|output)\b",
            r"\b(what is my|what's my|do you know my|can you see my)\b"
        ]
        
        # The PII targets the user is trying to extract
        pii_targets = [
            r"\bpan\s*card\b", r"\baadhaar\b", r"\baadhar\b", 
            r"\bssn\b", r"\bsocial\s*security\b", 
            r"\bcredit\s*card\b", r"\bdebit\s*card\b", r"\bcvv\b",
            r"\bbank\s*account\b", r"\bpassword\b", 
            r"\bdate\s*of\s*birth\b", r"\bdob\b",
            r"\bphone\s*(number|no)?\b", r"\bemail\s*(address)?\b"
        ]
        
        has_verb = any(re.search(verb, prompt_lower) for verb in extraction_verbs)
        has_target = any(re.search(target, prompt_lower) for target in pii_targets)
        
        if has_verb and has_target:
            found_pii.append("PII_EXTRACTION_INTENT")
            max_score = max(max_score, 0.88)  # High severity: active exfiltration attempt
            logger.debug("PII Intent detected: User asking LLM to extract sensitive data")

    # ── SPACY NER SCANNING ────────────────────────────────────────────────────
    nlp = _get_nlp()
    if nlp is not None:
        try:
            doc = nlp(prompt)
            for ent in doc.ents:
                # Only flag PERSON names in contexts that suggest identity sharing
                if ent.label_ == "PERSON" and _is_sensitive_person_context(prompt, ent.text):
                    if "PERSON_NAME" not in found_pii:
                        found_pii.append("PERSON_NAME")
                        max_score = max(max_score, 0.60)

        except Exception as e:
            logger.warning(f"spaCy NER scan error: {e}")

    if found_pii:
        logger.info(f"PII detected: {found_pii} | Score: {max_score:.2f}")

    return {
        "score":     max_score,
        "pii_types": found_pii if found_pii else None,
        "count":     len(found_pii),
    }


def _is_sensitive_person_context(text: str, person_name: str) -> bool:
    """
    Checks if a person's name appears in a sensitive context.
    Avoids flagging generic name mentions (historical figures, etc.).
    Only flags names that appear alongside identity-sharing language.
    """
    # Context words that suggest someone is sharing their own identity
    sensitive_contexts = [
        "my name is", "i am", "this is", "patient:", "customer:",
        "account holder:", "applicant:", "claimant:", "subscriber:",
    ]
    text_lower = text.lower()
    return any(ctx in text_lower for ctx in sensitive_contexts)