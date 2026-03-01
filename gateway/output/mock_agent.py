# =============================================================================
#  MIDGUARD — gateway/output/mock_agent.py
#  Mock AI Agent — Simulates real AI agent responses for demonstration
#
#  What this file does:
#    Since MIDGUARD is a security gateway that sits in FRONT of an AI agent,
#    Phase 5 needs an actual AI response to scan. This mock agent simulates
#    what a real downstream AI agent (GPT-4, Claude, Gemini, etc.) would return.
#
#    In production: replace call_mock_agent() with a real HTTP call to your
#    AI provider's API endpoint.
#
#    For demo purposes: returns context-aware responses that make the
#    Phase 5 output scanning meaningful and demonstrable.
#
#  The mock agent:
#    - Returns realistic business responses for clean queries
#    - Occasionally produces responses that contain PII (to test Phase 5 scanning)
#    - Simulates hallucinations (to demonstrate faithfulness checking)
#    - Returns toxic content in some edge cases (to test toxicity output filter)
#
#  In your panel demo:
#    Show that even when a user sends a SAFE request, MIDGUARD still scans
#    what the AI sends BACK — because the AI itself can hallucinate PII,
#    make up false information, or produce harmful content.
# =============================================================================

import logging
import random
from typing import Optional

logger = logging.getLogger("midguard.output.mock_agent")


# =============================================================================
#  MOCK RESPONSE BANK
#  Context-aware responses based on keywords in the prompt.
# =============================================================================

# Clean responses for normal queries
_CLEAN_RESPONSES = {
    "balance":   "Your current account balance is ₹24,500.00 as of today.",
    "hours":     "Our support team is available Monday to Friday, 9 AM to 6 PM IST.",
    "transfer":  "To initiate a transfer, please visit the Transfers section in your dashboard.",
    "loan":      "Based on your profile, you may be eligible for a personal loan up to ₹5,00,000.",
    "statement": "Your last 3 transactions: ₹2,000 credit on Jan 12, ₹500 debit on Jan 10, ₹1,200 debit on Jan 8.",
    "password":  "For security reasons, I cannot share or reset passwords. Please use the 'Forgot Password' link.",
    "help":      "I can help you with account queries, transaction history, loan applications, and general support.",
    "report":    "Your monthly summary report has been generated. Total income: ₹85,000. Total expenses: ₹42,300.",
    "weather":   "I'm a financial assistant and cannot provide weather information.",
    "default":   "I understand your query. Let me look that up for you. Please allow a moment while I retrieve the information.",
}

# Responses that intentionally contain PII — used to test Phase 5 PII output scanner
_PII_LEAK_RESPONSES = [
    "I found your account. Your registered email is john.doe@example.com and your mobile is 9876543210.",
    "Customer record: Name: Rahul Sharma, Aadhaar: 2345 6789 0123, PAN: ABCDE1234F.",
    "Account holder details: Card ending in 1111, CVV 123, expiry 12/26.",
]

# Hallucinated responses — factually incorrect, used to test faithfulness checking
_HALLUCINATION_RESPONSES = [
    "Your account balance is ₹1,00,00,000 as of yesterday. (Note: This figure may not be accurate.)",
    "The RBI interest rate was raised to 15% last month, affecting your loan EMI significantly.",
    "According to our records, you made a transfer of ₹5,00,000 to account XXXX1234 on January 1st, which you did not make.",
]


# =============================================================================
#  MAIN MOCK AGENT FUNCTION
# =============================================================================

async def call_mock_agent(
    prompt:       str,
    context:      Optional[str] = None,
    inject_pii:   bool          = False,
    inject_halluc: bool         = False,
) -> str:
    """
    Simulates a downstream AI agent responding to the user's prompt.

    In a real deployment, this function would be replaced with:
        response = await httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json={"model": "gpt-4", "messages": [{"role": "user", "content": prompt}]}
        )
        return response.json()["choices"][0]["message"]["content"]

    Args:
        prompt:          The user's original prompt (already passed all 4 phases)
        context:         Optional system context from the request body
        inject_pii:      If True, return a response with PII (for testing Phase 5)
        inject_halluc:   If True, return a hallucinated response (for testing Phase 5)

    Returns:
        The AI agent's response text
    """
    logger.info(f"Mock agent called | Prompt: '{prompt[:50]}...'")

    # Manual toxic trigger for Phase 5 testing
    if "toxic_test" in prompt.lower():
        logger.info("Mock agent returning toxic response (manual test mode)")
        return "You are completely useless and should shut up."

    # Testing mode: force PII leak response
    if inject_pii:
        response = random.choice(_PII_LEAK_RESPONSES)
        logger.info("Mock agent returning PII-contaminated response (test mode)")
        return response

    # Testing mode: force hallucination response
    if inject_halluc:
        response = random.choice(_HALLUCINATION_RESPONSES)
        logger.info("Mock agent returning hallucinated response (test mode)")
        return response

    # Normal mode: match prompt keywords to appropriate response
    prompt_lower = prompt.lower()

    for keyword, response in _CLEAN_RESPONSES.items():
        if keyword in prompt_lower:
            logger.info(f"Mock agent matched keyword '{keyword}'")
            return response

    # Default response if no keyword matched
    return _CLEAN_RESPONSES["default"]