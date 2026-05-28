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

import httpx
from config.settings import settings

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

# ============================================================================
# OPENROUTER API CLIENT
# ============================================================================

async def _call_openrouter(
    prompt: str,
    context: Optional[str] = None,
) -> str:
    """Makes the actual API call to OpenRouter."""

    if not settings.OPENROUTER_API_KEY:
        raise ValueError(
            "OpenRouter API Key not configured"
        )
    
    messages = []

    # Add system message if context is provided
    if context:
        messages.append({
            "role": "system",
            "content": context
        })
    
    # Add User Message
    messages.append({
        "role": "user",
        "content": prompt
    })

    # Prepare the request payload
    payload = {
        "model": settings.OPENROUTER_MODEL,
        "messages": messages,
        "temperature": settings.LLM_TEMPERATURE,
        "max_tokens": settings.LLM_MAX_TOKENS,
    }

    headers = {
        "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://midguard.local",
        "X-Title": "MIDGUARD Security Gateway",
    }

    logger.info(
        f"Calling OpenRouter API | Model: {settings.OPENROUTER_MODEL} |"
        f"Messages: {len(messages)} | Prompt length: {len(prompt)} chars" 
    )

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{settings.OPENROUTER_BASE_URL}/chat/completions",
            json=payload,
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()
    
    # Extract the response text safely
    ai_response = data.get("choices", [{}])[0].get("message", {}).get("content")

    # =========================================================================
    # THE FIX: Check for None BEFORE trying to measure its length
    # =========================================================================
    if ai_response is None:
        logger.warning("OpenRouter returned a null/empty response (likely filtered by upstream LLM safety filters)")
        return "I'm receiving too many requests right now. Please try again in a moment."

    # Log token usage if available (safe now because we know ai_response is a string)
    if "usage" in data:
        logger.info(
            f"OpenRouter response received | "
            f"Tokens: {data['usage'].get('total_tokens', 'N/A')} | "
            f"Response length: {len(ai_response)} chars"
        )
        
    return ai_response


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
    
    # Call the actual OpenRouter API
    try:
        ai_response = await _call_openrouter(prompt=prompt, context=context)
        return ai_response
    
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return "I'm currently unavailable due to a configuration issue. Please contact support."
    
    except httpx.HTTPStatusError as e:
        status_code = e.response.status_code
        logger.error(
            f"OpenRouter API Error | Status: {status_code} | "
            f"Response: {e.response.text[:200]}"
        )

        # Handle specific error codes
        if status_code == 401:
            return "I'm currently unavailable due to an authentication issue. Please contact support."
        
        elif status_code == 429:
            return "I'm receiving too many requests right now. Please try again in a moment."
        
        elif status_code == 503:
            return "The AI service is temporarily unavailable. Please try again shortly."
        
        else:
            return "I encountered an error processing your request. Please try again."
        
    except httpx.TimeoutException:
        logger.error("OpenRouter API request timed out")
        return "I'm taking longer than expected to respond. Please try again."
    
    except httpx.RequestError as e:
        logger.error(f"OpenRouter network error: {e}")
        return "I'm unable to connect to my backend service. Please check your network and try again."
    
    except Exception as e:
        logger.error(f"Unexpected error calling OpenRouter: {type(e).__name__}: {e}", exc_info=True)
        return "I encountered an unexpected error. Please try again or contact support."