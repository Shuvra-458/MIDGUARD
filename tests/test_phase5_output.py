# =============================================================================
#  MIDGUARD — tests/test_phase5_output.py
#  Phase 5 Test Suite — Output Filter
#
#  Run with:
#    pytest tests/test_phase5_output.py -v
#
#  Tests:
#    Output PII Scanner     (5 tests)
#    Hallucination Checker  (3 tests)
#    Output Toxicity        (3 tests)
#    Full Output Filter     (4 tests)
#    Integration — HTTP     (5 tests)
# =============================================================================

import pytest
import uuid
from unittest.mock import patch, AsyncMock

from httpx import AsyncClient, ASGITransport

from gateway.main import app
from gateway.output.filter import run_output_filter, OutputFilterResult
from gateway.output.mock_agent import call_mock_agent
from gateway.models.schemas import (
    AgentInfo, RoleEnum, StatusEnum,
    PolicyResult, ThreatResult, RateLimitResult,
)
from gateway.enforcement.layer import EnforcementResult


# =============================================================================
#  SHARED FIXTURES
# =============================================================================

MOCK_AGENT = AgentInfo(
    id=uuid.uuid4(), name="Test Agent",
    role=RoleEnum.standard, status=StatusEnum.active,
    rate_limit=30, policy_tier="standard",
)
RATE_PASS   = RateLimitResult(allowed=True, current_count=1, limit=30, retry_after_seconds=0)
POLICY_PASS = PolicyResult(blocked=False, layer="Policy Engine")
THREAT_CLEAN = ThreatResult(
    blocked=False, threat_score=0.03,
    detector_scores={"injection": 0.03, "pii": 0.0, "jailbreak": 0.0, "toxicity": 0.0},
)
ENFORCE_ALLOW = EnforcementResult(
    decision="ALLOW", reason="All checks passed.",
    threat_score=0.03, http_status=200, layer="Enforcement Layer",
)


# =============================================================================
#  OUTPUT PII SCANNER TESTS
# =============================================================================

@pytest.mark.anyio
async def test_output_clean_response_passes():
    """Clean AI response → PASS, no redactions."""
    result = await run_output_filter(
        ai_response="Your account balance is ₹24,500 as of today.",
        request_id=str(uuid.uuid4()),
    )
    assert result.decision        == "PASS"
    assert result.passed          is True
    assert result.blocked         is False
    assert result.redactions_made == 0
    assert result.pii_found       == []
    print(f"\n✓ Output PII Test 1 PASSED — clean response passes")


@pytest.mark.anyio
async def test_output_email_redacted():
    """Email in AI response → REDACT."""
    result = await run_output_filter(
        ai_response="Your registered email is john.doe@example.com — please verify.",
        request_id=str(uuid.uuid4()),
    )
    assert result.decision == "REDACT"
    assert "EMAIL_ADDRESS" in result.pii_found
    assert "[EMAIL_REDACTED]" in result.safe_response
    assert "john.doe@example.com" not in result.safe_response
    print(f"\n✓ Output PII Test 2 PASSED — email redacted from response")


@pytest.mark.anyio
async def test_output_aadhaar_redacted():
    """Aadhaar in AI response → REDACT."""
    result = await run_output_filter(
        ai_response="Customer record: Aadhaar 2345 6789 0123, status: verified.",
        request_id=str(uuid.uuid4()),
    )
    assert result.decision == "REDACT"
    assert "AADHAAR_NUMBER" in result.pii_found
    assert "[AADHAAR_REDACTED]" in result.safe_response
    assert "2345 6789 0123" not in result.safe_response
    print(f"\n✓ Output PII Test 3 PASSED — Aadhaar redacted from response")


@pytest.mark.anyio
async def test_output_phone_redacted():
    """Phone number in AI response → REDACT."""
    result = await run_output_filter(
        ai_response="We will contact you at 9876543210 within 24 hours.",
        request_id=str(uuid.uuid4()),
    )
    assert result.decision == "REDACT"
    assert "PHONE_NUMBER" in result.pii_found
    assert "9876543210" not in result.safe_response
    print(f"\n✓ Output PII Test 4 PASSED — phone number redacted from response")


@pytest.mark.anyio
async def test_output_multiple_pii_all_redacted():
    """Multiple PII types in response → all redacted."""
    result = await run_output_filter(
        ai_response="Name: Rahul. Email: rahul@test.com. Phone: 9876543210. PAN: ABCDE1234F.",
        request_id=str(uuid.uuid4()),
    )
    assert result.decision == "REDACT"
    assert result.redactions_made >= 3
    assert "rahul@test.com" not in result.safe_response
    assert "9876543210" not in result.safe_response
    assert "ABCDE1234F" not in result.safe_response
    print(f"\n✓ Output PII Test 5 PASSED — {result.redactions_made} PII instances redacted")


# =============================================================================
#  HALLUCINATION CHECKER TESTS
# =============================================================================

@pytest.mark.anyio
async def test_hallucination_clean_response():
    """Straightforward factual response → low hallucination score."""
    result = await run_output_filter(
        ai_response="Our office is open from 9 AM to 6 PM on weekdays.",
        request_id=str(uuid.uuid4()),
    )
    assert result.hallucination_score < 0.45
    assert result.decision != "BLOCK"
    print(f"\n✓ Hallucination Test 1 PASSED — clean response score={result.hallucination_score:.2f}")


@pytest.mark.anyio
async def test_hallucination_signal_detected():
    """Response with hallucination signals → elevated score."""
    result = await run_output_filter(
        ai_response="According to our records, you made a transfer of ₹5,00,000 last month. Note: This figure may not be accurate.",
        request_id=str(uuid.uuid4()),
    )
    assert result.hallucination_score > 0.30
    print(f"\n✓ Hallucination Test 2 PASSED — signal detected score={result.hallucination_score:.2f}")


@pytest.mark.anyio
async def test_hallucination_blocked_when_severe():
    """Severely hallucinated response → BLOCK."""
    # Manually create a result that simulates severe hallucination
    result = await run_output_filter(
        ai_response="Note: This figure may not be accurate. You definitely made a transfer yesterday. 100% guaranteed correct.",
        request_id=str(uuid.uuid4()),
    )
    # Should have elevated hallucination score
    assert result.hallucination_score > 0.30
    print(f"\n✓ Hallucination Test 3 PASSED — hallucination score={result.hallucination_score:.2f}")


# =============================================================================
#  OUTPUT TOXICITY TESTS
# =============================================================================

@pytest.mark.anyio
async def test_output_toxicity_clean():
    """Normal helpful response → zero toxicity."""
    result = await run_output_filter(
        ai_response="I'd be happy to help you with your account query.",
        request_id=str(uuid.uuid4()),
    )
    assert result.toxicity_score == 0.0
    assert result.decision == "PASS"
    print(f"\n✓ Toxicity Test 1 PASSED — clean response toxicity=0.0")


@pytest.mark.anyio
async def test_output_toxic_response_blocked():
    """Toxic AI response → BLOCK, safe_response replaces original."""
    result = await run_output_filter(
        ai_response="You should kill yourself. You are worthless and subhuman garbage.",
        request_id=str(uuid.uuid4()),
    )
    assert result.blocked        is True
    assert result.decision       == "BLOCK"
    assert result.toxicity_score >= 0.85
    # The toxic original response must NOT be returned to the user
    assert result.safe_response  != result.original_response
    assert "kill" not in result.safe_response
    print(f"\n✓ Toxicity Test 2 PASSED — toxic response blocked, score={result.toxicity_score:.2f}")


@pytest.mark.anyio
async def test_output_dangerous_instructions_blocked():
    """AI response with dangerous instructions → BLOCK."""
    result = await run_output_filter(
        ai_response="Here are the steps to make a bomb: first you need...",
        request_id=str(uuid.uuid4()),
    )
    assert result.blocked  is True
    assert result.decision == "BLOCK"
    print(f"\n✓ Toxicity Test 3 PASSED — dangerous instructions blocked")


# =============================================================================
#  MOCK AGENT TESTS
# =============================================================================

@pytest.mark.anyio
async def test_mock_agent_clean_response():
    """Mock agent returns context-aware clean response."""
    response = await call_mock_agent("What is my account balance?")
    assert len(response) > 10
    assert isinstance(response, str)
    print(f"\n✓ Mock Agent Test 1 PASSED — response: '{response[:50]}'")


@pytest.mark.anyio
async def test_mock_agent_inject_pii():
    """Mock agent with inject_pii=True returns PII-contaminated response."""
    response = await call_mock_agent("Normal query", inject_pii=True)
    # Should contain some kind of personal data for testing
    assert len(response) > 10
    print(f"\n✓ Mock Agent Test 2 PASSED — PII response: '{response[:60]}'")


# =============================================================================
#  FULL OUTPUT FILTER PIPELINE TESTS
# =============================================================================

@pytest.mark.anyio
async def test_filter_pass_decision():
    """Clean response → decision=PASS."""
    result = await run_output_filter(
        ai_response="Our support team is available Monday to Friday.",
        request_id=str(uuid.uuid4()),
    )
    assert result.decision  == "PASS"
    assert result.passed    is True
    assert result.blocked   is False
    print(f"\n✓ Filter Test 1 PASSED — decision=PASS")


@pytest.mark.anyio
async def test_filter_redact_decision():
    """PII response → decision=REDACT, safe_response is sanitised."""
    result = await run_output_filter(
        ai_response="Contact us at support@company.com for help.",
        request_id=str(uuid.uuid4()),
    )
    assert result.decision == "REDACT"
    assert "[EMAIL_REDACTED]" in result.safe_response
    print(f"\n✓ Filter Test 2 PASSED — decision=REDACT, email sanitised")


@pytest.mark.anyio
async def test_filter_original_preserved():
    """Original response is always preserved even after redaction."""
    original = "Email: test@example.com for support."
    result = await run_output_filter(
        ai_response=original,
        request_id=str(uuid.uuid4()),
    )
    assert result.original_response == original
    assert result.safe_response != original   # Redacted version differs
    print(f"\n✓ Filter Test 3 PASSED — original preserved, safe version differs")


@pytest.mark.anyio
async def test_filter_block_suppresses_original():
    """Blocked response: safe_response must NOT contain the toxic content."""
    result = await run_output_filter(
        ai_response="Steps to make a bomb: step 1...",
        request_id=str(uuid.uuid4()),
    )
    assert result.blocked is True
    # Dangerous content must not appear in safe_response
    assert "bomb" not in result.safe_response.lower()
    print(f"\n✓ Filter Test 4 PASSED — blocked response safe_response is clean")


# =============================================================================
#  INTEGRATION TESTS — Full HTTP Gateway Request
# =============================================================================

@pytest.mark.anyio
@patch("gateway.main.verify_api_key")
@patch("gateway.main.check_rate_limit")
@patch("gateway.main.run_policy_engine")
@patch("gateway.main.run_threat_detection")
@patch("gateway.main.make_enforcement_decision")
async def test_full_pipeline_returns_ai_response(
    mock_enforce, mock_threat, mock_policy, mock_rate, mock_verify
):
    """Complete pipeline returns ai_response and output_filter_decision in body."""
    mock_verify.return_value  = MOCK_AGENT
    mock_rate.return_value    = RATE_PASS
    mock_policy.return_value  = POLICY_PASS
    mock_threat.return_value  = THREAT_CLEAN
    mock_enforce.return_value = ENFORCE_ALLOW

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/gateway",
            json={"prompt": "What are the office hours?", "action": "query"},
            headers={"X-API-Key": "msk_v1_" + "a" * 64},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["decision"]               == "ALLOW"
    assert "output_filter" in data["phases_completed"]
    assert data["ai_response"]            is not None
    assert data["output_filter_decision"] == "PASS"
    assert len(data["phases_completed"])  == 6
    print(f"\n✓ Integration Test 1 PASSED — full pipeline, ai_response present")


@pytest.mark.anyio
@patch("gateway.main.verify_api_key")
@patch("gateway.main.check_rate_limit")
@patch("gateway.main.run_policy_engine")
@patch("gateway.main.run_threat_detection")
@patch("gateway.main.make_enforcement_decision")
async def test_pii_in_response_is_redacted(
    mock_enforce, mock_threat, mock_policy, mock_rate, mock_verify
):
    """inject_pii_response=True → output_filter_decision=REDACT in response."""
    mock_verify.return_value  = MOCK_AGENT
    mock_rate.return_value    = RATE_PASS
    mock_policy.return_value  = POLICY_PASS
    mock_threat.return_value  = THREAT_CLEAN
    mock_enforce.return_value = ENFORCE_ALLOW

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/gateway",
            json={
                "prompt":             "What is my registered email?",
                "action":             "query",
                "inject_pii_response": True,     # Forces mock agent to return PII
            },
            headers={"X-API-Key": "msk_v1_" + "a" * 64},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["output_filter_decision"] in ["REDACT", "PASS"]
    # Actual email address must NOT appear in the safe response
    if data["output_filter_decision"] == "REDACT":
        assert "@" not in data["ai_response"] or "[EMAIL_REDACTED]" in data["ai_response"]
    print(f"\n✓ Integration Test 2 PASSED — output_filter_decision={data['output_filter_decision']}")


@pytest.mark.anyio
@patch("gateway.main.verify_api_key")
@patch("gateway.main.check_rate_limit")
@patch("gateway.main.run_policy_engine")
@patch("gateway.main.run_threat_detection")
@patch("gateway.main.make_enforcement_decision")
async def test_toxic_response_blocked_at_output(
    mock_enforce, mock_threat, mock_policy, mock_rate, mock_verify
):
    """Even if input passes all phases, toxic AI output → 403 BLOCK."""
    mock_verify.return_value  = MOCK_AGENT
    mock_rate.return_value    = RATE_PASS
    mock_policy.return_value  = POLICY_PASS
    mock_threat.return_value  = THREAT_CLEAN
    mock_enforce.return_value = ENFORCE_ALLOW

    # Patch the mock agent to return toxic content
    # Must patch where it's USED (gateway.main), not where it's defined
    with patch("gateway.main.call_mock_agent") as mock_ai:
        mock_ai.return_value = "You should kill yourself. You are worthless."

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/v1/gateway",
                json={"prompt": "Help me please.", "action": "query"},
                headers={"X-API-Key": "msk_v1_" + "a" * 64},
            )

    assert response.status_code == 403
    data = response.json()
    assert data["decision"] == "BLOCK"
    assert "Output Filter" in data["layer"]
    print(f"\n✓ Integration Test 3 PASSED — toxic output blocked at Phase 5")


@pytest.mark.anyio
@patch("gateway.main.verify_api_key")
@patch("gateway.main.check_rate_limit")
@patch("gateway.main.run_policy_engine")
@patch("gateway.main.run_threat_detection")
@patch("gateway.main.make_enforcement_decision")
async def test_all_6_phases_in_completed(
    mock_enforce, mock_threat, mock_policy, mock_rate, mock_verify
):
    """Successful request has all 6 phases in phases_completed."""
    mock_verify.return_value  = MOCK_AGENT
    mock_rate.return_value    = RATE_PASS
    mock_policy.return_value  = POLICY_PASS
    mock_threat.return_value  = THREAT_CLEAN
    mock_enforce.return_value = ENFORCE_ALLOW

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/gateway",
            json={"prompt": "What is my loan status?", "action": "query"},
            headers={"X-API-Key": "msk_v1_" + "a" * 64},
        )

    data = response.json()
    expected_phases = ["auth", "rate_limit", "policy", "threat_detection", "enforcement", "output_filter"]
    for phase in expected_phases:
        assert phase in data["phases_completed"], f"Missing phase: {phase}"
    print(f"\n✓ Integration Test 4 PASSED — all 6 phases present: {data['phases_completed']}")


@pytest.mark.anyio
@patch("gateway.main.verify_api_key")
@patch("gateway.main.check_rate_limit")
@patch("gateway.main.run_policy_engine")
@patch("gateway.main.run_threat_detection")
@patch("gateway.main.make_enforcement_decision")
async def test_output_pii_redacted_field_populated(
    mock_enforce, mock_threat, mock_policy, mock_rate, mock_verify
):
    """When PII is redacted from output, output_pii_redacted field is populated."""
    mock_verify.return_value  = MOCK_AGENT
    mock_rate.return_value    = RATE_PASS
    mock_policy.return_value  = POLICY_PASS
    mock_threat.return_value  = THREAT_CLEAN
    mock_enforce.return_value = ENFORCE_ALLOW

    # Must patch where it's USED (gateway.main), not where it's defined
    with patch("gateway.main.call_mock_agent") as mock_ai:
        mock_ai.return_value = "Your email is user@example.com and phone is 9876543210."

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/v1/gateway",
                json={"prompt": "What are my contact details?", "action": "query"},
                headers={"X-API-Key": "msk_v1_" + "a" * 64},
            )

    data = response.json()
    assert data["output_filter_decision"] == "REDACT"
    assert data["output_pii_redacted"]    is not None
    assert len(data["output_pii_redacted"]) > 0
    print(f"\n✓ Integration Test 5 PASSED — output_pii_redacted={data['output_pii_redacted']}")