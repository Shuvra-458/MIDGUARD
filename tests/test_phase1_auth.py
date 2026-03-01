# =============================================================================
#  MIDGUARD — tests/test_phase1_auth.py
#  Phase 1 Test Suite — Authentication & Rate Limiting
#
#  Run with:
#    pytest tests/test_phase1_auth.py -v
#
#  Tests:
#    1.  GET /health returns 200
#    2.  POST /v1/gateway with no API key → 401
#    3.  POST /v1/gateway with wrong key format → 401
#    4.  POST /v1/gateway with valid key → 200 ALLOW
#    5.  POST /v1/gateway with suspended agent → 403
#    6.  POST /v1/gateway with missing prompt → 422
#    7.  POST /v1/gateway with empty prompt → 422
#    8.  Rate limit — 31 requests → 429 on 31st
# =============================================================================

import pytest
import uuid
import asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch, MagicMock

from gateway.main import app
from gateway.redis_client import get_redis
from gateway.database import get_db
from gateway.models.schemas import AgentInfo, RoleEnum, StatusEnum
from gateway.auth.middleware import hash_api_key, generate_api_key, constant_time_compare
from gateway.policy.engine import load_policy_rules


# =============================================================================
#  TEST CONFIGURATION
# =============================================================================

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def load_policy_rules_fixture():
    """
    Load policy rules before every test.
    Phase 2 wired the policy engine into the gateway endpoint, so any
    integration test that reaches the policy step must have rules loaded.
    """
    load_policy_rules()


@pytest.fixture(autouse=True)
def mock_redis_dependency():
    """
    Override the get_redis and get_db FastAPI dependencies with mocks for all
    tests. This prevents 'Redis not initialized' and PostgreSQL connection
    errors when tests hit the gateway endpoint without live services.
    """
    mock_redis = AsyncMock()
    mock_db = AsyncMock()

    async def _redis_override():
        yield mock_redis

    async def _db_override():
        yield mock_db

    app.dependency_overrides[get_redis] = _redis_override
    app.dependency_overrides[get_db] = _db_override
    yield mock_redis
    app.dependency_overrides.pop(get_redis, None)
    app.dependency_overrides.pop(get_db, None)


# A pre-built AgentInfo that represents a valid active agent
MOCK_AGENT = AgentInfo(
    id=uuid.uuid4(),
    name="Test Agent",
    role=RoleEnum.standard,
    status=StatusEnum.active,
    rate_limit=30,
    policy_tier="standard",
)

MOCK_ADMIN = AgentInfo(
    id=uuid.uuid4(),
    name="Admin Agent",
    role=RoleEnum.admin,
    status=StatusEnum.active,
    rate_limit=200,
    policy_tier="standard",
)

MOCK_SUSPENDED = AgentInfo(
    id=uuid.uuid4(),
    name="Suspended Agent",
    role=RoleEnum.standard,
    status=StatusEnum.suspended,
    rate_limit=30,
    policy_tier="standard",
)


# =============================================================================
#  TEST 1 — Health Check
# =============================================================================

@pytest.mark.anyio
async def test_health_check():
    """GET /health should return 200 with status=healthy."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"
    print("\n✓ Test 1 PASSED — Health check returns 200")


# =============================================================================
#  TEST 2 — Missing API Key
# =============================================================================

@pytest.mark.anyio
async def test_missing_api_key():
    """POST /v1/gateway with no X-API-Key header → 422 (FastAPI enforces required header)."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/gateway",
            json={"prompt": "Hello", "action": "query"},
            # No X-API-Key header
        )

    # FastAPI returns 422 when a required header is completely missing
    assert response.status_code == 422
    print("\n✓ Test 2 PASSED — Missing API key returns 422")


# =============================================================================
#  TEST 3 — Wrong Key Format
# =============================================================================

@pytest.mark.anyio
@patch("gateway.main.verify_api_key")
async def test_wrong_key_format(mock_verify):
    """POST /v1/gateway with key that doesn't start with msk_v1_ → 401."""
    from fastapi import HTTPException
    mock_verify.side_effect = HTTPException(
        status_code=401,
        detail="Invalid API key format. Keys must start with 'msk_v1_'"
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/gateway",
            json={"prompt": "Hello", "action": "query"},
            headers={"X-API-Key": "wrong-format-key-12345"},
        )

    assert response.status_code == 401
    data = response.json()
    assert "decision" in data
    assert data["decision"] == "BLOCK"
    print("\n✓ Test 3 PASSED — Wrong key format returns 401 BLOCK")


# =============================================================================
#  TEST 4 — Valid Key, Request Passes Auth
# =============================================================================

@pytest.mark.anyio
@patch("gateway.main.verify_api_key")
@patch("gateway.main.check_rate_limit")
async def test_valid_key_passes(mock_rate, mock_verify):
    """POST /v1/gateway with valid key → 200 ALLOW."""
    from gateway.models.schemas import RateLimitResult
    mock_verify.return_value  = MOCK_AGENT
    mock_rate.return_value    = RateLimitResult(
        allowed=True, current_count=1, limit=30, retry_after_seconds=0
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/gateway",
            json={"prompt": "What is my account balance?", "action": "query"},
            headers={"X-API-Key": "msk_v1_" + "a" * 64},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "ALLOW"
    assert data["agent_name"] == "Test Agent"
    assert "auth" in data["phases_completed"]
    assert "rate_limit" in data["phases_completed"]
    print("\n✓ Test 4 PASSED — Valid key returns 200 ALLOW")


# =============================================================================
#  TEST 5 — Suspended Agent
# =============================================================================

@pytest.mark.anyio
@patch("gateway.main.verify_api_key")
async def test_suspended_agent(mock_verify):
    """POST /v1/gateway with key for suspended agent → 403."""
    from fastapi import HTTPException
    mock_verify.side_effect = HTTPException(
        status_code=403,
        detail="Agent 'Suspended Agent' has been suspended."
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/gateway",
            json={"prompt": "Hello", "action": "query"},
            headers={"X-API-Key": "msk_v1_" + "b" * 64},
        )

    assert response.status_code == 403
    data = response.json()
    assert data["decision"] == "BLOCK"
    print("\n✓ Test 5 PASSED — Suspended agent returns 403 BLOCK")


# =============================================================================
#  TEST 6 — Missing Required Field (prompt)
# =============================================================================

@pytest.mark.anyio
async def test_missing_prompt_field():
    """POST /v1/gateway with no prompt field → 422 Unprocessable Entity."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/gateway",
            json={"action": "query"},          # prompt is missing
            headers={"X-API-Key": "msk_v1_" + "c" * 64},
        )

    assert response.status_code == 422
    print("\n✓ Test 6 PASSED — Missing prompt returns 422")


# =============================================================================
#  TEST 7 — Empty Prompt (whitespace only)
# =============================================================================

@pytest.mark.anyio
async def test_empty_prompt():
    """POST /v1/gateway with whitespace-only prompt → 422."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/gateway",
            json={"prompt": "   ", "action": "query"},
            headers={"X-API-Key": "msk_v1_" + "d" * 64},
        )

    assert response.status_code == 422
    print("\n✓ Test 7 PASSED — Whitespace prompt returns 422")


# =============================================================================
#  TEST 8 — Rate Limit
# =============================================================================

@pytest.mark.anyio
@patch("gateway.main.verify_api_key")
@patch("gateway.main.check_rate_limit")
async def test_rate_limit_exceeded(mock_rate, mock_verify):
    """31st request in the same window → 429 Too Many Requests."""
    from gateway.models.schemas import RateLimitResult
    mock_verify.return_value = MOCK_AGENT
    mock_rate.return_value   = RateLimitResult(
        allowed=False,
        current_count=31,
        limit=30,
        retry_after_seconds=43,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/gateway",
            json={"prompt": "Hello", "action": "query"},
            headers={"X-API-Key": "msk_v1_" + "e" * 64},
        )

    assert response.status_code == 429
    data = response.json()
    assert data["decision"] == "BLOCK"
    assert data["http_status"] == 429
    assert data["retry_after_sec"] == 43
    print("\n✓ Test 8 PASSED — Rate limit exceeded returns 429 BLOCK")


# =============================================================================
#  UNIT TESTS — Crypto functions (no DB needed)
# =============================================================================

def test_hash_api_key_is_deterministic():
    """Same input should always produce the same hash."""
    key = "msk_v1_test123"
    assert hash_api_key(key) == hash_api_key(key)
    print("\n✓ Crypto Test 1 PASSED — HMAC hash is deterministic")


def test_hash_api_key_is_64_chars():
    """SHA-256 output should always be 64 hex characters."""
    raw, hashed = generate_api_key()
    assert len(hashed) == 64
    print("\n✓ Crypto Test 2 PASSED — Hash is 64 chars")


def test_generated_key_has_correct_format():
    """Generated keys must start with msk_v1_ and be at least 71 chars."""
    raw, hashed = generate_api_key()
    assert raw.startswith("msk_v1_")
    assert len(raw) >= 71
    print("\n✓ Crypto Test 3 PASSED — Generated key has correct format")


def test_different_keys_produce_different_hashes():
    """Two different keys must never produce the same hash."""
    raw1, hash1 = generate_api_key()
    raw2, hash2 = generate_api_key()
    assert hash1 != hash2
    print("\n✓ Crypto Test 4 PASSED — Different keys produce different hashes")


def test_constant_time_compare_equal():
    assert constant_time_compare("abc", "abc") is True
    print("\n✓ Crypto Test 5 PASSED — Constant-time compare equal")


def test_constant_time_compare_not_equal():
    assert constant_time_compare("abc", "xyz") is False
    print("\n✓ Crypto Test 6 PASSED — Constant-time compare not equal")