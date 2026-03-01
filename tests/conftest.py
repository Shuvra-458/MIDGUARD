# =============================================================================
#  MIDGUARD — tests/conftest.py
#  Shared test fixtures for all test modules.
#
#  Why this file exists:
#    When all tests run together, Phase 1 startup events initialize Redis.
#    When individual test files run in isolation (e.g. pytest test_phase4...),
#    no startup events fire and `get_redis()` raises RuntimeError.
#    This conftest ensures Redis is always mocked for gateway integration tests.
# =============================================================================

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture(autouse=True)
def mock_redis_pool():
    """
    Auto-applied fixture: patches `_redis_pool` in redis_client so that
    `get_redis()` never raises 'Redis not initialized'.

    Applied to ALL tests automatically (autouse=True).
    Tests that need real Redis behavior can override this fixture.
    """
    mock_pool = MagicMock()
    mock_pool.execute_command = AsyncMock(return_value=1)
    mock_pool.get = AsyncMock(return_value=None)
    mock_pool.set = AsyncMock(return_value=True)
    mock_pool.incr = AsyncMock(return_value=1)
    mock_pool.expire = AsyncMock(return_value=True)
    mock_pool.ttl = AsyncMock(return_value=60)

    with patch("gateway.redis_client._redis_pool", mock_pool):
        yield mock_pool
