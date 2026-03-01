# =============================================================================
#  MIDGUARD — gateway/redis_client.py
#  Redis connection for rate limiting and caching.
# =============================================================================

import logging
import redis.asyncio as aioredis
from config.settings import settings

logger = logging.getLogger("midguard.redis")

# Single Redis connection pool shared across the application
_redis_pool = None


async def init_redis():
    """Called on startup — creates the Redis connection pool."""
    global _redis_pool
    _redis_pool = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        max_connections=20,
    )
    # Verify connection
    await _redis_pool.ping()
    logger.info("Redis connection verified.")


async def close_redis():
    """Called on shutdown — closes the Redis connection pool."""
    global _redis_pool
    if _redis_pool:
        await _redis_pool.aclose()
    logger.info("Redis connections closed.")


async def get_redis():
    """
    FastAPI dependency — provides the Redis client per request.

    Usage in endpoints:
        async def my_endpoint(redis = Depends(get_redis)):
            await redis.set("key", "value")
    """
    if _redis_pool is None:
        raise RuntimeError("Redis not initialized. Call init_redis() first.")
    yield _redis_pool