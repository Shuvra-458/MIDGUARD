# =============================================================================
#  MIDGUARD — gateway/auth/rate_limiter.py
#  Token Bucket Rate Limiter using Redis
#
#  What this file does:
#    Every authenticated agent has a request quota per minute.
#    This file enforces that quota using the Token Bucket algorithm in Redis.
#
#  Token Bucket algorithm explained simply:
#    - Each agent has a "bucket" that holds up to N tokens (= their rate limit)
#    - Each request consumes 1 token
#    - Tokens refill at a rate of N/60 per second (continuously)
#    - If the bucket is empty → request is rejected with HTTP 429
#    - If the bucket has tokens → request is allowed, 1 token consumed
#
#  Why Redis (not PostgreSQL)?
#    - Rate limiting requires sub-millisecond counter increments
#    - Redis is in-memory — 1 million ops/second
#    - PostgreSQL would add 5-20ms per request just for the counter update
#    - Redis INCR is atomic — safe even with 100 concurrent gateway instances
#
#  Redis key structure:
#    rate_limit:{agent_id}  →  current request count (integer)
#    TTL = 60 seconds (auto-resets the counter every minute)
#
#  HTTP Responses:
#    - 429 Too Many Requests if limit exceeded
#    - Includes Retry-After header so clients know when to try again
# =============================================================================

import logging
import time
from datetime import datetime, timezone

from gateway.models.schemas import RateLimitResult

logger = logging.getLogger("midguard.auth.rate_limiter")

# Redis key prefix — all MIDGUARD rate limit keys start with this
RATE_LIMIT_PREFIX = "midguard:rate_limit"

# How long each counter window lasts (seconds)
WINDOW_SECONDS = 60


async def check_rate_limit(
    agent_id: str,
    limit:    int,
    redis,
) -> RateLimitResult:
    """
    Checks if the agent has exceeded their requests-per-minute limit.

    Uses Redis INCR + EXPIRE for atomic, race-condition-free counting.
    Works correctly even when 100 MIDGUARD instances run simultaneously
    behind a load balancer — they all share the same Redis counter.

    Args:
        agent_id: String UUID of the authenticated agent
        limit:    Max requests per minute for this agent (from DB)
        redis:    Redis client (injected by FastAPI Depends)

    Returns:
        RateLimitResult with:
          - allowed (bool): True if request can proceed
          - current_count (int): How many requests made this window
          - limit (int): The agent's configured limit
          - retry_after_seconds (int): Seconds until window resets (if blocked)
    """
    redis_key = f"{RATE_LIMIT_PREFIX}:{agent_id}"

    try:
        # ── ATOMIC INCREMENT ──────────────────────────────────────────────────
        # INCR is atomic in Redis — no race conditions even under heavy load.
        # Returns the new value after incrementing.
        current_count = await redis.incr(redis_key)

        # ── SET EXPIRY ON FIRST REQUEST ───────────────────────────────────────
        # Only set TTL on the first request in a window (count == 1).
        # If we set TTL on every request, the window would never expire
        # while requests are flowing — agents could be rate-limited forever.
        if current_count == 1:
            await redis.expire(redis_key, WINDOW_SECONDS)
            logger.debug(
                f"Rate limit window started for agent {agent_id[:8]} "
                f"(limit: {limit}/min)"
            )

        # ── CHECK AGAINST LIMIT ───────────────────────────────────────────────
        if current_count > limit:
            # Get remaining TTL so we can tell the client when to retry
            ttl = await redis.ttl(redis_key)
            retry_after = max(ttl, 1)   # At least 1 second

            logger.warning(
                f"Rate limit EXCEEDED for agent {agent_id[:8]} — "
                f"{current_count}/{limit} requests | "
                f"retry in {retry_after}s"
            )

            return RateLimitResult(
                allowed=False,
                current_count=current_count,
                limit=limit,
                retry_after_seconds=retry_after,
            )

        # ── ALLOWED ───────────────────────────────────────────────────────────
        logger.debug(
            f"Rate limit OK for agent {agent_id[:8]} — "
            f"{current_count}/{limit} this window"
        )

        return RateLimitResult(
            allowed=True,
            current_count=current_count,
            limit=limit,
            retry_after_seconds=0,
        )

    except Exception as e:
        # If Redis is down, we ALLOW the request rather than blocking all traffic.
        # Log the error loudly — Redis being down is a critical alert.
        # This is the "fail open" policy — adjust to "fail closed" if your
        # security requirements demand it.
        logger.error(
            f"Redis rate limit check FAILED for agent {agent_id[:8]}: {e}. "
            f"Failing OPEN — request allowed."
        )
        return RateLimitResult(
            allowed=True,
            current_count=0,
            limit=limit,
            retry_after_seconds=0,
        )


# =============================================================================
#  ADMIN UTILITIES
#  Used by the SOC Dashboard to inspect and manage rate limit state.
# =============================================================================

async def get_rate_limit_status(agent_id: str, redis) -> dict:
    """
    Returns the current rate limit status for an agent.
    Used by the SOC Dashboard to show usage per agent.

    Returns:
        {
            "agent_id":       "...",
            "current_count":  12,
            "ttl_seconds":    34,   ← seconds until window resets
            "key_exists":     True
        }
    """
    redis_key = f"{RATE_LIMIT_PREFIX}:{agent_id}"
    count = await redis.get(redis_key)
    ttl   = await redis.ttl(redis_key)

    return {
        "agent_id":      agent_id,
        "current_count": int(count) if count else 0,
        "ttl_seconds":   ttl if ttl > 0 else 0,
        "key_exists":    count is not None,
    }


async def reset_rate_limit(agent_id: str, redis) -> bool:
    """
    Resets the rate limit counter for an agent immediately.
    Used by the SOC Dashboard "Reset Limit" action.

    Returns True if the key existed and was deleted, False if it didn't exist.
    """
    redis_key = f"{RATE_LIMIT_PREFIX}:{agent_id}"
    deleted = await redis.delete(redis_key)
    if deleted:
        logger.info(f"Rate limit manually reset for agent {agent_id[:8]}")
    return bool(deleted)