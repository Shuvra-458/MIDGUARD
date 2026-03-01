# =============================================================================
#  MIDGUARD — gateway/auth/middleware.py
#  API Key Authentication Layer
#
#  What this file does:
#    1. Reads the X-API-Key header from the incoming request
#    2. Hashes it using HMAC-SHA256 with the server secret
#    3. Queries PostgreSQL to find a matching agent record
#    4. Verifies the agent is active (not suspended or blocked)
#    5. Returns the agent's full identity (name, role, rate_limit, etc.)
#    6. Updates the agent's last_seen timestamp
#    7. Logs every auth attempt to the auth_events table
#
#  Security details:
#    - API keys are NEVER stored in plain text in the database
#    - Only the HMAC-SHA256 hash is stored
#    - Constant-time comparison prevents timing side-channel attacks
#    - If the database is leaked, hashes cannot be reversed to get real keys
#
#  HTTP Responses:
#    - 401 if key is missing, malformed, invalid, or expired
#    - 403 if key is valid but agent is suspended or blocked
#    - 200 if everything passes — agent identity returned to pipeline
# =============================================================================

import hashlib
import hmac
import logging
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import settings
from gateway.models.schemas import AgentInfo, RoleEnum, StatusEnum
from gateway.models.db_models import Agent, AuthEvent

logger = logging.getLogger("midguard.auth.middleware")


# =============================================================================
#  HMAC KEY HASHING
# =============================================================================

def hash_api_key(raw_key: str) -> str:
    """
    Hashes a raw API key using HMAC-SHA256.

    HMAC (Hash-based Message Authentication Code) uses a secret key
    in addition to the data being hashed. This means:
      - Even if two agents somehow use the same base key, their hashes
        differ because the secret binds the hash to this application.
      - Without knowing HMAC_SECRET_KEY, you cannot produce a valid hash.

    Args:
        raw_key: The plain text API key from the X-API-Key header

    Returns:
        64-character hex string (SHA-256 output = 32 bytes = 64 hex chars)
    """
    return hmac.new(
        key=settings.HMAC_SECRET_KEY.encode("utf-8"),
        msg=raw_key.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def constant_time_compare(val1: str, val2: str) -> bool:
    """
    Compares two strings in constant time to prevent timing attacks.

    Why this matters:
        Naive comparison (val1 == val2) stops at the first differing
        character. An attacker can measure tiny response time differences
        to deduce how many characters of their guess are correct.
        This is called a timing side-channel attack.

        hmac.compare_digest() always takes identical time regardless
        of where the strings differ — making this attack impossible.
    """
    return hmac.compare_digest(
        val1.encode("utf-8"),
        val2.encode("utf-8"),
    )


# =============================================================================
#  API KEY GENERATION UTILITY
#  Used by scripts/create_agent.py to generate new agent keys.
# =============================================================================

def generate_api_key() -> tuple[str, str]:
    """
    Generates a new API key pair: (raw_key, hashed_key).

    The raw_key is given to the agent owner — used in every request header.
    The hashed_key is stored in PostgreSQL — the raw key is never stored.

    Format:  msk_v1_<64 random hex characters>
    Example: msk_v1_a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2

    Returns:
        Tuple of (raw_key, hashed_key)
    """
    random_part = uuid.uuid4().hex + uuid.uuid4().hex   # 64 hex chars
    raw_key = f"msk_v1_{random_part}"
    hashed_key = hash_api_key(raw_key)
    return raw_key, hashed_key


# =============================================================================
#  MAIN AUTHENTICATION FUNCTION
# =============================================================================

async def verify_api_key(
    api_key:    str,
    db:         AsyncSession,
    request_id: str,
) -> AgentInfo:
    """
    Verifies the API key and returns the authenticated agent's identity.

    This is called as the very first step in the MIDGUARD pipeline.
    If this raises, the request is rejected immediately — Phases 2-5 never run.

    Args:
        api_key:    Raw key value from the X-API-Key header
        db:         Async SQLAlchemy session (injected by FastAPI Depends)
        request_id: UUID string for this request (for log tracing)

    Returns:
        AgentInfo — the agent's identity, passed through all pipeline phases

    Raises:
        HTTPException(401): Key missing, wrong format, or not found in DB
        HTTPException(403): Key valid but agent is suspended or blocked
    """

    # ── STEP 1: Basic format check ───────────────────────────────────────────
    # Reject obviously wrong keys immediately — zero database queries wasted.

    if not api_key:
        logger.warning(f"[{request_id[:8]}] Auth FAILED — no API key provided")
        await _log_auth_event(db, None, "missing_key", request_id)
        raise HTTPException(
            status_code=401,
            detail="API key required. Add request header: X-API-Key: msk_v1_...",
        )

    if not api_key.startswith("msk_v1_"):
        logger.warning(
            f"[{request_id[:8]}] Auth FAILED — wrong format "
            f"(got '{api_key[:12]}...')"
        )
        await _log_auth_event(db, None, "invalid_key", request_id)
        raise HTTPException(
            status_code=401,
            detail="Invalid API key format. Keys must start with 'msk_v1_'",
        )

    if len(api_key) < 71:
        # msk_v1_ = 7 chars, + 64 hex chars = 71 minimum
        logger.warning(f"[{request_id[:8]}] Auth FAILED — key too short ({len(api_key)} chars)")
        await _log_auth_event(db, None, "invalid_key", request_id)
        raise HTTPException(
            status_code=401,
            detail="Invalid API key. Key length is incorrect.",
        )

    # ── STEP 2: Hash the provided key ────────────────────────────────────────
    # We compare hashes — never raw keys.

    provided_hash = hash_api_key(api_key)

    # ── STEP 3: Query the database ───────────────────────────────────────────
    # Look up an agent with a matching stored hash.

    result = await db.execute(
        select(Agent).where(Agent.api_key_hash == provided_hash)
    )
    agent_record = result.scalar_one_or_none()

    if agent_record is None:
        logger.warning(
            f"[{request_id[:8]}] Auth FAILED — key hash not found in database"
        )
        await _log_auth_event(db, None, "invalid_key", request_id)
        # Deliberately vague error — don't tell attacker the key format was correct
        raise HTTPException(status_code=401, detail="Invalid API key.")

    # ── STEP 4: Constant-time comparison (extra safety layer) ─────────────────
    if not constant_time_compare(provided_hash, agent_record.api_key_hash):
        logger.error(
            f"[{request_id[:8]}] Auth ANOMALY — hash mismatch post-DB match "
            f"for agent '{agent_record.name}'. Possible DB corruption."
        )
        raise HTTPException(status_code=401, detail="Invalid API key.")

    # ── STEP 5: Check agent status ───────────────────────────────────────────
    # Valid key, but is the agent allowed to use it?

    if agent_record.status == "suspended":
        logger.warning(
            f"[{request_id[:8]}] Auth FAILED — "
            f"agent '{agent_record.name}' is SUSPENDED"
        )
        await _log_auth_event(db, str(agent_record.id), "suspended_agent", request_id)
        raise HTTPException(
            status_code=403,
            detail=(
                f"Agent '{agent_record.name}' has been suspended. "
                "Contact your MIDGUARD administrator."
            ),
        )

    if agent_record.status == "blocked":
        logger.warning(
            f"[{request_id[:8]}] Auth FAILED — "
            f"agent '{agent_record.name}' is BLOCKED"
        )
        await _log_auth_event(db, str(agent_record.id), "blocked_agent", request_id)
        raise HTTPException(
            status_code=403,
            detail=(
                f"Agent '{agent_record.name}' is permanently blocked. "
                "Contact your MIDGUARD administrator."
            ),
        )

    # ── STEP 6: Update last_seen ─────────────────────────────────────────────
    # Powers the "Last Seen" column in the SOC Dashboard agent table.

    await db.execute(
        update(Agent)
        .where(Agent.id == agent_record.id)
        .values(last_seen=datetime.now(timezone.utc))
    )

    # ── STEP 7: Log success ───────────────────────────────────────────────────
    await _log_auth_event(db, str(agent_record.id), "success", request_id)

    logger.info(
        f"[{request_id[:8]}] ✓ Auth PASSED — "
        f"agent '{agent_record.name}' | role: {agent_record.role}"
    )

    # ── STEP 8: Return agent identity ────────────────────────────────────────
    return AgentInfo(
        id=agent_record.id,
        name=agent_record.name,
        role=RoleEnum(agent_record.role),
        status=StatusEnum(agent_record.status),
        rate_limit=agent_record.rate_limit,
        policy_tier=agent_record.policy_tier,
    )


# =============================================================================
#  INTERNAL — Auth event logger
# =============================================================================

async def _log_auth_event(
    db:         AsyncSession,
    agent_id:   str | None,
    event_type: str,
    request_id: str,
) -> None:
    """
    Writes an authentication event to the auth_events table.

    Every attempt — success or failure — is permanently logged.
    This powers:
      - SOC Dashboard activity feed
      - Repeated failure detection (brute force alerts)
      - Access pattern forensics

    event_type values:
        "success"         — key valid, agent active
        "invalid_key"     — hash not found in DB
        "missing_key"     — no X-API-Key header at all
        "suspended_agent" — key valid but agent suspended
        "blocked_agent"   — key valid but agent blocked
    """
    try:
        event = AuthEvent(
            id=uuid.uuid4(),
            agent_id=uuid.UUID(agent_id) if agent_id else None,
            event_type=event_type,
            request_id=uuid.UUID(request_id) if request_id else uuid.uuid4(),
            timestamp=datetime.now(timezone.utc),
        )
        db.add(event)
        await db.flush()
    except Exception as e:
        # Never let logging failures crash the auth flow
        logger.error(f"Failed to write auth_event: {e}")