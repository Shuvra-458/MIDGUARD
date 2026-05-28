# =============================================================================
#  MIDGUARD — main.py
#  Middleware Intelligent Defense Gateway for User-Agent Request Defense
#
#  Entry point for the MIDGUARD security gateway server.
#  This file:
#    1. Creates the FastAPI application
#    2. Registers all middleware (CORS, logging, timing)
#    3. Connects to PostgreSQL and Redis on startup
#    4. Defines the single main gateway endpoint POST /v1/gateway
#    5. Wires together all security pipeline phases
#
#  Request flow:
#    POST /v1/gateway
#        │
#        ▼
#    [Phase 1]  Auth & Identity Layer        ← THIS FILE orchestrates
#        │           ├── API Key Validation   ← auth/middleware.py
#        │           └── Rate Limiter         ← auth/rate_limiter.py
#        │
#        ▼
#    [Phase 2]  Policy Engine                ← Coming next (policy/engine.py)
#        │
#        ▼
#    [Phase 3]  Threat Detection             ← Coming next (threat/scanner.py)
#        │
#        ▼
#    [Phase 4]  Enforcement Layer            ← Coming next (enforcement/layer.py)
#        │
#        ▼
#    [Phase 5]  Output Filter                ← Coming next (output/filter.py)
#        │
#        ▼
#    ALLOW → Forward to AI Agent
#    BLOCK → Return error to user
# =============================================================================

import time
import uuid
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Depends, Header, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Internal imports — we will create these files one by one
from gateway.models.schemas import (
    GatewayRequest,
    GatewayResponse,
    ErrorResponse,
    HealthResponse,
    AgentInfo,
)
from gateway.auth.middleware import verify_api_key
from gateway.auth.rate_limiter import check_rate_limit
from gateway.policy.engine import run_policy_engine, load_policy_rules
from gateway.threat.scanner import run_threat_detection
from gateway.enforcement.layer import make_enforcement_decision, EnforcementResult
from gateway.output.filter import run_output_filter
from gateway.output.mock_agent import call_mock_agent
from gateway.database import get_db, init_db, close_db
from gateway.redis_client import get_redis, init_redis, close_redis
from config.settings import settings
from gateway.threat.emotion_detector import scan_emotion_cvv
from gateway.soc.routes import router as soc_router
from gateway.auth.login import router as auth_router
from gateway.threat.emotion_detector import preload_deberta_model
import time  # To calculate how fast DeBERTa is
# =============================================================================
#  LOGGING SETUP
#  Structured logging so every event is traceable in production
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("midguard.main")


# =============================================================================
#  LIFESPAN — Startup & Shutdown
#  FastAPI's modern way to run code on startup and shutdown.
#  Replaces the old @app.on_event("startup") decorator.
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs on server startup:
      - Connects to PostgreSQL database
      - Connects to Redis
      - Logs confirmation that all systems are ready

    Runs on server shutdown:
      - Gracefully closes all database connections
      - Closes Redis connection pool
    """
    # ── STARTUP ──────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("  MIDGUARD Security Gateway — Starting Up")
    logger.info("  Middleware Intelligent Defense Gateway")
    logger.info("=" * 60)

    logger.info("Connecting to PostgreSQL...")
    await init_db()
    logger.info("✓ PostgreSQL connected")

    logger.info("Connecting to Redis...")
    await init_redis()
    logger.info("✓ Redis connected")

    logger.info("Loading policy rules...")
    load_policy_rules()
    logger.info("✓ Policy rules loaded")

    logger.info("Pre-loading local ML models (DeBERTa + SpaCy)...")
    preload_deberta_model()

    logger.info(f"Environment : {settings.ENVIRONMENT}")
    logger.info(f"Gateway     : http://0.0.0.0:{settings.PORT}")
    logger.info(f"Rate Limit  : {settings.DEFAULT_RATE_LIMIT} req/min (default)")
    logger.info("=" * 60)
    logger.info("MIDGUARD is ACTIVE — All requests will be screened")
    logger.info("=" * 60)

    yield  # ← Application runs here

    # ── SHUTDOWN ─────────────────────────────────────────────
    logger.info("Shutting down MIDGUARD...")
    await close_db()
    await close_redis()
    logger.info("MIDGUARD shut down cleanly.")


# =============================================================================
#  FASTAPI APPLICATION
#  The core application instance.
# =============================================================================

app = FastAPI(
    title="MIDGUARD Security Gateway",
    description="""
## Middleware Intelligent Defense Gateway for User-Agent Request Defense

MIDGUARD sits between **human users** and **AI agents**, screening every
request and response through a 5-phase security pipeline:

| Phase | Layer | What It Does |
|-------|-------|--------------|
| 1 | Auth & Identity | Validates API keys, enforces rate limits |
| 2 | Policy Engine | Checks YAML-based organizational rules |
| 3 | Threat Detection | AI-powered injection & PII scanning |
| 4 | Enforcement | Makes final Allow/Block/Quarantine decision |
| 5 | Output Filter | Scans AI responses before returning to user |

### Decision Codes
- **ALLOW** — Request passed all checks, forwarded to AI agent
- **BLOCK** — Request blocked, returned 403 to caller
- **QUARANTINE** — Suspicious but not certain, flagged for review
    """,
    version="1.0.0",
    docs_url="/docs",        # Swagger UI at http://localhost:8000/docs
    redoc_url="/redoc",      # ReDoc UI at http://localhost:8000/redoc
    lifespan=lifespan,
)


# =============================================================================
#  MIDDLEWARE
#  Code that runs on EVERY request before it reaches any endpoint.
# =============================================================================

# ── CORS ─────────────────────────────────────────────────────────────────────
# Allows browser-based frontends to call the gateway API.
app.include_router(soc_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── REQUEST TIMING & REQUEST ID ──────────────────────────────────────────────
# Attaches a unique request ID to every request and logs timing.
# This is how you trace a specific request through all log lines.
@app.middleware("http")
async def request_id_and_timing(request: Request, call_next):
    """
    For every incoming request:
    1. Generate a unique request ID (UUID)
    2. Attach it to the request state so all handlers can log it
    3. Measure total processing time
    4. Add timing and request ID to the response headers
    """
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    request.state.start_time = time.time()

    logger.info(
        f"[{request_id[:8]}] ► {request.method} {request.url.path} "
        f"| IP: {request.client.host}"
    )

    response = await call_next(request)

    duration_ms = round((time.time() - request.state.start_time) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time-Ms"] = str(duration_ms)

    logger.info(
        f"[{request_id[:8]}] ◄ {response.status_code} | {duration_ms}ms"
    )

    return response


# =============================================================================
#  EXCEPTION HANDLERS
#  Custom responses for common HTTP errors — returns clean JSON
#  instead of FastAPI's default HTML error pages.
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Returns all HTTP errors as clean JSON with consistent structure."""
    request_id = getattr(request.state, "request_id", "unknown")
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.detail,
            http_status=exc.status_code,
            request_id=request_id,
        ).model_dump(),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Catches any unhandled Python exception — prevents raw stack traces
    from leaking to the client in production."""
    request_id = getattr(request.state, "request_id", "unknown")
    logger.error(
        f"[{request_id[:8]}] Unhandled exception: {type(exc).__name__}: {exc}",
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal gateway error. The incident has been logged.",
            http_status=500,
            request_id=request_id,
        ).model_dump(),
    )


# =============================================================================
#  UTILITY — Build standard blocked response
#  All BLOCK decisions use this function so the response format is
#  always consistent regardless of which phase triggered the block.
# =============================================================================

def build_block_response(
    reason: str,
    layer: str,
    threat_score: float,
    request_id: str,
    http_status: int = 403,
    extra: Optional[dict] = None,
) -> JSONResponse:
    """
    Builds the standard MIDGUARD BLOCK response.

    Every blocked request returns this exact same structure —
    this consistency is important for the audit logger and SOC Dashboard.

    Args:
        reason:       Human-readable explanation of why it was blocked
        layer:        Which MIDGUARD layer blocked it (e.g. "Auth Layer")
        threat_score: Float 0.0–1.0 from the threat detection model
        request_id:   UUID of this specific request
        http_status:  403 for security blocks, 429 for rate limit, 401 for auth
        extra:        Optional dict of additional fields (pii_types, etc.)
    """
    body = {
        "decision":      "BLOCK",
        "reason":        reason,
        "threat_score":  threat_score,
        "layer":         layer,
        "request_id":    request_id,
        "http_status":   http_status,
        "agent_reached": False,
    }
    if extra:
        body.update(extra)

    return JSONResponse(status_code=http_status, content=body)


# =============================================================================
#  ROUTES
# =============================================================================

# ── HEALTH CHECK ─────────────────────────────────────────────────────────────
@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Gateway health check",
    tags=["System"],
)
async def health_check():
    """
    Returns the live status of MIDGUARD and all connected services.
    Used by Docker health checks and monitoring tools like Prometheus.

    No authentication required — this endpoint is public.
    """
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        environment=settings.ENVIRONMENT,
        services={
            "postgresql": "connected",
            "redis":      "connected",
            "llm_guard":  "pending",   # Phase 3 will update this
        },
    )

# ── DEBERTA SCANNER TEST ENDPOINT ─────────────────────────────────────────
@app.post(
    "/v1/test/deberta",
    summary="Test the local DeBERTa CVV Scanner",
    tags=["Debug"],
)
async def test_deberta_scanner(
    prompt: str = Body(..., embed=True, description="The text to scan for injection intent")
):
    """
    Standalone test endpoint for Scanner 5 (DeBERTa).
    Bypasses all other phases to show exactly what the local AI model is thinking.
    """
    start_time = time.time()
    
    # Call the scanner directly
    result = await scan_emotion_cvv(prompt)
    
    duration_ms = round((time.time() - start_time) * 1000, 2)
    
    return {
        "scanner_name": "ProtectAI DeBERTa-v3-base",
        "model_location": "Local Container (Air-gapped)",
        "processing_time_ms": duration_ms,
        "analysis": result
    }

# ── ROOT ─────────────────────────────────────────────────────────────────────
@app.get("/", tags=["System"], include_in_schema=False)
async def root():
    """Returns a simple welcome message at the root URL."""
    return {
        "name":    "MIDGUARD Security Gateway",
        "version": "1.0.0",
        "status":  "active",
        "docs":    "/docs",
        "health":  "/health",
        "gateway": "POST /v1/gateway",
    }


# ── MAIN GATEWAY ENDPOINT ────────────────────────────────────────────────────
@app.post(
    "/v1/gateway",
    response_model=GatewayResponse,
    summary="Main security gateway endpoint",
    tags=["Gateway"],
    responses={
        200: {"description": "Request passed all security checks (ALLOW)"},
        401: {"description": "Missing or invalid API key"},
        403: {"description": "Request blocked by security pipeline (BLOCK)"},
        422: {"description": "Request body validation failed"},
        429: {"description": "Rate limit exceeded"},
        500: {"description": "Internal gateway error"},
    },
)
async def gateway_endpoint(
    request:     Request,
    body:        GatewayRequest,                     # Pydantic validates this automatically
    x_api_key:   str = Header(..., alias="X-API-Key"),  # Required header — 401 if missing
    db=Depends(get_db),                              # PostgreSQL session injected
    redis=Depends(get_redis),                        # Redis client injected
):
    """
    ## The Main MIDGUARD Gateway

    Every request from a human user to an AI agent must pass through this endpoint.
    The request travels through each security phase in order.
    The first phase that rejects the request immediately returns a BLOCK response.
    Only requests that pass ALL phases are forwarded to the AI agent.

    ### Required Headers
    - `X-API-Key`: Your MIDGUARD agent API key (format: `msk_v1_...`)

    ### Request Body
    See the GatewayRequest schema below.

    ### Response
    - **ALLOW**: Request passed — AI agent response returned
    - **BLOCK**: Request blocked — reason and threat score returned
    """
    request_id = request.state.request_id

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 1A — API KEY AUTHENTICATION
    # Verify the X-API-Key header is valid and the agent is active.
    # Returns the agent's identity if valid, raises HTTP 401 if not.
    # ──────────────────────────────────────────────────────────────────────
    logger.info(f"[{request_id[:8]}] Phase 1A: API key authentication")

    agent: AgentInfo = await verify_api_key(
        api_key=x_api_key,
        db=db,
        request_id=request_id,
    )
    # If verify_api_key raises HTTPException(401), execution stops here.
    # The http_exception_handler above catches it and returns clean JSON.

    logger.info(
        f"[{request_id[:8]}] ✓ Auth passed | Agent: '{agent.name}' | "
        f"Role: {agent.role}"
    )

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 1B — RATE LIMITING
    # Check if this agent has exceeded their requests-per-minute limit.
    # Uses Token Bucket algorithm in Redis.
    # ──────────────────────────────────────────────────────────────────────
    logger.info(f"[{request_id[:8]}] Phase 1B: Rate limit check")

    rate_limit_result = await check_rate_limit(
        agent_id=str(agent.id),
        limit=agent.rate_limit,
        redis=redis,
    )

    if not rate_limit_result.allowed:
        logger.warning(
            f"[{request_id[:8]}] ✗ Rate limit exceeded | Agent: '{agent.name}' | "
            f"Retry after: {rate_limit_result.retry_after_seconds}s"
        )
        return build_block_response(
            reason=f"Rate limit exceeded — {agent.rate_limit} req/min maximum",
            layer="Auth Layer — Token Bucket Rate Limiter",
            threat_score=0.0,
            request_id=request_id,
            http_status=429,
            extra={
                "requests_made":   rate_limit_result.current_count,
                "limit":           agent.rate_limit,
                "retry_after_sec": rate_limit_result.retry_after_seconds,
            },
        )

    logger.info(
        f"[{request_id[:8]}] ✓ Rate limit OK | "
        f"{rate_limit_result.current_count}/{agent.rate_limit} req/min"
    )

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 2 — POLICY ENGINE
    # Checks YAML-based organizational rules:
    #   - Input rules  (blocked keywords in prompt)
    #   - Action rules (forbidden action types)
    #   - Network rules (unauthorized domains)
    # 100% deterministic — same input always produces same result.
    # Under 1ms evaluation time.
    # ──────────────────────────────────────────────────────────────────────
    logger.info(f"[{request_id[:8]}] Phase 2: Policy engine")

    policy_result = await run_policy_engine(
        prompt=body.prompt,
        action=body.action,
        target_url=getattr(body, "target_url", None),
        agent_tier=agent.policy_tier,
    )

    if policy_result.blocked:
        logger.warning(
            f"[{request_id[:8]}] Policy flagged | "
            f"Rule: '{policy_result.rule_triggered}' — passing to Phase 4 enforcement"
        )
    else:
        logger.info(f"[{request_id[:8]}] ✓ Policy engine passed")

    # ──────────────────────────────────────────────────────────────────────
    # ──────────────────────────────────────────────────────────────────────
    # PHASE 3 — THREAT DETECTION
    # AI-powered scanning using LLM Guard + pattern matching:
    #   - Prompt injection detection (transformer + patterns)
    #   - Jailbreak detection (pattern library)
    #   - PII scanning (spaCy NER + regex)
    #   - Toxicity scanning (LLM Guard + keywords)
    # All 4 scanners run concurrently via asyncio.gather()
    # ──────────────────────────────────────────────────────────────────────
    logger.info(f"[{request_id[:8]}] Phase 3: Threat detection")

    threat_result = await run_threat_detection(
        prompt=body.prompt,
    )

    if threat_result.blocked:
        logger.warning(
            f"[{request_id[:8]}] Threat flagged | "
            f"Detector: {threat_result.triggered_detector} | "
            f"Score: {threat_result.threat_score} — passing to Phase 4 enforcement"
        )
    else:
        logger.info(
            f"[{request_id[:8]}] ✓ Threat detection passed | "
            f"Score: {threat_result.threat_score}"
        )

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 4 — ENFORCEMENT LAYER
    # Takes Phase 2 + Phase 3 results and makes ONE final decision.
    # Also writes the permanent audit log entry for this request.
    # ──────────────────────────────────────────────────────────────────────
    logger.info(f"[{request_id[:8]}] Phase 4: Enforcement decision")

    enforcement = await make_enforcement_decision(
        agent          = agent,
        policy_result  = policy_result,
        threat_result  = threat_result,
        prompt         = body.prompt,
        action         = body.action,
        request_id     = request_id,
        db             = db,
    )

    # If enforcement decided BLOCK, return immediately
    if enforcement.decision == "BLOCK":
        block_extra: dict = {}
        # Include rule_triggered for policy blocks (Phase 2)
        if policy_result.blocked and policy_result.rule_triggered:
            block_extra["rule_triggered"] = policy_result.rule_triggered
        # Include pii_types for PII threat blocks (Phase 3)
        if threat_result.blocked and threat_result.pii_types:
            block_extra["pii_types"] = threat_result.pii_types
        return build_block_response(
            reason       = enforcement.reason,
            layer        = enforcement.layer,
            threat_score = enforcement.threat_score,
            request_id   = request_id,
            http_status  = 403,
            extra        = block_extra if block_extra else None,
        )

    logger.info(
        f"[{request_id[:8]}] ✓ Enforcement: {enforcement.decision} | "
        f"Score: {enforcement.threat_score:.2f}"
    )

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 5 — OUTPUT FILTER
    # Step 5A: Call the AI agent to get its response
    # Step 5B: Scan the response before returning it to the user
    #   - PII Scanner  → redact personal data leaked in response
    #   - Hallucination → block severely confabulated responses
    #   - Toxicity     → block harmful AI output
    # ──────────────────────────────────────────────────────────────────────
    logger.info(f"[{request_id[:8]}] Phase 5: Calling AI agent")

    ai_response_text = await call_mock_agent(
        prompt       = body.prompt,
        context      = body.context,
        inject_pii   = getattr(body, "inject_pii_response",  False),
        inject_halluc= getattr(body, "inject_hallucination", False),
    )

    logger.info(f"[{request_id[:8]}] Phase 5: Scanning AI response")

    output_result = await run_output_filter(
        ai_response = ai_response_text,
        context     = body.context,
        request_id  = request_id,
    )

    # If output is blocked (toxic or severely hallucinated)
    if output_result.blocked:
        logger.warning(
            f"[{request_id[:8]}] ✗ Output BLOCK | "
            f"Reason: {output_result.reason}"
        )
        return build_block_response(
            reason       = output_result.reason,
            layer        = "Output Filter — Phase 5",
            threat_score = max(output_result.toxicity_score, output_result.hallucination_score),
            request_id   = request_id,
            http_status  = 403,
            extra        = {"output_filter_decision": output_result.decision},
        )

    if output_result.decision == "REDACT":
        logger.info(
            f"[{request_id[:8]}] ⚠ Output REDACT | "
            f"PII removed: {output_result.pii_found} | "
            f"Redactions: {output_result.redactions_made}"
        )
    else:
        logger.info(f"[{request_id[:8]}] ✓ Output filter PASS")

    # ──────────────────────────────────────────────────────────────────────
    # FINAL RESPONSE — All 5 phases complete
    # ──────────────────────────────────────────────────────────────────────
    logger.info(
        f"[{request_id[:8]}] ✓ PIPELINE COMPLETE | "
        f"Decision: {enforcement.decision} | "
        f"Agent: '{agent.name}' | "
        f"Score: {enforcement.threat_score:.2f}"
    )

    return GatewayResponse(
        decision                = enforcement.decision,
        request_id              = request_id,
        agent_name              = agent.name,
        threat_score            = enforcement.threat_score,
        phases_completed        = ["auth", "rate_limit", "policy", "threat_detection", "enforcement", "output_filter"],
        message                 = enforcement.reason,
        ai_response             = output_result.safe_response,
        output_filter_decision  = output_result.decision,
        output_pii_redacted     = output_result.pii_found if output_result.pii_found else None,
    )


# =============================================================================
#  ADMIN ENDPOINTS
#  For the SOC Dashboard and management operations.
#  All require authentication and admin role.
# =============================================================================

@app.get(
    "/v1/admin/agents",
    summary="List all registered agents",
    tags=["Admin"],
)
async def list_agents(
    request:   Request,
    x_api_key: str = Header(..., alias="X-API-Key"),
    db=Depends(get_db),
):
    """
    Returns a list of all registered AI agents and their status.
    Requires admin-level API key.

    Used by the SOC Dashboard to populate the agent management table.
    """
    request_id = request.state.request_id

    # Verify admin auth
    agent = await verify_api_key(api_key=x_api_key, db=db, request_id=request_id)
    if agent.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    # TODO: Query agents from database
    # For now, returns a placeholder so the endpoint exists and is testable
    return {
        "agents": [],
        "total": 0,
        "message": "Agent listing will be implemented with the agents database table.",
    }


@app.get(
    "/v1/admin/audit-log",
    summary="Query the audit log",
    tags=["Admin"],
)
async def get_audit_log(
    request:   Request,
    limit:     int = 50,
    x_api_key: str = Header(..., alias="X-API-Key"),
    db=Depends(get_db),
):
    """
    Returns recent audit log entries.
    Requires admin-level API key.

    Used by the SOC Dashboard's live event feed.
    """
    request_id = request.state.request_id

    agent = await verify_api_key(api_key=x_api_key, db=db, request_id=request_id)
    if agent.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    # TODO: Query audit_log table
    return {
        "events": [],
        "total":  0,
        "limit":  limit,
        "message": "Audit log will be populated as requests flow through the gateway.",
    }


# =============================================================================
#  ENTRY POINT
#  Runs the server directly when you execute: python main.py
#  In production, use: uvicorn gateway.main:app --host 0.0.0.0 --port 8000
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "gateway.main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=settings.ENVIRONMENT == "development",  # Auto-reload in dev mode
        log_level="info",
    )