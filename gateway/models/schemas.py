# =============================================================================
#  MIDGUARD — gateway/models/schemas.py
#  All Pydantic data models (request & response shapes).
#
#  Pydantic validates every incoming request automatically.
#  If a required field is missing or has the wrong type,
#  FastAPI returns HTTP 422 before any security logic runs.
# =============================================================================

import uuid
from typing import Optional, List, Dict
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from enum import Enum


# =============================================================================
#  ENUMS — Fixed allowed values for key fields
# =============================================================================

class DecisionEnum(str, Enum):
    ALLOW      = "ALLOW"
    BLOCK      = "BLOCK"
    QUARANTINE = "QUARANTINE"

class RoleEnum(str, Enum):
    standard = "standard"
    admin    = "admin"

class StatusEnum(str, Enum):
    active    = "active"
    suspended = "suspended"
    blocked   = "blocked"


# =============================================================================
#  REQUEST MODELS — What the caller must send
# =============================================================================

class GatewayRequest(BaseModel):
    """
    The request body that every client must send to POST /v1/gateway.

    Example:
        {
            "prompt": "What is my account balance?",
            "action": "query",
            "context": "Customer is asking about their savings account.",
            "agent_id": "bot-customer-service-v1"
        }
    """
    prompt: str = Field(
        ...,                            # ... means required, no default
        min_length=1,
        max_length=10000,
        description="The human user's message to send to the AI agent.",
        examples=["What is my account balance?"],
    )
    action: str = Field(
        default="query",
        min_length=1,
        max_length=100,
        description="The type of action being requested. Used by the Policy Engine.",
        examples=["query", "summarize", "generate_report"],
    )
    context: Optional[str] = Field(
        default=None,
        max_length=50000,
        description="Optional system context or document provided to the AI agent.",
    )
    agent_id: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Identifier of the target AI agent. Optional for single-agent setups.",
    )
    session_id: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Optional session ID to group related requests in the audit log.",
    )
    metadata: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional key-value metadata attached to this request for audit purposes.",
    )
    target_url: Optional[str] = Field(
        default=None,
        max_length=2000,
        description="Optional target URL — checked by network egress rules.",
    )

    # ── Phase 5 test flags (development only) ─────────────────────────────────
    inject_pii_response:   bool = Field(default=False, description="[DEV] Force mock agent to return PII in response.")
    inject_hallucination:  bool = Field(default=False, description="[DEV] Force mock agent to return hallucinated response.")

    @field_validator("prompt")
    @classmethod
    def prompt_must_not_be_blank(cls, v: str) -> str:
        """Rejects prompts that are only whitespace."""
        if not v.strip():
            raise ValueError("Prompt cannot be empty or whitespace only.")
        return v.strip()

    @field_validator("action")
    @classmethod
    def action_must_be_alphanumeric(cls, v: str) -> str:
        """Action field should only contain letters, numbers, underscores, hyphens."""
        import re
        if not re.match(r'^[a-zA-Z0-9_\-]+$', v):
            raise ValueError(
                "Action must contain only letters, numbers, underscores, or hyphens."
            )
        return v.lower()

    class Config:
        json_schema_extra = {
            "example": {
                "prompt":  "What is my account balance?",
                "action":  "query",
                "context": "Customer is calling about their savings account opened in 2022.",
                "agent_id": "customer-service-bot-v1",
            }
        }


# =============================================================================
#  RESPONSE MODELS — What MIDGUARD returns
# =============================================================================

class GatewayResponse(BaseModel):
    """
    Returned when a request PASSES all security checks (decision = ALLOW).
    """
    decision:          DecisionEnum = Field(description="ALLOW / BLOCK / QUARANTINE")
    request_id:        str          = Field(description="Unique ID for this request.")
    agent_name:        str          = Field(description="Name of the authenticated agent.")
    threat_score:      float        = Field(description="Highest threat score detected (0.0–1.0).")
    phases_completed:  List[str]    = Field(description="List of security phases that ran.")
    message:           Optional[str] = Field(default=None, description="Human-readable status message.")
    ai_response:          Optional[str]       = Field(default=None, description="The AI agent response returned to the user.")
    output_filter_decision: Optional[str]    = Field(default=None, description="PASS / REDACT / BLOCK — what Phase 5 did to the response.")
    output_pii_redacted:  Optional[List[str]] = Field(default=None, description="PII types redacted from AI response.")
    processing_time_ms:   Optional[float]    = Field(default=None, description="Total gateway processing time.")

    class Config:
        json_schema_extra = {
            "example": {
                "decision":         "ALLOW",
                "request_id":       "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "agent_name":       "Customer Service Bot v1",
                "threat_score":     0.05,
                "phases_completed": ["auth", "rate_limit", "policy", "threat_detection"],
                "message":          "Request cleared all security checks.",
                "ai_response":      "Your current account balance is ₹24,500.",
            }
        }


class ErrorResponse(BaseModel):
    """
    Returned when a request is BLOCKED or an error occurs.
    This consistent structure makes it easy for callers to parse errors.
    """
    decision:     str           = Field(default="BLOCK")
    error:        str           = Field(description="Human-readable reason for the block/error.")
    http_status:  int           = Field(description="The HTTP status code.")
    request_id:   str           = Field(description="Unique ID for this request.")
    layer:        Optional[str] = Field(default=None, description="Which MIDGUARD layer blocked the request.")
    threat_score: Optional[float] = Field(default=None, description="Threat score if applicable.")

    class Config:
        json_schema_extra = {
            "example": {
                "decision":    "BLOCK",
                "error":       "Invalid API key",
                "http_status": 401,
                "request_id":  "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "layer":       "Auth Layer — HMAC-SHA256 Key Verification",
            }
        }


class HealthResponse(BaseModel):
    """Returned by GET /health — shows status of all connected services."""
    status:      str             = Field(description="Overall gateway status: healthy / degraded / down")
    version:     str             = Field(description="MIDGUARD version")
    environment: str             = Field(description="development / production")
    services:    Dict[str, str]  = Field(description="Status of each connected service")
    timestamp:   datetime        = Field(default_factory=datetime.utcnow)

    class Config:
        json_schema_extra = {
            "example": {
                "status":      "healthy",
                "version":     "1.0.0",
                "environment": "development",
                "services": {
                    "postgresql": "connected",
                    "redis":      "connected",
                    "llm_guard":  "loaded",
                },
                "timestamp": "2024-01-15T10:30:00Z",
            }
        }


# =============================================================================
#  INTERNAL MODELS — Used inside the gateway pipeline (not HTTP responses)
# =============================================================================

class AgentInfo(BaseModel):
    """
    Represents an authenticated agent's identity.
    Returned by verify_api_key() after successful authentication.
    Passed through the entire pipeline so every phase knows who is asking.
    """
    id:           uuid.UUID
    name:         str
    role:         RoleEnum
    status:       StatusEnum
    rate_limit:   int             = Field(description="Max requests per minute for this agent.")
    policy_tier:  str             = Field(default="standard", description="Which policy ruleset applies.")

    class Config:
        json_schema_extra = {
            "example": {
                "id":          "550e8400-e29b-41d4-a716-446655440000",
                "name":        "Customer Service Bot v1",
                "role":        "standard",
                "status":      "active",
                "rate_limit":  30,
                "policy_tier": "standard",
            }
        }


class RateLimitResult(BaseModel):
    """Returned by check_rate_limit() with the outcome of the rate limit check."""
    allowed:              bool
    current_count:        int
    limit:                int
    retry_after_seconds:  int = Field(default=0)


class PolicyResult(BaseModel):
    """Returned by the Policy Engine (Phase 2)."""
    blocked:         bool
    reason:          Optional[str] = None
    rule_triggered:  Optional[str] = None
    layer:           str           = "Policy Engine"


class ThreatResult(BaseModel):
    """Returned by the Threat Detection module (Phase 3)."""
    blocked:             bool
    threat_score:        float                      = 0.0
    reason:              Optional[str]              = None
    pii_types:           Optional[List[str]]        = None
    layer:               str                        = "Threat Detection"
    quarantine:          bool                       = False
    triggered_detector:  Optional[str]              = None
    detector_scores:     Optional[Dict[str, float]] = None