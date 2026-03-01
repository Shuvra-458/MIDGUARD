# =============================================================================
#  MIDGUARD — gateway/models/db_models.py
#  SQLAlchemy ORM Database Models
#
#  These classes define the actual PostgreSQL tables.
#  Alembic reads these models and generates migration scripts automatically.
#
#  Tables created:
#    1. agents       — registered AI agents and their API key hashes
#    2. auth_events  — every authentication attempt (success or failure)
#
#  Later phases will add:
#    3. audit_log    — every request that passed auth (Phase 2+)
#    4. threat_events — detected threats with scores (Phase 3)
# =============================================================================

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Integer, Boolean,
    DateTime, Enum, ForeignKey, Text,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from gateway.database import Base


# =============================================================================
#  TABLE 1 — agents
#  Every AI agent registered with MIDGUARD.
#  One row per agent. The API key hash is stored here — never the raw key.
# =============================================================================

class Agent(Base):
    """
    Represents a registered AI agent in MIDGUARD.

    Example rows:
        name                      role       status    rate_limit
        "Customer Service Bot v1" standard   active    30
        "Finance Report Agent"    standard   active    30
        "MIDGUARD Admin Console"  admin      active    200
        "Compromised Bot"         standard   blocked   30
    """
    __tablename__ = "agents"

    # ── Primary Key ───────────────────────────────────────────────────────────
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Unique identifier for this agent",
    )

    # ── Identity ──────────────────────────────────────────────────────────────
    name = Column(
        String(200),
        nullable=False,
        comment="Human-readable name, e.g. 'Customer Service Bot v1'",
    )
    description = Column(
        Text,
        nullable=True,
        comment="Optional description of what this agent does",
    )

    # ── Authentication ────────────────────────────────────────────────────────
    api_key_hash = Column(
        String(64),                  # SHA-256 hash = always 64 hex chars
        nullable=False,
        unique=True,                 # Each agent has a unique key
        index=True,                  # Indexed for fast lookup on every request
        comment="HMAC-SHA256 hash of the raw API key. Never store the raw key.",
    )

    # ── Authorization ─────────────────────────────────────────────────────────
    role = Column(
        Enum("standard", "admin", name="agent_role"),
        nullable=False,
        default="standard",
        comment="'standard' for regular agents, 'admin' for SOC Dashboard access",
    )
    status = Column(
        Enum("active", "suspended", "blocked", name="agent_status"),
        nullable=False,
        default="active",
        comment="'active'=normal, 'suspended'=temporarily disabled, 'blocked'=permanently banned",
    )

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    rate_limit = Column(
        Integer,
        nullable=False,
        default=30,
        comment="Maximum requests per minute for this agent",
    )

    # ── Policy ────────────────────────────────────────────────────────────────
    policy_tier = Column(
        String(50),
        nullable=False,
        default="standard",
        comment="Which policy ruleset applies: 'standard', 'strict', 'permissive'",
    )

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="When this agent was registered",
    )
    last_seen = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When this agent last made a successful authenticated request",
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    auth_events = relationship(
        "AuthEvent",
        back_populates="agent",
        cascade="all, delete-orphan",
        lazy="noload",               # Don't auto-load — we query explicitly
    )

    def __repr__(self) -> str:
        return (
            f"<Agent id={str(self.id)[:8]} "
            f"name='{self.name}' "
            f"role={self.role} "
            f"status={self.status}>"
        )


# =============================================================================
#  TABLE 2 — auth_events
#  Every authentication attempt — success or failure — permanently logged.
#  This is the forensic record of who tried to access MIDGUARD and when.
# =============================================================================

class AuthEvent(Base):
    """
    One row per authentication attempt.

    Why log failures?
        - Repeated failures from the same request pattern = brute force attack
        - Failed attempts on a suspended agent = someone trying to reactivate it
        - Sudden spike in failures = credential stuffing attack in progress

    The SOC Dashboard queries this table to show:
        - Recent auth failures (live threat feed)
        - Per-agent access history
        - Suspicious patterns (5+ failures in 60 seconds = alert)
    """
    __tablename__ = "auth_events"

    # ── Primary Key ───────────────────────────────────────────────────────────
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # ── Foreign Key ───────────────────────────────────────────────────────────
    agent_id = Column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="SET NULL"),
        nullable=True,               # NULL when key is completely unknown
        index=True,
        comment="The agent this event belongs to. NULL if key was unrecognized.",
    )

    # ── Event Details ─────────────────────────────────────────────────────────
    event_type = Column(
        Enum(
            "success",
            "invalid_key",
            "missing_key",
            "suspended_agent",
            "blocked_agent",
            name="auth_event_type",
        ),
        nullable=False,
        index=True,
        comment="Outcome of this authentication attempt",
    )

    # ── Request Tracing ───────────────────────────────────────────────────────
    request_id = Column(
        UUID(as_uuid=True),
        nullable=True,
        comment="The UUID of the HTTP request — links this event to other log lines",
    )

    # ── Timestamp ─────────────────────────────────────────────────────────────
    timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,                  # Indexed for fast time-range queries
        comment="When this auth attempt occurred",
    )

    # ── Relationship ──────────────────────────────────────────────────────────
    agent = relationship("Agent", back_populates="auth_events")

    def __repr__(self) -> str:
        return (
            f"<AuthEvent "
            f"type={self.event_type} "
            f"agent={str(self.agent_id)[:8] if self.agent_id else 'unknown'} "
            f"at={self.timestamp}>"
        )


# =============================================================================
#  DATABASE INDEXES
#  Composite indexes for the most common query patterns.
#  Added here so they're created automatically by Alembic migrations.
# =============================================================================

# Fast lookup: "show all auth failures in the last 5 minutes"
Index(
    "ix_auth_events_type_timestamp",
    AuthEvent.event_type,
    AuthEvent.timestamp,
)

# Fast lookup: "show all events for agent X ordered by time"
Index(
    "ix_auth_events_agent_timestamp",
    AuthEvent.agent_id,
    AuthEvent.timestamp,
)


# =============================================================================
#  TABLE 3 — audit_log
#  Every request that passes Phase 1 auth is permanently logged here.
#  One row per request — ALLOW, BLOCK, and QUARANTINE all recorded.
#  Added in Phase 4 (Enforcement Layer).
# =============================================================================

class AuditLog(Base):
    """
    Permanent record of every gateway request and its enforcement outcome.

    This table powers:
      - SOC Dashboard live event feed
      - Compliance reports ("show all blocked requests this week")
      - Threat timeline ("when did injection attacks spike?")
      - Agent activity report ("what is each agent requesting?")
    """
    __tablename__ = "audit_log"

    # ── Primary Key ───────────────────────────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # ── Request Identity ──────────────────────────────────────────────────────
    request_id  = Column(UUID(as_uuid=True), nullable=False, index=True)
    agent_id    = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True)
    agent_name  = Column(String(200), nullable=False)
    agent_role  = Column(String(50),  nullable=False)

    # ── Request Content ───────────────────────────────────────────────────────
    prompt_preview  = Column(Text,        nullable=True,  comment="First 500 chars of the prompt")
    action          = Column(String(100), nullable=False)

    # ── Enforcement Decision ──────────────────────────────────────────────────
    decision     = Column(
        Enum("ALLOW", "BLOCK", "QUARANTINE", name="enforcement_decision"),
        nullable=False, index=True,
    )
    reason       = Column(Text,    nullable=True)
    threat_score = Column(Integer, nullable=True, comment="Score * 100 stored as int (0–100)")
    layer        = Column(String(200), nullable=True)

    # ── Threat Details ────────────────────────────────────────────────────────
    rule_triggered  = Column(String(200), nullable=True)
    pii_types       = Column(Text, nullable=True, comment="JSON array of PII types found")
    detector_scores = Column(Text, nullable=True, comment="JSON dict of all detector scores")

    # ── Timestamp ─────────────────────────────────────────────────────────────
    timestamp = Column(DateTime(timezone=True), nullable=False,
                       default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f"<AuditLog decision={self.decision} agent={self.agent_name} score={self.threat_score}>"


# Indexes for fast SOC Dashboard queries
Index("ix_audit_log_decision_timestamp", AuditLog.decision, AuditLog.timestamp)
Index("ix_audit_log_agent_timestamp",    AuditLog.agent_id,  AuditLog.timestamp)