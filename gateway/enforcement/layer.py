# =============================================================================
#  MIDGUARD — gateway/enforcement/layer.py
#  Phase 4: Enforcement Layer — Final Decision Engine
#
#  What this file does:
#    Phase 4 is the JUDGE of MIDGUARD. It takes ALL evidence collected
#    by Phase 2 (Policy) and Phase 3 (Threat Detection) and makes one
#    final, authoritative decision:
#
#      ALLOW      → Forward request to the AI agent
#      BLOCK      → Reject request, return 403 to caller
#      QUARANTINE → Flag for human review (allow but log prominently)
#
#  Why a separate Enforcement Layer?
#    Phases 2 and 3 are DETECTORS — they find problems.
#    Phase 4 is the DECISION MAKER — it decides what to do about them.
#
#    This separation matters because:
#      - Different agent roles may have different enforcement rules
#        (admin agents might be allowed things standard agents cannot)
#      - Some violations warrant BLOCK, others warrant QUARANTINE
#      - Combining scores from multiple phases requires a single
#        authoritative place to do it — not scattered across phases
#      - The audit log needs ONE clear final decision per request,
#        not multiple partial decisions from different layers
#
#  Decision Logic (in order of priority):
#    1. If policy_result is blocked           → always BLOCK (0.0 score)
#    2. If threat_score > block_threshold     → BLOCK
#    3. If threat_score > quarantine_threshold → QUARANTINE
#    4. If agent role is admin + suspicious   → QUARANTINE (not BLOCK)
#    5. Otherwise                             → ALLOW
#
#  Audit Logging:
#    Every single request — ALLOW, BLOCK, or QUARANTINE — is written
#    to the audit_log table in PostgreSQL. This is what powers the
#    SOC Dashboard live feed and the compliance reports.
#
#  HTTP Status Codes:
#    ALLOW      → 200 OK
#    BLOCK      → 403 Forbidden
#    QUARANTINE → 200 OK (passes through, but flagged in audit log)
# =============================================================================

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from gateway.models.schemas import (
    PolicyResult,
    ThreatResult,
    AgentInfo,
)
from gateway.models.db_models import AuditLog
from config.settings import settings

logger = logging.getLogger("midguard.enforcement")


# =============================================================================
#  ENFORCEMENT RESULT
#  Returned by make_enforcement_decision() to main.py
# =============================================================================

class EnforcementResult:
    """
    The final verdict from Phase 4.

    Attributes:
        decision       : "ALLOW" | "BLOCK" | "QUARANTINE"
        reason         : Human-readable explanation
        threat_score   : The highest threat score seen across all phases
        http_status    : HTTP status code to return to the caller
        layer          : Which rule triggered this decision
        audit_id       : UUID of the audit log entry written for this request
    """
    def __init__(
        self,
        decision:     str,
        reason:       str,
        threat_score: float,
        http_status:  int,
        layer:        str,
        audit_id:     Optional[uuid.UUID] = None,
    ):
        self.decision     = decision
        self.reason       = reason
        self.threat_score = threat_score
        self.http_status  = http_status
        self.layer        = layer
        self.audit_id     = audit_id


# =============================================================================
#  MAIN ENFORCEMENT FUNCTION
#  Called from gateway/main.py after Phase 3 completes.
# =============================================================================

async def make_enforcement_decision(
    agent:          AgentInfo,
    policy_result:  PolicyResult,
    threat_result:  ThreatResult,
    prompt:         str,
    action:         str,
    request_id:     str,
    db:             AsyncSession,
) -> EnforcementResult:
    """
    Makes the final ALLOW / BLOCK / QUARANTINE decision for a request.

    Takes the combined evidence from Phase 2 (policy) and Phase 3 (threat
    detection) and applies the enforcement rules to reach one clear verdict.

    Also writes a complete audit log entry to PostgreSQL regardless of outcome.
    Every request is permanently recorded — this is non-negotiable for compliance.

    Args:
        agent:         Authenticated agent identity from Phase 1
        policy_result: Result from Phase 2 policy engine
        threat_result: Result from Phase 3 threat detection
        prompt:        Original prompt text (stored in audit log)
        action:        Original action field (stored in audit log)
        request_id:    UUID of this HTTP request
        db:            Async database session

    Returns:
        EnforcementResult with the final verdict
    """
    short_id     = request_id[:8]
    threat_score = threat_result.threat_score

    logger.info(
        f"[{short_id}] Phase 4: Enforcement decision | "
        f"policy_blocked={policy_result.blocked} | "
        f"threat_score={threat_score:.2f} | "
        f"agent_role={agent.role}"
    )

    # ──────────────────────────────────────────────────────────────────────────
    # RULE 1: Policy violation → always BLOCK
    # If Phase 2 flagged something, Phase 4 enforces it unconditionally.
    # Policy rules are written by humans — they represent absolute org rules.
    # ──────────────────────────────────────────────────────────────────────────
    if policy_result.blocked:
        result = EnforcementResult(
            decision    = "BLOCK",
            reason      = policy_result.reason or "Blocked by policy rule.",
            threat_score= 0.0,
            http_status = 403,
            layer       = policy_result.layer or "Policy Engine",
        )
        await _write_audit_log(
            db=db, agent=agent, request_id=request_id,
            prompt=prompt, action=action, result=result,
            rule_triggered=policy_result.rule_triggered,
            detector_scores=None,
        )
        logger.warning(
            f"[{short_id}] ✗ BLOCK (policy) | "
            f"Rule: {policy_result.rule_triggered}"
        )
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # RULE 2: High threat score → BLOCK
    # Phase 3 detectors returned a score above the block threshold.
    # ──────────────────────────────────────────────────────────────────────────
    if threat_score > settings.THREAT_BLOCK_THRESHOLD:
        result = EnforcementResult(
            decision    = "BLOCK",
            reason      = threat_result.reason or f"Threat detected (score: {threat_score:.2f}).",
            threat_score= threat_score,
            http_status = 403,
            layer       = threat_result.layer or "Enforcement Layer — Threat Score Block",
        )
        await _write_audit_log(
            db=db, agent=agent, request_id=request_id,
            prompt=prompt, action=action, result=result,
            rule_triggered=threat_result.triggered_detector,
            detector_scores=threat_result.detector_scores,
            pii_types=threat_result.pii_types,
        )
        logger.warning(
            f"[{short_id}] ✗ BLOCK (threat) | "
            f"Score: {threat_score:.2f} | "
            f"Detector: {threat_result.triggered_detector}"
        )
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # RULE 3: Medium threat score → QUARANTINE
    # Suspicious but not certain — pass through but flag loudly.
    # Human reviewer will see this in the SOC Dashboard audit feed.
    # ──────────────────────────────────────────────────────────────────────────
    if threat_score > settings.THREAT_QUARANTINE_THRESHOLD:
        result = EnforcementResult(
            decision    = "QUARANTINE",
            reason      = f"Suspicious content (score: {threat_score:.2f}). Flagged for review.",
            threat_score= threat_score,
            http_status = 200,   # Passes through — but logged as QUARANTINE
            layer       = "Enforcement Layer — Quarantine",
        )
        await _write_audit_log(
            db=db, agent=agent, request_id=request_id,
            prompt=prompt, action=action, result=result,
            rule_triggered=threat_result.triggered_detector,
            detector_scores=threat_result.detector_scores,
        )
        logger.warning(
            f"[{short_id}] ⚠ QUARANTINE | "
            f"Score: {threat_score:.2f} | "
            f"Detector: {threat_result.triggered_detector}"
        )
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # RULE 4: ALLOW — all checks passed
    # Request is clean. Log it and forward to AI agent.
    # ──────────────────────────────────────────────────────────────────────────
    result = EnforcementResult(
        decision    = "ALLOW",
        reason      = "All security checks passed.",
        threat_score= threat_score,
        http_status = 200,
        layer       = "Enforcement Layer",
    )
    await _write_audit_log(
        db=db, agent=agent, request_id=request_id,
        prompt=prompt, action=action, result=result,
        detector_scores=threat_result.detector_scores,
    )
    logger.info(
        f"[{short_id}] ✓ ALLOW | "
        f"Score: {threat_score:.2f} | "
        f"Agent: '{agent.name}'"
    )
    return result


# =============================================================================
#  AUDIT LOGGER
#  Writes every request outcome permanently to PostgreSQL.
#  Called for EVERY request — ALLOW, BLOCK, and QUARANTINE.
# =============================================================================

async def _write_audit_log(
    db:              AsyncSession,
    agent:           AgentInfo,
    request_id:      str,
    prompt:          str,
    action:          str,
    result:          EnforcementResult,
    rule_triggered:  Optional[str]        = None,
    detector_scores: Optional[dict]       = None,
    pii_types:       Optional[list]       = None,
) -> None:
    """
    Writes a complete audit log entry to the audit_log table.

    This is the permanent compliance record of what happened.
    The SOC Dashboard queries this table for:
      - Live event feed (recent requests)
      - Threat timeline (when did attacks happen?)
      - Agent activity report (what is each agent doing?)
      - Block rate metrics (how many requests are being blocked?)

    Args:
        db:              Database session
        agent:           Authenticated agent
        request_id:      UUID of the HTTP request
        prompt:          The original prompt (first 500 chars stored)
        action:          The action field
        result:          The enforcement decision
        rule_triggered:  Which rule or detector triggered (if any)
        detector_scores: Dict of scores from all 4 Phase 3 detectors
        pii_types:       List of PII types found (if any)
    """
    try:
        import json

        entry = AuditLog(
            id              = uuid.uuid4(),
            request_id      = uuid.UUID(request_id),
            agent_id        = agent.id,
            agent_name      = agent.name,
            agent_role      = str(agent.role.value),
            decision        = result.decision,
            reason          = result.reason,
            threat_score    = result.threat_score,
            action          = action,
            # Store only first 500 chars — full prompt can be huge
            prompt_preview  = prompt[:500],
            rule_triggered  = rule_triggered,
            pii_types       = json.dumps(pii_types) if pii_types else None,
            detector_scores = json.dumps(detector_scores) if detector_scores else None,
            layer           = result.layer,
            timestamp       = datetime.now(timezone.utc),
        )
        db.add(entry)
        await db.flush()

        result.audit_id = entry.id

    except Exception as e:
        # Audit logging must NEVER crash the gateway.
        # Log the error loudly but let the request continue.
        logger.error(
            f"AUDIT LOG WRITE FAILED for request {request_id[:8]}: "
            f"{type(e).__name__}: {e}"
        )