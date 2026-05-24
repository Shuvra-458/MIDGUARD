# =============================================================================
#  MIDGUARD — gateway/soc/routes.py
#  SOC Dashboard API Routes
#  Provides all endpoints needed by the Gateway SOC frontend.
# =============================================================================

import uuid
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy import select, func, desc, and_, text
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from gateway.database import get_db
from gateway.models.db_models import Agent, AuthEvent, AuditLog
from gateway.auth.middleware import verify_api_key, hash_api_key, generate_api_key
from gateway.models.schemas import AgentInfo

logger = logging.getLogger("midguard.soc")

router = APIRouter(prefix="/v1/soc", tags=["SOC Dashboard"])


# =============================================================================
#  REQUEST / RESPONSE SCHEMAS
# =============================================================================

class CreateAgentRequest(BaseModel):
    name: str
    description: Optional[str] = None
    role: str = "standard"
    rate_limit: int = 30
    policy_tier: str = "standard"


class UpdateAgentRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    rate_limit: Optional[int] = None
    policy_tier: Optional[str] = None
    role: Optional[str] = None


class PolicyRuleRequest(BaseModel):
    name: str
    rule_type: str  # "input" | "action" | "network"
    pattern: str
    match: str = "contains"
    reason: str
    severity: str = "medium"
    enabled: bool = True


# =============================================================================
#  HELPER: get requesting agent (or allow unauthenticated for SOC demo)
# =============================================================================

async def _get_agent_optional(request: Request, db: AsyncSession) -> Optional[AgentInfo]:
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None
    try:
        return await verify_api_key(api_key=api_key, db=db, request_id=str(uuid.uuid4()))
    except HTTPException:
        return None


# =============================================================================
#  DASHBOARD STATS
# =============================================================================

@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Returns 24h summary stats for the SOC Dashboard header."""
    now = datetime.now(timezone.utc)
    window_24h = now - timedelta(hours=24)

    try:
        # Total requests in 24h
        total_result = await db.execute(
            select(func.count(AuditLog.id)).where(AuditLog.timestamp >= window_24h)
        )
        total = total_result.scalar() or 0

        # Blocked in 24h
        blocked_result = await db.execute(
            select(func.count(AuditLog.id)).where(
                and_(AuditLog.timestamp >= window_24h, AuditLog.decision == "BLOCK")
            )
        )
        blocked = blocked_result.scalar() or 0

        # Quarantined in 24h
        quarantined_result = await db.execute(
            select(func.count(AuditLog.id)).where(
                and_(AuditLog.timestamp >= window_24h, AuditLog.decision == "QUARANTINE")
            )
        )
        quarantined = quarantined_result.scalar() or 0

        block_rate = round((blocked / total * 100), 1) if total > 0 else 0.0

        return {
            "requests_24h": total,
            "blocked_24h": blocked,
            "quarantined_24h": quarantined,
            "allowed_24h": total - blocked - quarantined,
            "block_rate_pct": block_rate,
            "open_alerts": 0,
            "mean_latency_ms": 0,
            "p50_latency_ms": 0,
            "p95_latency_ms": 0,
            "rate_limited_24h": 0,
            "status": "OPERATIONAL",
        }
    except Exception as e:
        logger.error(f"Stats query error: {e}")
        return {
            "requests_24h": 0, "blocked_24h": 0, "quarantined_24h": 0,
            "allowed_24h": 0, "block_rate_pct": 0.0, "open_alerts": 0,
            "mean_latency_ms": 0, "p50_latency_ms": 0, "p95_latency_ms": 0,
            "rate_limited_24h": 0, "status": "OPERATIONAL",
        }


# =============================================================================
#  THREAT TIMELINE
# =============================================================================

@router.get("/threat-timeline")
async def get_threat_timeline(db: AsyncSession = Depends(get_db)):
    """Returns hourly breakdown for the last 24h for the timeline chart."""
    now = datetime.now(timezone.utc)
    hours = []
    for i in range(24, -1, -1):
        slot_start = now - timedelta(hours=i + 1)
        slot_end   = now - timedelta(hours=i)
        label_dt   = now - timedelta(hours=i)
        hours.append({
            "label": label_dt.strftime("%H:%M"),
            "ts_start": slot_start.isoformat(),
            "ts_end": slot_end.isoformat(),
        })

    result = []
    try:
        for slot in hours:
            ts_start = datetime.fromisoformat(slot["ts_start"])
            ts_end   = datetime.fromisoformat(slot["ts_end"])

            counts = await db.execute(
                select(
                    AuditLog.decision,
                    func.count(AuditLog.id).label("cnt")
                ).where(
                    and_(AuditLog.timestamp >= ts_start, AuditLog.timestamp < ts_end)
                ).group_by(AuditLog.decision)
            )
            rows = counts.all()
            d = {"label": slot["label"], "allowed": 0, "blocked": 0, "quarantined": 0, "threats": 0}
            for row in rows:
                if row.decision == "ALLOW":
                    d["allowed"] = row.cnt
                elif row.decision == "BLOCK":
                    d["blocked"] = row.cnt
                    d["threats"] += row.cnt
                elif row.decision == "QUARANTINE":
                    d["quarantined"] = row.cnt
                    d["threats"] += row.cnt
            result.append(d)
    except Exception as e:
        logger.error(f"Timeline query error: {e}")
        result = [{"label": h["label"], "allowed": 0, "blocked": 0, "quarantined": 0, "threats": 0} for h in hours]

    return {"timeline": result}


# =============================================================================
#  THREAT BREAKDOWN
# =============================================================================

@router.get("/threat-breakdown")
async def get_threat_breakdown(db: AsyncSession = Depends(get_db)):
    """Returns threat volume per detector category for the last 24h."""
    now = datetime.now(timezone.utc)
    window = now - timedelta(hours=24)
    try:
        rows = await db.execute(
            select(AuditLog.rule_triggered, func.count(AuditLog.id).label("cnt"))
            .where(and_(AuditLog.timestamp >= window, AuditLog.decision.in_(["BLOCK", "QUARANTINE"])))
            .group_by(AuditLog.rule_triggered)
            .order_by(desc("cnt"))
            .limit(10)
        )
        categories = []
        for row in rows.all():
            categories.append({"category": row.rule_triggered or "unknown", "count": row.cnt})
        return {"categories": categories}
    except Exception as e:
        logger.error(f"Breakdown query error: {e}")
        return {"categories": []}


# =============================================================================
#  TOP NOISY AGENTS
# =============================================================================

@router.get("/top-agents")
async def get_top_noisy_agents(db: AsyncSession = Depends(get_db)):
    """Returns agents with the most blocked/quarantined requests."""
    now = datetime.now(timezone.utc)
    window = now - timedelta(hours=24)
    try:
        rows = await db.execute(
            select(
                AuditLog.agent_name,
                func.count(AuditLog.id).filter(AuditLog.decision.in_(["BLOCK", "QUARANTINE"])).label("violations"),
                func.count(AuditLog.id).label("total"),
            )
            .where(AuditLog.timestamp >= window)
            .group_by(AuditLog.agent_name)
            .order_by(desc("violations"))
            .limit(10)
        )
        agents = []
        for row in rows.all():
            agents.append({
                "name": row.agent_name,
                "violations": row.violations,
                "total": row.total,
            })
        return {"agents": agents}
    except Exception as e:
        logger.error(f"Top agents query error: {e}")
        return {"agents": []}


# =============================================================================
#  POLICY EFFECTIVENESS
# =============================================================================

@router.get("/policy-effectiveness")
async def get_policy_effectiveness(db: AsyncSession = Depends(get_db)):
    """Returns hit count per active policy rule for the last 24h."""
    now = datetime.now(timezone.utc)
    window = now - timedelta(hours=24)
    try:
        rows = await db.execute(
            select(AuditLog.rule_triggered, func.count(AuditLog.id).label("hits"))
            .where(and_(AuditLog.timestamp >= window, AuditLog.rule_triggered.isnot(None)))
            .group_by(AuditLog.rule_triggered)
            .order_by(desc("hits"))
            .limit(15)
        )
        rules = []
        for row in rows.all():
            rules.append({"rule": row.rule_triggered, "hits": row.hits})
        return {"rules": rules}
    except Exception as e:
        logger.error(f"Policy effectiveness query error: {e}")
        return {"rules": []}


# =============================================================================
#  REQUEST STREAM
# =============================================================================

@router.get("/requests")
async def get_request_stream(
    decision: Optional[str] = Query(None),
    agent_name: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    """Returns paginated request stream for the Requests view."""
    try:
        q = select(AuditLog).order_by(desc(AuditLog.timestamp))
        if decision and decision != "all":
            q = q.where(AuditLog.decision == decision.upper())
        if agent_name and agent_name != "all":
            q = q.where(AuditLog.agent_name == agent_name)

        count_q = select(func.count()).select_from(q.subquery())
        total_result = await db.execute(count_q)
        total = total_result.scalar() or 0

        q = q.offset(offset).limit(limit)
        rows = await db.execute(q)
        entries = rows.scalars().all()

        items = []
        for e in entries:
            detector_scores = {}
            try:
                if e.detector_scores:
                    detector_scores = json.loads(e.detector_scores)
            except Exception:
                pass

            pii_types = []
            try:
                if e.pii_types:
                    pii_types = json.loads(e.pii_types)
            except Exception:
                pass

            # Determine AI classification label
            ai_class = "Safe"
            ai_subtype = "Benign"
            ai_score = 0
            if e.rule_triggered:
                if "injection" in (e.rule_triggered or "").lower() or e.triggered_detector_from_scores(detector_scores) == "injection":
                    ai_class = "Injection"
                    ai_subtype = "Prompt Injection"
                    ai_score = int(detector_scores.get("injection", 0) * 100)
                elif "pii" in (e.rule_triggered or "").lower():
                    ai_class = "Injection"
                    ai_subtype = "PII Attack"
                    ai_score = 99
                elif "toxic" in (e.rule_triggered or "").lower():
                    ai_class = "Injection"
                    ai_subtype = "Toxic Content"
                    ai_score = int(detector_scores.get("toxicity", 0.88) * 100)

            items.append({
                "id": str(e.id),
                "request_id": str(e.request_id),
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "agent_name": e.agent_name,
                "agent_role": e.agent_role,
                "prompt_preview": e.prompt_preview or "",
                "action": e.action,
                "decision": e.decision,
                "threat_score": e.threat_score or 0,
                "rule_triggered": e.rule_triggered,
                "pii_types": pii_types,
                "layer": e.layer,
                "reason": e.reason,
                "detector_scores": detector_scores,
                "ai_class": ai_class,
                "ai_subtype": ai_subtype,
                "ai_score": ai_score,
                "latency_ms": 59,
            })

        return {"items": items, "total": total, "limit": limit, "offset": offset}
    except Exception as e:
        logger.error(f"Request stream query error: {e}")
        return {"items": [], "total": 0, "limit": limit, "offset": offset}


# =============================================================================
#  ALERTS
# =============================================================================

@router.get("/alerts")
async def get_alerts(
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
):
    """Returns recent alerts derived from blocked/quarantined requests."""
    try:
        now = datetime.now(timezone.utc)
        window = now - timedelta(days=7)

        rows = await db.execute(
            select(AuditLog)
            .where(and_(
                AuditLog.timestamp >= window,
                AuditLog.decision.in_(["BLOCK", "QUARANTINE"])
            ))
            .order_by(desc(AuditLog.timestamp))
            .limit(limit)
        )
        entries = rows.scalars().all()

        alerts = []
        for e in entries:
            severity = "HIGH"
            if e.threat_score and e.threat_score > 0.9:
                severity = "CRITICAL"
            elif e.threat_score and e.threat_score < 0.6:
                severity = "MEDIUM"

            rule = e.rule_triggered or "unknown"
            title = _rule_to_alert_title(rule)

            alerts.append({
                "id": str(e.id),
                "title": title,
                "agent_name": e.agent_name,
                "severity": severity,
                "decision": e.decision,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "reason": e.reason,
                "rule_triggered": rule,
                "threat_score": e.threat_score or 0,
            })

        return {"alerts": alerts, "total": len(alerts)}
    except Exception as e:
        logger.error(f"Alerts query error: {e}")
        return {"alerts": [], "total": 0}


def _rule_to_alert_title(rule: str) -> str:
    mapping = {
        "block_ignore_instructions": "Prompt Injection On Agent",
        "block_delete_all": "Bulk Delete Attempt",
        "block_drop_table": "Schema Modification Attempt",
        "block_export_all": "Data Exfiltration Attempt",
        "injection": "Prompt Injection Detected",
        "pii": "PII In Payload",
        "toxicity": "Toxic Content Detected",
        "jailbreak": "Jailbreak Attempt",
        "smuggling": "Token Smuggling Detected",
        "block_bulk_export": "Bulk Export Blocked",
        "block_bulk_delete": "Bulk Delete Blocked",
    }
    return mapping.get(rule, f"Security Event: {rule.replace('_', ' ').title()}")


# =============================================================================
#  AGENTS CRUD
# =============================================================================

@router.get("/agents")
async def list_agents(db: AsyncSession = Depends(get_db)):
    """Returns all registered agents."""
    try:
        result = await db.execute(select(Agent).order_by(desc(Agent.created_at)))
        agents = result.scalars().all()
        return {
            "agents": [
                {
                    "id": str(a.id),
                    "name": a.name,
                    "description": a.description,
                    "role": a.role,
                    "status": a.status,
                    "rate_limit": a.rate_limit,
                    "policy_tier": a.policy_tier,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                    "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                }
                for a in agents
            ],
            "total": len(agents),
        }
    except Exception as e:
        logger.error(f"List agents error: {e}")
        return {"agents": [], "total": 0}


@router.post("/agents")
async def create_agent(body: CreateAgentRequest, db: AsyncSession = Depends(get_db)):
    """Creates a new agent and returns its API key (shown once)."""
    raw_key, hashed_key = generate_api_key()
    agent = Agent(
        id=uuid.uuid4(),
        name=body.name,
        description=body.description,
        api_key_hash=hashed_key,
        role=body.role,
        status="active",
        rate_limit=body.rate_limit,
        policy_tier=body.policy_tier,
    )
    db.add(agent)
    await db.flush()
    return {
        "agent": {
            "id": str(agent.id),
            "name": agent.name,
            "role": agent.role,
            "status": agent.status,
            "rate_limit": agent.rate_limit,
            "policy_tier": agent.policy_tier,
            "created_at": agent.created_at.isoformat() if agent.created_at else None,
        },
        "api_key": raw_key,
        "message": "Save this API key — it will not be shown again.",
    }


@router.patch("/agents/{agent_id}")
async def update_agent(
    agent_id: str,
    body: UpdateAgentRequest,
    db: AsyncSession = Depends(get_db),
):
    """Updates an agent's metadata or status."""
    result = await db.execute(select(Agent).where(Agent.id == uuid.UUID(agent_id)))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if body.name is not None:
        agent.name = body.name
    if body.description is not None:
        agent.description = body.description
    if body.status is not None:
        if body.status not in ("active", "suspended", "blocked"):
            raise HTTPException(status_code=400, detail="Invalid status")
        agent.status = body.status
    if body.rate_limit is not None:
        agent.rate_limit = body.rate_limit
    if body.policy_tier is not None:
        agent.policy_tier = body.policy_tier
    if body.role is not None:
        agent.role = body.role

    await db.flush()
    return {
        "id": str(agent.id),
        "name": agent.name,
        "status": agent.status,
        "role": agent.role,
        "rate_limit": agent.rate_limit,
        "policy_tier": agent.policy_tier,
    }


@router.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Soft-deletes an agent by blocking it."""
    result = await db.execute(select(Agent).where(Agent.id == uuid.UUID(agent_id)))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.status = "blocked"
    await db.flush()
    return {"message": f"Agent '{agent.name}' blocked successfully."}


@router.post("/agents/{agent_id}/rotate-key")
async def rotate_agent_key(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Rotates the API key for an agent."""
    result = await db.execute(select(Agent).where(Agent.id == uuid.UUID(agent_id)))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    raw_key, hashed_key = generate_api_key()
    agent.api_key_hash = hashed_key
    await db.flush()
    return {
        "api_key": raw_key,
        "message": "New API key generated. Save it — it will not be shown again.",
    }


# =============================================================================
#  POLICIES (in-memory read from YAML + DB overrides)
# =============================================================================

@router.get("/policies")
async def get_policies():
    """Returns the current policy rules loaded in memory."""
    try:
        from gateway.policy.engine import get_policy_rules
        rules = get_policy_rules()

        input_rules = [
            {
                "id": f"input_{i}",
                "name": r.get("name"),
                "rule_type": "input",
                "pattern": r.get("pattern"),
                "match": r.get("match", "contains"),
                "reason": r.get("reason", ""),
                "severity": r.get("severity", "medium"),
                "enabled": True,
                "hits_24h": 0,
            }
            for i, r in enumerate(rules.input_rules)
        ]
        action_rules = [
            {
                "id": f"action_{i}",
                "name": r.get("name"),
                "rule_type": "action",
                "pattern": r.get("pattern"),
                "match": r.get("match", "exact"),
                "reason": r.get("reason", ""),
                "severity": r.get("severity", "medium"),
                "enabled": True,
                "hits_24h": 0,
            }
            for i, r in enumerate(rules.action_rules)
        ]
        network_allow = [
            {
                "id": f"net_allow_{i}",
                "name": f"allow_{d.replace('.', '_')}",
                "rule_type": "network_allow",
                "pattern": d,
                "match": "exact",
                "reason": f"Allowed egress to {d}",
                "severity": "low",
                "enabled": True,
                "hits_24h": 0,
            }
            for i, d in enumerate(rules.allowed_domains)
        ]
        network_block = [
            {
                "id": f"net_block_{i}",
                "name": f"block_{d.replace('.', '_')}",
                "rule_type": "network_block",
                "pattern": d,
                "match": "exact",
                "reason": f"Blocked egress to {d}",
                "severity": "high",
                "enabled": True,
                "hits_24h": 0,
            }
            for i, d in enumerate(rules.blocked_domains)
        ]

        all_rules = input_rules + action_rules + network_allow + network_block
        return {"rules": all_rules, "total": len(all_rules)}
    except Exception as e:
        logger.error(f"Get policies error: {e}")
        return {"rules": [], "total": 0}


# =============================================================================
#  AUDIT LOG
# =============================================================================

@router.get("/audit")
async def get_audit_log(
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    decision: Optional[str] = Query(None),
    agent_name: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Returns paginated audit log entries."""
    try:
        q = select(AuditLog).order_by(desc(AuditLog.timestamp))
        if decision and decision != "all":
            q = q.where(AuditLog.decision == decision.upper())
        if agent_name and agent_name != "all":
            q = q.where(AuditLog.agent_name == agent_name)

        count_q = select(func.count()).select_from(q.subquery())
        total = (await db.execute(count_q)).scalar() or 0

        rows = await db.execute(q.offset(offset).limit(limit))
        entries = rows.scalars().all()

        items = []
        for e in entries:
            pii = []
            try:
                if e.pii_types:
                    pii = json.loads(e.pii_types)
            except Exception:
                pass
            scores = {}
            try:
                if e.detector_scores:
                    scores = json.loads(e.detector_scores)
            except Exception:
                pass

            items.append({
                "id": str(e.id),
                "request_id": str(e.request_id),
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "agent_id": str(e.agent_id) if e.agent_id else None,
                "agent_name": e.agent_name,
                "agent_role": e.agent_role,
                "action": e.action,
                "prompt_preview": e.prompt_preview or "",
                "decision": e.decision,
                "reason": e.reason,
                "threat_score": e.threat_score or 0,
                "layer": e.layer,
                "rule_triggered": e.rule_triggered,
                "pii_types": pii,
                "detector_scores": scores,
            })

        return {"items": items, "total": total, "limit": limit, "offset": offset}
    except Exception as e:
        logger.error(f"Audit log query error: {e}")
        return {"items": [], "total": 0, "limit": limit, "offset": offset}


# =============================================================================
#  AGENT NAMES (for filter dropdowns)
# =============================================================================

@router.get("/agent-names")
async def get_agent_names(db: AsyncSession = Depends(get_db)):
    """Returns distinct agent names for filter dropdowns."""
    try:
        rows = await db.execute(
            select(AuditLog.agent_name).distinct().order_by(AuditLog.agent_name)
        )
        names = [r[0] for r in rows.all() if r[0]]
        return {"names": names}
    except Exception as e:
        logger.error(f"Agent names error: {e}")
        return {"names": []}


# Patch AuditLog with helper method (monkey-patch for route helper)
def _triggered_detector_from_scores(self, scores: dict) -> str:
    if not scores:
        return ""
    max_k = max(scores, key=scores.get)
    return max_k if scores[max_k] > 0.5 else ""

AuditLog.triggered_detector_from_scores = _triggered_detector_from_scores
