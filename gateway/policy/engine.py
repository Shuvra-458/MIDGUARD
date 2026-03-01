# =============================================================================
#  MIDGUARD — gateway/policy/engine.py
#  Phase 2: Policy Engine
#
#  What this file does:
#    Loads the YAML policy rules and evaluates every incoming request
#    against three independent rule sets — in this exact order:
#
#      1. Input Rules   — is the prompt text safe?
#      2. Action Rules  — is the requested action allowed?
#      3. Network Rules — is the target URL on the approved list?
#
#    The first rule that matches triggers an immediate BLOCK.
#    If no rule matches, the request passes to Phase 3 (Threat Detection).
#
#  Why rule-based (not AI)?
#    - 100% deterministic — same input always produces same output
#    - 100% auditable — compliance officers can read the YAML file
#    - Zero false negatives on configured rules — if it's in the YAML, it's always caught
#    - Under 1ms evaluation time — no model loading, no inference
#    - Security teams can update rules without touching Python code
#
#  Performance:
#    Rules are loaded ONCE at startup and cached in memory.
#    Every request evaluation is pure Python string matching — <1ms.
# =============================================================================

import re
import logging
from pathlib import Path
from typing import Optional

import yaml

from gateway.models.schemas import PolicyResult

logger = logging.getLogger("midguard.policy.engine")


# =============================================================================
#  RULE LOADER
#  Reads policy_rules.yaml once at startup and caches it.
# =============================================================================

class PolicyRules:
    """
    Holds all loaded policy rules in memory.
    Loaded once at startup via load_policy_rules().
    Shared across all requests — read-only after loading.
    """
    def __init__(self):
        self.input_rules:    list[dict] = []
        self.action_rules:   list[dict] = []
        self.allowed_domains:list[str]  = []
        self.blocked_domains:list[str]  = []
        self.loaded:         bool       = False


# Module-level singleton — one instance for the whole application
_policy_rules = PolicyRules()


def load_policy_rules(rules_path: Optional[str] = None) -> PolicyRules:
    """
    Loads policy rules from the YAML file into memory.

    Called once during application startup (from main.py lifespan).
    All subsequent requests use the cached _policy_rules object.

    Args:
        rules_path: Path to policy_rules.yaml. Defaults to config/policy_rules.yaml

    Returns:
        PolicyRules object with all rules loaded
    """
    global _policy_rules

    if rules_path is None:
        # Default location relative to project root
        rules_path = Path(__file__).parent.parent.parent / "config" / "policy_rules.yaml"

    rules_path = Path(rules_path)

    if not rules_path.exists():
        logger.error(f"Policy rules file not found: {rules_path}")
        raise FileNotFoundError(f"Policy rules file not found: {rules_path}")

    with open(rules_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    _policy_rules.input_rules    = data.get("input_rules",  [])
    _policy_rules.action_rules   = data.get("action_rules", [])
    _policy_rules.allowed_domains = (
        data.get("network_rules", {}).get("allowed_domains", [])
    )
    _policy_rules.blocked_domains = (
        data.get("network_rules", {}).get("blocked_domains", [])
    )
    _policy_rules.loaded = True

    logger.info(
        f"Policy rules loaded: "
        f"{len(_policy_rules.input_rules)} input rules, "
        f"{len(_policy_rules.action_rules)} action rules, "
        f"{len(_policy_rules.allowed_domains)} allowed domains, "
        f"{len(_policy_rules.blocked_domains)} blocked domains"
    )

    return _policy_rules


def get_policy_rules() -> PolicyRules:
    """Returns the cached policy rules. Raises if not loaded yet."""
    if not _policy_rules.loaded:
        raise RuntimeError(
            "Policy rules not loaded. Call load_policy_rules() during startup."
        )
    return _policy_rules


# =============================================================================
#  PATTERN MATCHING
#  Evaluates a single rule against a given text value.
# =============================================================================

def _matches_rule(value: str, rule: dict) -> bool:
    """
    Checks if a value matches a single rule's pattern.

    Supports 5 match types:
      contains    — pattern appears anywhere in value (case-insensitive)
      exact       — value exactly equals pattern (case-insensitive)
      startswith  — value starts with pattern (case-insensitive)
      endswith    — value ends with pattern (case-insensitive)
      regex       — pattern is a regular expression

    Args:
        value: The text to check (prompt, action, or URL)
        rule:  A rule dict from the YAML file

    Returns:
        True if the value matches this rule's pattern
    """
    pattern    = rule.get("pattern", "").lower()
    match_type = rule.get("match", "contains").lower()
    text       = value.lower().strip()

    if match_type == "contains":
        return pattern in text

    elif match_type == "exact":
        return text == pattern

    elif match_type == "startswith":
        return text.startswith(pattern)

    elif match_type == "endswith":
        return text.endswith(pattern)

    elif match_type == "regex":
        try:
            return bool(re.search(pattern, text, re.IGNORECASE))
        except re.error as e:
            logger.error(f"Invalid regex pattern in policy rule '{rule.get('name')}': {e}")
            return False

    else:
        logger.warning(f"Unknown match type '{match_type}' in rule '{rule.get('name')}'")
        return False


# =============================================================================
#  MAIN POLICY EVALUATION FUNCTION
#  Called from gateway/main.py for every request that passes Phase 1.
# =============================================================================

async def run_policy_engine(
    prompt:     str,
    action:     str,
    target_url: Optional[str] = None,
    agent_tier: str           = "standard",
) -> PolicyResult:
    """
    Evaluates a request against all policy rules.

    Checks in this order:
      1. Input Rules   → checked against prompt text
      2. Action Rules  → checked against action field
      3. Network Rules → checked against target_url (if provided)

    Returns on the FIRST rule that matches (fail-fast evaluation).
    If no rules match, returns PolicyResult(blocked=False).

    Args:
        prompt:     The user's message text (body.prompt)
        action:     The requested action type (body.action)
        target_url: URL the agent wants to call (body.target_url, if any)
        agent_tier: The agent's policy tier ("standard", "strict", etc.)

    Returns:
        PolicyResult — blocked=True with reason if blocked, blocked=False if clear
    """
    rules = get_policy_rules()

    # ── STEP 1: Evaluate Input Rules ─────────────────────────────────────────
    for rule in rules.input_rules:
        if _matches_rule(prompt, rule):
            logger.warning(
                f"Policy BLOCK — input rule '{rule['name']}' triggered | "
                f"Prompt: '{prompt[:60]}...'"
            )
            return PolicyResult(
                blocked=True,
                reason=rule.get("reason", "Request blocked by input policy rule."),
                rule_triggered=rule.get("name"),
                layer="Policy Engine — Input Rules",
            )

    logger.debug(f"Policy input rules: all {len(rules.input_rules)} passed")

    # ── STEP 2: Evaluate Action Rules ────────────────────────────────────────
    for rule in rules.action_rules:
        if _matches_rule(action, rule):
            logger.warning(
                f"Policy BLOCK — action rule '{rule['name']}' triggered | "
                f"Action: '{action}'"
            )
            return PolicyResult(
                blocked=True,
                reason=rule.get("reason", "Request blocked by action policy rule."),
                rule_triggered=rule.get("name"),
                layer="Policy Engine — Action Rules",
            )

    logger.debug(f"Policy action rules: all {len(rules.action_rules)} passed")

    # ── STEP 3: Evaluate Network Rules ───────────────────────────────────────
    if target_url:
        network_result = _check_network_rules(target_url, rules)
        if network_result:
            return network_result

    # ── ALL RULES PASSED ─────────────────────────────────────────────────────
    logger.debug("Policy engine: request passed all rules")
    return PolicyResult(
        blocked=False,
        layer="Policy Engine",
    )


def _check_network_rules(url: str, rules: PolicyRules) -> Optional[PolicyResult]:
    """
    Checks a URL against the network allow/block lists.

    Logic:
      1. Check blocked_domains first — always blocked regardless of allowlist
      2. Check allowed_domains — if domain not in allowlist, block it
      3. If domain is in allowlist and not blocked → allow

    This is a DENY-BY-DEFAULT policy:
    Any domain NOT explicitly in allowed_domains is blocked.

    Args:
        url:   The URL string to check
        rules: The loaded PolicyRules object

    Returns:
        PolicyResult(blocked=True) if URL is blocked
        None if URL is allowed (caller treats None as "passed")
    """
    # Extract the domain from the URL
    # Handles: https://api.example.com/path → api.example.com
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remove port number if present: api.example.com:443 → api.example.com
        if ":" in domain:
            domain = domain.split(":")[0]
    except Exception:
        domain = url.lower()

    # Check explicitly blocked domains first
    for blocked in rules.blocked_domains:
        if domain == blocked.lower() or domain.endswith("." + blocked.lower()):
            logger.warning(f"Policy BLOCK — domain '{domain}' is on blocked list")
            return PolicyResult(
                blocked=True,
                reason=f"Domain '{domain}' is explicitly blocked by network policy.",
                rule_triggered="network_blocked_domain",
                layer="Policy Engine — Network Rules",
            )

    # Check if domain is on the allowlist
    domain_allowed = False
    for allowed in rules.allowed_domains:
        if domain == allowed.lower() or domain.endswith("." + allowed.lower()):
            domain_allowed = True
            break

    if not domain_allowed:
        logger.warning(
            f"Policy BLOCK — domain '{domain}' is not in allowed_domains list"
        )
        return PolicyResult(
            blocked=True,
            reason=f"Domain '{domain}' is not on the approved network access list.",
            rule_triggered="network_domain_not_allowed",
            layer="Policy Engine — Network Rules (Egress Filter)",
        )

    return None  # Domain is allowed — return None means "passed"