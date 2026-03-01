#!/usr/bin/env python3
# =============================================================================
#  MIDGUARD — scripts/create_agent.py
#  CLI tool to register a new AI agent and generate its API key.
#
#  Usage:
#    python scripts/create_agent.py
#    python scripts/create_agent.py --name "My Bot" --role admin
#    python scripts/create_agent.py --name "Finance Agent" --limit 100
#
#  What it does:
#    1. Generates a secure random API key (msk_v1_...)
#    2. Hashes it with HMAC-SHA256
#    3. Inserts the agent record into PostgreSQL (hash only, not raw key)
#    4. Prints the raw API key ONCE — copy it immediately, it is never shown again
#
#  Security note:
#    The raw API key is printed exactly once and never stored.
#    If you lose it, you must delete the agent and create a new one.
# =============================================================================

import asyncio
import argparse
import uuid
import sys
import os

# Add project root to Python path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from gateway.models.db_models import Agent
from gateway.auth.middleware import generate_api_key
from config.settings import settings


async def create_agent(
    name:        str,
    role:        str,
    rate_limit:  int,
    policy_tier: str,
    description: str,
) -> None:
    """
    Creates a new agent record in PostgreSQL and prints the API key.
    """

    # Connect to PostgreSQL
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    SessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with SessionLocal() as db:
        # Generate the key pair
        raw_key, hashed_key = generate_api_key()
        agent_id = uuid.uuid4()

        # Create the agent record
        agent = Agent(
            id=agent_id,
            name=name,
            description=description,
            api_key_hash=hashed_key,
            role=role,
            status="active",
            rate_limit=rate_limit,
            policy_tier=policy_tier,
        )

        db.add(agent)
        await db.commit()

    await engine.dispose()

    # ── Print results ──────────────────────────────────────────────────────────
    print()
    print("=" * 65)
    print("  ✓ MIDGUARD Agent Created Successfully")
    print("=" * 65)
    print(f"  Name        : {name}")
    print(f"  Agent ID    : {agent_id}")
    print(f"  Role        : {role}")
    print(f"  Rate Limit  : {rate_limit} req/min")
    print(f"  Policy Tier : {policy_tier}")
    print()
    print("  ┌─────────────────────────────────────────────────────────┐")
    print("  │  YOUR API KEY (shown once — copy it now):               │")
    print("  │                                                         │")
    print(f"  │  {raw_key}  │")
    print("  │                                                         │")
    print("  │  ⚠️  This key will NOT be shown again.                  │")
    print("  │     If lost, delete this agent and create a new one.    │")
    print("  └─────────────────────────────────────────────────────────┘")
    print()
    print("  Use in Postman:")
    print(f"  Header → X-API-Key: {raw_key}")
    print()
    print("  Use in curl:")
    print(f'  curl -X POST http://localhost:8000/v1/gateway \\')
    print(f'       -H "X-API-Key: {raw_key}" \\')
    print(f'       -H "Content-Type: application/json" \\')
    print(f'       -d \'{{"prompt": "Hello MIDGUARD", "action": "query"}}\'')
    print()
    print("=" * 65)


def main():
    parser = argparse.ArgumentParser(
        description="Register a new AI agent with MIDGUARD and generate its API key.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/create_agent.py
  python scripts/create_agent.py --name "Customer Service Bot" --role standard
  python scripts/create_agent.py --name "SOC Admin Console" --role admin --limit 200
  python scripts/create_agent.py --name "Finance Agent" --tier strict --limit 10
        """,
    )
    parser.add_argument(
        "--name",
        default="New MIDGUARD Agent",
        help="Human-readable name for this agent (default: 'New MIDGUARD Agent')",
    )
    parser.add_argument(
        "--role",
        choices=["standard", "admin"],
        default="standard",
        help="Agent role: 'standard' for regular agents, 'admin' for SOC Dashboard (default: standard)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=30,
        help="Max requests per minute (default: 30)",
    )
    parser.add_argument(
        "--tier",
        choices=["standard", "strict", "permissive"],
        default="standard",
        help="Policy ruleset tier (default: standard)",
    )
    parser.add_argument(
        "--description",
        default="",
        help="Optional description of what this agent does",
    )

    args = parser.parse_args()

    print(f"\nCreating agent '{args.name}'...")
    asyncio.run(
        create_agent(
            name=args.name,
            role=args.role,
            rate_limit=args.limit,
            policy_tier=args.tier,
            description=args.description,
        )
    )


if __name__ == "__main__":
    main()