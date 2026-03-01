"""Create agents and auth_events tables

Revision ID: 001
Revises:
Create Date: 2024-01-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Use raw SQL for everything so SQLAlchemy cannot intercept ENUM creation ─
    # This avoids the duplicate-type error that occurs when SQLAlchemy's
    # metadata-registered Enum objects fire CREATE TYPE during create_table.
    op.execute("""
        CREATE TYPE agent_role AS ENUM ('standard', 'admin')
    """)
    op.execute("""
        CREATE TYPE agent_status AS ENUM ('active', 'suspended', 'blocked')
    """)
    op.execute("""
        CREATE TYPE auth_event_type AS ENUM (
            'success', 'invalid_key', 'missing_key',
            'suspended_agent', 'blocked_agent'
        )
    """)

    op.execute("""
        CREATE TABLE agents (
            id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            name         VARCHAR(200) NOT NULL,
            description  TEXT,
            api_key_hash VARCHAR(64)  NOT NULL UNIQUE,
            role         agent_role   NOT NULL DEFAULT 'standard',
            status       agent_status NOT NULL DEFAULT 'active',
            rate_limit   INTEGER      NOT NULL DEFAULT 30,
            policy_tier  VARCHAR(50)  NOT NULL DEFAULT 'standard',
            created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            last_seen    TIMESTAMPTZ
        )
    """)
    op.execute("""
        CREATE UNIQUE INDEX ix_agents_api_key_hash ON agents (api_key_hash)
    """)

    op.execute("""
        CREATE TABLE auth_events (
            id         UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
            agent_id   UUID            REFERENCES agents(id) ON DELETE SET NULL,
            event_type auth_event_type NOT NULL,
            request_id UUID,
            timestamp  TIMESTAMPTZ     NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX ix_auth_events_agent_id       ON auth_events (agent_id)")
    op.execute("CREATE INDEX ix_auth_events_timestamp      ON auth_events (timestamp)")
    op.execute("CREATE INDEX ix_auth_events_type_timestamp ON auth_events (event_type, timestamp)")
    op.execute("CREATE INDEX ix_auth_events_agent_timestamp ON auth_events (agent_id, timestamp)")


def downgrade() -> None:
    op.execute('DROP TABLE IF EXISTS auth_events')
    op.execute('DROP TABLE IF EXISTS agents')
    op.execute('DROP TYPE IF EXISTS auth_event_type')
    op.execute('DROP TYPE IF EXISTS agent_status')
    op.execute('DROP TYPE IF EXISTS agent_role')