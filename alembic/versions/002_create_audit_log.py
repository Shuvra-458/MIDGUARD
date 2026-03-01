"""Create audit_log table

Revision ID: 002
Revises: 001
Create Date: 2024-01-01 01:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision      = '002'
down_revision = '001'
branch_labels = None
depends_on    = None


def upgrade() -> None:
    # ── Create ENUM type + audit_log table via raw SQL ────────────────────────
    # Using raw SQL bypasses SQLAlchemy's sa.Enum auto-creation behavior,
    # which was triggering a duplicate CREATE TYPE within the same transaction.
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE enforcement_decision AS ENUM ('ALLOW', 'BLOCK', 'QUARANTINE');
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """)

    op.execute("""
        CREATE TABLE audit_log (
            id              UUID PRIMARY KEY,
            request_id      UUID NOT NULL,
            agent_id        UUID REFERENCES agents(id) ON DELETE SET NULL,
            agent_name      VARCHAR(200) NOT NULL,
            agent_role      VARCHAR(50)  NOT NULL,
            prompt_preview  TEXT,
            action          VARCHAR(100) NOT NULL,
            decision        enforcement_decision NOT NULL,
            reason          TEXT,
            threat_score    INTEGER,
            layer           VARCHAR(200),
            rule_triggered  VARCHAR(200),
            pii_types       TEXT,
            detector_scores TEXT,
            timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # ── Indexes ───────────────────────────────────────────────────────────────
    op.create_index('ix_audit_log_request_id',           'audit_log', ['request_id'])
    op.create_index('ix_audit_log_agent_id',             'audit_log', ['agent_id'])
    op.create_index('ix_audit_log_timestamp',            'audit_log', ['timestamp'])
    op.create_index('ix_audit_log_decision',             'audit_log', ['decision'])
    op.create_index('ix_audit_log_decision_timestamp',   'audit_log', ['decision', 'timestamp'])
    op.create_index('ix_audit_log_agent_timestamp',      'audit_log', ['agent_id',  'timestamp'])


def downgrade() -> None:
    op.drop_table('audit_log')
    op.execute('DROP TYPE IF EXISTS enforcement_decision')