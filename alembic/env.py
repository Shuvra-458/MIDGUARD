# =============================================================================
#  MIDGUARD — alembic/env.py
#  Alembic migration configuration.
#  Tells Alembic where the database is and which models to track.
# =============================================================================

import sys
import os

# ── Ensure project root is on sys.path so 'gateway' and 'config' are importable ──
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import Connection

from alembic import context

# Import our models so Alembic can detect schema changes
from gateway.models.db_models import Base  # noqa: F401 — must import for detection
from gateway.models import db_models       # noqa: F401 — registers all models

from config.settings import settings

# Alembic Config object
config = context.config

# Set the database URL from our settings (reads from .env).
# Alembic needs the synchronous psycopg2 driver — swap asyncpg → psycopg2.
sync_url = settings.DATABASE_URL.replace("postgresql+asyncpg", "postgresql+psycopg2")
config.set_main_option("sqlalchemy.url", sync_url)

# Set up logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata — Alembic compares this against the live DB to generate migrations
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations without a live DB connection (generates SQL script)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against the live database (sync psycopg2)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        do_run_migrations(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()