# =============================================================================
#  MIDGUARD — gateway/database.py
#  PostgreSQL connection using SQLAlchemy async engine.
# =============================================================================

import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from config.settings import settings

logger = logging.getLogger("midguard.database")

# The async engine — one per application, shared across all requests
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.ENVIRONMENT == "development",  # Log SQL in dev only
    pool_size=10,
    max_overflow=20,
)

# Session factory — creates individual database sessions per request
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


async def init_db():
    """Called on startup — verifies database connection."""
    async with engine.connect() as conn:
        await conn.execute(__import__('sqlalchemy').text("SELECT 1"))
    logger.info("Database connection verified.")


async def close_db():
    """Called on shutdown — closes connection pool."""
    await engine.dispose()
    logger.info("Database connections closed.")


async def get_db():
    """
    FastAPI dependency — provides a database session per request.
    Automatically closes the session when the request finishes.

    Usage in endpoints:
        async def my_endpoint(db = Depends(get_db)):
            result = await db.execute(...)
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise