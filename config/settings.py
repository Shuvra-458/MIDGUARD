# =============================================================================
#  MIDGUARD — config/settings.py
# =============================================================================

from pydantic_settings import BaseSettings
from typing import List
# Removed: import os (You don't need it, Pydantic handles .env files!)


class Settings(BaseSettings):
    """
    All MIDGUARD configuration in one place.
    Pydantic reads these from environment variables automatically.
    """

    # ── APP ───────────────────────────────────────────────────────────────
    ENVIRONMENT:  str = "development"
    PORT:         int = 8000

    # ── DATABASE ──────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://midguard:midguard123@localhost:5432/midguard_db"

    # ── REDIS ─────────────────────────────────────────────────────────────
    REDIS_URL:    str = "redis://localhost:6379/0"

    # ── SECURITY ──────────────────────────────────────────────────────────
    HMAC_SECRET_KEY: str = "dev-secret-change-this-in-production-use-openssl-rand-hex-32"

    # ── LLM PROVIDER (OpenRouter) ──────────────────────────────────────────
    # Pydantic automatically looks for these in your .env file!
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    OPENROUTER_MODEL: str = "z-ai/glm-4.5-air:free"          # Main chatbot model (Phase 5)
    SCANNER_MODEL: str = ""        # Fast model for DeBERTa fallback (Phase 3)
    LLM_TEMPERATURE: float = 0.7
    LLM_MAX_TOKENS: int = 2048     

    # ── RATE LIMITING ─────────────────────────────────────────────────────
    DEFAULT_RATE_LIMIT: int = 30    
    ADMIN_RATE_LIMIT:   int = 200   

    # ── THREAT DETECTION ──────────────────────────────────────────────────
    THREAT_BLOCK_THRESHOLD:     float = 0.70  
    THREAT_QUARANTINE_THRESHOLD:float = 0.45  

    # ── CORS ──────────────────────────────────────────────────────────────
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


settings = Settings()