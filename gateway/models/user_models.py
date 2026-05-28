# =============================================================================
#  MIDGUARD — gateway/models/user_models.py
#  User authentication tables for SOC and Frontend access
# =============================================================================

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Boolean, DateTime, Enum, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from gateway.database import Base


class User(Base):
    """
    Users who can log into the SOC Dashboard or Frontend.
    
    Two roles:
        - admin: Full access to SOC Dashboard (soc.html)
        - user: Limited access to frontend (index.html) with auto-generated API key
    """
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(Enum("admin", "user", name="user_role"), nullable=False, default="user")
    is_active = Column(Boolean, default=True)
    
    # For users: auto-generated API key linked to an Agent
    linked_agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True)
    
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    linked_agent = relationship("Agent", foreign_keys=[linked_agent_id])
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User username='{self.username}' role={self.role}>"


class UserSession(Base):
    """
    User sessions for refresh tokens and logout tracking.
    """
    __tablename__ = "user_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    refresh_token = Column(String(500), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="sessions")


# Add to Agent model - add this relationship to existing Agent class
# In gateway/models/db_models.py, add:
#   linked_user = relationship("User", foreign_keys="User.linked_agent_id", back_populates="linked_agent")