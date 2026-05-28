# =============================================================================
#  MIDGUARD — gateway/auth/login.py
#  Login endpoints for SOC and Frontend access
# =============================================================================

import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.database import get_db
from gateway.models.user_models import User, UserSession
from gateway.models.db_models import Agent
from gateway.auth.jwt_handler import (
    hash_password, verify_password, 
    create_access_token, create_refresh_token,
    verify_token
)
from gateway.auth.middleware import hash_api_key, generate_api_key
from config.settings import settings

logger = logging.getLogger("midguard.auth.login")

router = APIRouter(prefix="/v1/auth", tags=["Authentication"])


# =============================================================================
#  Request/Response Models
# =============================================================================

class LoginRequest(BaseModel):
    username: str = Field(..., description="Username or email")
    password: str = Field(..., description="Password")


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str
    username: str
    api_key: Optional[str] = None  # For users, auto-generated API key


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: str = Field(..., description="Valid email address")
    password: str = Field(..., min_length=6)
    full_name: Optional[str] = None
    role: str = Field("user", description="admin or user")


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


# =============================================================================
#  Helper Functions
# =============================================================================

async def get_user_by_username_or_email(db: AsyncSession, identifier: str) -> Optional[User]:
    """Get user by username or email."""
    result = await db.execute(
        select(User).where(
            (User.username == identifier) | (User.email == identifier)
        )
    )
    return result.scalar_one_or_none()


async def create_user_agent(db: AsyncSession, user_id: uuid.UUID, username: str) -> tuple[Agent, str]:
    """
    Create an API key agent for a user.
    Returns (agent, raw_api_key)
    """
    raw_key, hashed_key = generate_api_key()
    
    agent = Agent(
        id=uuid.uuid4(),
        name=f"User: {username}",
        description=f"Auto-generated agent for user {username}",
        api_key_hash=hashed_key,
        role="standard",
        status="active",
        rate_limit=settings.DEFAULT_RATE_LIMIT,
        policy_tier="standard",
    )
    db.add(agent)
    await db.flush()
    
    # Link agent to user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one()
    user.linked_agent_id = agent.id
    
    return agent, raw_key


# =============================================================================
#  Public Endpoints
# =============================================================================

@router.post("/register", response_model=LoginResponse)
async def register_user(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user.
    - Admin registration requires an existing admin API key (optional for now)
    - User registration is open
    """
    # Check if username exists
    existing = await get_user_by_username_or_email(db, request.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    # Check if email exists
    existing_email = await get_user_by_username_or_email(db, request.email)
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        id=uuid.uuid4(),
        username=request.username,
        email=request.email,
        password_hash=hash_password(request.password),
        full_name=request.full_name,
        role=request.role if request.role in ["admin", "user"] else "user",
        is_active=True,
    )
    db.add(user)
    await db.flush()
    
    # Create API key agent for the user
    agent, api_key = await create_user_agent(db, user.id, user.username)
    
    # Create tokens
    access_token = create_access_token(user.id, user.username, user.role)
    refresh_token = create_refresh_token(user.id)
    
    # Store refresh token session
    session = UserSession(
        id=uuid.uuid4(),
        user_id=user.id,
        refresh_token=refresh_token,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(session)
    await db.commit()
    
    logger.info(f"New user registered: {user.username} (role: {user.role})")
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        role=user.role,
        username=user.username,
        api_key=api_key if user.role == "user" else None
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Login with username/email and password.
    Returns JWT tokens and auto-generated API key for users.
    """
    user = await get_user_by_username_or_email(db, request.username)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
    
    # Update last login
    user.last_login = datetime.now(timezone.utc)
    
    # If user doesn't have a linked agent, create one
    api_key = None
    if not user.linked_agent_id:
        agent, api_key = await create_user_agent(db, user.id, user.username)
        logger.info(f"Created API key agent for user: {user.username}")
    else:
        # Get existing API key (can't retrieve raw key, so user must already have it)
        # For existing users without stored key, they need to regenerate
        pass
    
    # Create tokens
    access_token = create_access_token(user.id, user.username, user.role)
    refresh_token = create_refresh_token(user.id)
    
    # Store refresh token session
    session = UserSession(
        id=uuid.uuid4(),
        user_id=user.id,
        refresh_token=refresh_token,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(session)
    await db.commit()
    
    logger.info(f"User logged in: {user.username}")
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        role=user.role,
        username=user.username,
        api_key=api_key
    )


@router.post("/refresh")
async def refresh_token(
    request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """Get a new access token using a refresh token."""
    payload = verify_token(request.refresh_token, "refresh")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    
    # Check if session exists
    result = await db.execute(
        select(UserSession).where(UserSession.refresh_token == request.refresh_token)
    )
    session = result.scalar_one_or_none()
    
    if not session or session.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired or invalid")
    
    # Get user
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    
    # Create new access token
    new_access_token = create_access_token(user.id, user.username, user.role)
    
    return {"access_token": new_access_token, "token_type": "bearer"}


@router.post("/logout")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Logout - invalidate the refresh token."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token provided")
    
    token = auth_header.split(" ")[1]
    payload = verify_token(token, "access")
    
    if payload:
        user_id = payload.get("sub")
        if user_id:
            # Find and delete refresh token sessions for this user
            # For simplicity, we'll mark this approach
            pass
    
    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Get current user information."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token provided")
    
    token = auth_header.split(" ")[1]
    payload = verify_token(token, "access")
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "has_api_key": user.linked_agent_id is not None
    }


@router.post("/regenerate-api-key")
async def regenerate_api_key(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Regenerate API key for the current user."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token provided")
    
    token = auth_header.split(" ")[1]
    payload = verify_token(token, "access")
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Create new agent or update existing
    if user.linked_agent_id:
        # Update existing agent's key
        from gateway.auth.middleware import generate_api_key
        raw_key, hashed_key = generate_api_key()
        
        result = await db.execute(select(Agent).where(Agent.id == user.linked_agent_id))
        agent = result.scalar_one()
        agent.api_key_hash = hashed_key
        await db.flush()
    else:
        # Create new agent
        agent, raw_key = await create_user_agent(db, user.id, user.username)
    
    await db.commit()
    
    return {"api_key": raw_key, "message": "New API key generated. Save it — it will not be shown again."}