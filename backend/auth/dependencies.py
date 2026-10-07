import logging
from typing import Generator
from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
import jwt

try:
    from database import SessionLocal
    import models
except ImportError:
    from backend.database import SessionLocal
    import backend.models as models

from .security import decode_access_token

logger = logging.getLogger("ai_grc.auth")


def get_db() -> Generator[Session, None, None]:
    """Provides a database session dependency for FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> models.User:
    """
    FastAPI dependency to extract and validate the Bearer JWT token.
    Validates signature, expiration, required claims, user existence, and active status.
    Returns the authenticated User model instance.
    Raises HTTP 401 on missing or invalid authentication.
    """
    auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]

    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as exc:
        logger.error(f"Authentication token validation error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload.get("username")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_roles(*allowed_roles: str):
    """
    Dependency factory returning a callable dependency that validates the authenticated
    user possesses one of the allowed roles.

    Hierarchy & Behavior:
    - If unauthenticated, expired, or invalid token -> HTTP 401 Unauthorized (via get_current_user)
    - If user account is inactive -> HTTP 401 Unauthorized (via get_current_user)
    - If user role is not in allowed_roles -> HTTP 403 Forbidden
    - If user role matches -> returns authenticated models.User instance
    """
    def role_checker(current_user: models.User = Depends(get_current_user)) -> models.User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted: insufficient privileges",
            )
        return current_user

    return role_checker


# Canonical hierarchical RBAC role dependencies
require_analyst = require_roles("Security Analyst", "GRC Reviewer", "Administrator")
require_reviewer = require_roles("GRC Reviewer", "Administrator")
require_admin = require_roles("Administrator")
