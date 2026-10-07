"""Authentication test utilities for AI-GRC Platform test suites.

Provides helpers to provision real User models and generate valid Stage 13D.1
Bearer JWT tokens for test client HTTP requests without bypassing authorization.
"""

import os
import models
from auth.security import hash_password, create_access_token

TEST_DEFAULT_SECRET = "test-jwt-secret-key-at-least-32-chars-long-123456"


def ensure_jwt_secret():
    """Ensure JWT_SECRET_KEY is configured in the environment."""
    if not os.environ.get("JWT_SECRET_KEY"):
        os.environ["JWT_SECRET_KEY"] = TEST_DEFAULT_SECRET


def create_test_user(
    db,
    username: str = "test_admin",
    email: str | None = None,
    role: str = "Administrator",
    password: str = "TestSecretPassword123!",
    is_active: bool = True,
) -> models.User:
    """Create and persist a real test user with Argon2id password hash."""
    ensure_jwt_secret()
    existing = db.query(models.User).filter(models.User.username == username).first()
    if existing:
        return existing

    if not email:
        email = f"{username}@example.com"

    user = models.User(
        username=username,
        email=email,
        display_name=username.replace("_", " ").title(),
        password_hash=hash_password(password),
        role=role,
        is_active=is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_test_auth_headers(
    db,
    username: str = "test_admin",
    role: str = "Administrator",
    password: str = "TestSecretPassword123!",
) -> dict:
    """Generate real Authorization: Bearer <token> headers for a test user."""
    ensure_jwt_secret()
    user = create_test_user(db, username=username, role=role, password=password)
    token = create_access_token(
        subject=user.id,
        username=user.username,
        role=user.role,
    )
    return {"Authorization": f"Bearer {token}"}
