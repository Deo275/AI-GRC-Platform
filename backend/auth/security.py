import os
import datetime
from typing import Optional, Dict, Any
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
import jwt

# Standard Argon2id configuration:
# time_cost=3, memory_cost=65536 KiB (64 MiB), parallelism=4, hash_len=32, salt_len=16
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id."""
    if not password or not isinstance(password, str):
        raise ValueError("Password must be a non-empty string")
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against an Argon2id hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def get_jwt_secret_key() -> str:
    """
    Retrieves the JWT secret key from the environment.
    Fails safely if missing when authentication operations are performed.
    """
    secret = os.environ.get("JWT_SECRET_KEY", "").strip()
    if not secret:
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable is not configured. "
            "Authentication operations require a valid JWT_SECRET_KEY."
        )
    return secret


def create_access_token(
    subject: str | int,
    username: str,
    role: str,
    expires_delta: Optional[datetime.timedelta] = None,
) -> str:
    """
    Creates a signed HS256 JWT access token using PyJWT.
    Claims include sub, username, role, iat, exp.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    expire = now + (
        expires_delta
        if expires_delta is not None
        else datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload: Dict[str, Any] = {
        "sub": str(subject),
        "username": username,
        "role": role,
        "iat": now,
        "exp": expire,
    }
    secret = get_jwt_secret_key()
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates a JWT access token using PyJWT.
    Validates signature, expiration, and required claims.
    """
    secret = get_jwt_secret_key()
    return jwt.decode(
        token,
        secret,
        algorithms=[JWT_ALGORITHM],
        options={"require": ["sub", "username", "role", "exp", "iat"]},
    )
