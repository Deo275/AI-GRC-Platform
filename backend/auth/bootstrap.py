import os
import logging
from sqlalchemy.orm import Session

try:
    from database import SessionLocal
    import models
except ImportError:
    from backend.database import SessionLocal
    import backend.models as models

from .security import hash_password

logger = logging.getLogger("ai_grc.auth.bootstrap")

DEMO_USERS_CONFIG = [
    {
        "username": "analyst",
        "email": "analyst@example.com",
        "display_name": "Security Analyst",
        "role": "Security Analyst",
        "env_var": "AUTH_BOOTSTRAP_ANALYST_PASSWORD",
    },
    {
        "username": "reviewer",
        "email": "reviewer@example.com",
        "display_name": "GRC Reviewer",
        "role": "GRC Reviewer",
        "env_var": "AUTH_BOOTSTRAP_REVIEWER_PASSWORD",
    },
    {
        "username": "admin",
        "email": "admin@example.com",
        "display_name": "Administrator",
        "role": "Administrator",
        "env_var": "AUTH_BOOTSTRAP_ADMIN_PASSWORD",
    },
]


def run_dev_bootstrap(db: Session | None = None) -> int:
    """
    Opt-in development bootstrap for creating demo accounts.
    Default behavior is disabled unless AUTH_BOOTSTRAP_ENABLED=true.
    Passwords must be supplied via environment variables.
    Never overwrites existing users.
    Returns the number of created users.
    """
    enabled_val = os.environ.get("AUTH_BOOTSTRAP_ENABLED", "false").strip().lower()
    if enabled_val not in ("true", "1"):
        logger.debug("Development auth bootstrap is disabled (AUTH_BOOTSTRAP_ENABLED=false).")
        return 0

    env_name = os.environ.get("ENV", os.environ.get("ENVIRONMENT", "development")).strip().lower()
    if env_name in ("production", "prod"):
        raise RuntimeError("AUTH_BOOTSTRAP_ENABLED is not allowed in production environments.")

    # Check that all passwords are provided
    passwords = {}
    missing = []
    for cfg in DEMO_USERS_CONFIG:
        pw = os.environ.get(cfg["env_var"], "").strip()
        if not pw:
            missing.append(cfg["env_var"])
        passwords[cfg["username"]] = pw

    if missing:
        raise RuntimeError(
            f"AUTH_BOOTSTRAP_ENABLED is true, but required environment password variables are missing or empty: "
            f"{', '.join(missing)}. Refusing to create insecure demo accounts."
        )

    should_close = False
    if db is None:
        db = SessionLocal()
        should_close = True

    created_count = 0
    try:
        for cfg in DEMO_USERS_CONFIG:
            username = cfg["username"]
            existing = db.query(models.User).filter(models.User.username == username).first()
            if existing:
                logger.info(f"Bootstrap: user '{username}' already exists. Skipping.")
                continue

            pw = passwords[username]
            user = models.User(
                username=username,
                email=cfg["email"],
                display_name=cfg["display_name"],
                password_hash=hash_password(pw),
                role=cfg["role"],
                is_active=True,
            )
            db.add(user)
            db.commit()
            created_count += 1
            logger.info(f"Bootstrap: successfully created user '{username}' (role: {cfg['role']}).")

        return created_count
    finally:
        if should_close:
            db.close()
