"""Initial Administrator Provisioning Script for AI-GRC Platform.

Provides a secure, one-time interactive CLI mechanism to create the initial
Administrator account when no administrator exists.

Security & Operational Guarantees:
1. Prompts for credentials interactively with silent getpass for passwords.
2. Enforces minimum 12-character passwords and matching confirmation.
3. Assigns role exactly 'Administrator' and sets is_active=True.
4. Refuses execution if an Administrator account already exists.
5. Enforces model limits (username <= 50, email <= 255, display_name <= 100).
6. Uses Argon2id password hashing via backend.auth.security.hash_password.
7. Wraps creation in a database transaction with rollback on failure.
8. Handles concurrency/race conditions safely without leaking sensitive data.
"""

import sys
import getpass
from pathlib import Path

# Setup sys.path to resolve imports in local dev, scripts dir, or inside Docker container
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

try:
    from database import SessionLocal
    import models
    from auth.security import hash_password
except ImportError:
    from backend.database import SessionLocal
    import backend.models as models
    from backend.auth.security import hash_password

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


MIN_PASSWORD_LENGTH = 12
MAX_USERNAME_LENGTH = 50
MAX_EMAIL_LENGTH = 255
MAX_DISPLAY_NAME_LENGTH = 100


def validate_admin_inputs(
    username: str,
    email: str,
    display_name: str,
    password: str,
    password_confirm: str,
) -> tuple[bool, str | None]:
    """Validates required input fields and enforces constraints.

    Returns:
        (is_valid, error_message)
    """
    # Username validation
    if not username or not username.strip():
        return False, "Username is required."
    username = username.strip()
    if len(username) > MAX_USERNAME_LENGTH:
        return False, f"Username cannot exceed {MAX_USERNAME_LENGTH} characters."
    if any(c.isspace() for c in username):
        return False, "Username must not contain whitespace."

    # Email validation
    if not email or not email.strip():
        return False, "Email is required."
    email = email.strip()
    if len(email) > MAX_EMAIL_LENGTH:
        return False, f"Email cannot exceed {MAX_EMAIL_LENGTH} characters."
    if "@" not in email or email.startswith("@") or email.endswith("@") or " " in email:
        return False, "Invalid email address format."

    # Display name validation
    if not display_name or not display_name.strip():
        return False, "Display name is required."
    display_name = display_name.strip()
    if len(display_name) > MAX_DISPLAY_NAME_LENGTH:
        return False, f"Display name cannot exceed {MAX_DISPLAY_NAME_LENGTH} characters."

    # Password validation
    if not password:
        return False, "Password is required."
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if password != password_confirm:
        return False, "Passwords do not match."

    return True, None


def provision_initial_admin(
    db: Session,
    username: str,
    email: str,
    display_name: str,
    password: str,
) -> tuple[bool, str]:
    """Provisions the initial Administrator account.

    Guarantees:
    - Refuses to overwrite if an Administrator already exists.
    - Rejects duplicate username or email.
    - Hashes password using Argon2id.
    - Transactional commit with rollback on IntegrityError or other failures.
    - Never prints or returns plaintext passwords or password hashes.

    Returns:
        (success, message)
    """
    username = username.strip()
    email = email.strip().lower()
    display_name = display_name.strip()

    # 1. Guard: Check if an Administrator already exists
    existing_admin = db.query(models.User).filter(models.User.role == "Administrator").first()
    if existing_admin:
        return (
            False,
            f"Refusing to provision: An Administrator account already exists (username: '{existing_admin.username}').",
        )

    # 2. Guard: Check if username is already taken
    if db.query(models.User).filter(models.User.username == username).first():
        return False, f"Username '{username}' is already in use."

    # 3. Guard: Check if email is already taken
    if db.query(models.User).filter(models.User.email == email).first():
        return False, f"Email '{email}' is already in use."

    # 4. Create and commit in transaction
    try:
        user = models.User(
            username=username,
            email=email,
            display_name=display_name,
            password_hash=hash_password(password),
            role="Administrator",
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return True, f"Successfully provisioned Administrator '{user.username}' ({user.email})."
    except IntegrityError:
        db.rollback()
        return (
            False,
            "Database integrity constraint violated: An account with this username or email already exists.",
        )
    except Exception as exc:
        db.rollback()
        return False, f"Failed to provision administrator due to database error: {type(exc).__name__}."


def main() -> int:
    """CLI entrypoint for interactive administrator provisioning."""
    print("=" * 65)
    print(" AI-GRC Platform: Initial Administrator Provisioning")
    print("=" * 65)

    db: Session = SessionLocal()
    try:
        # Pre-check before prompting for input
        existing_admin = db.query(models.User).filter(models.User.role == "Administrator").first()
        if existing_admin:
            print(
                f"[-] Refusing to provision: An Administrator account ('{existing_admin.username}') already exists."
            )
            return 1

        # Interactive prompts
        try:
            username = input("Enter admin username [default: admin]: ").strip() or "admin"
            email = input(f"Enter admin email [default: {username}@example.com]: ").strip() or f"{username}@example.com"
            display_name = input("Enter display name [default: System Administrator]: ").strip() or "System Administrator"
            password = getpass.getpass("Enter administrator password (min 12 chars): ")
            password_confirm = getpass.getpass("Confirm administrator password: ")
        except (KeyboardInterrupt, EOFError):
            print("\n[-] Provisioning cancelled by user.")
            return 1

        # Validation
        is_valid, error_msg = validate_admin_inputs(
            username=username,
            email=email,
            display_name=display_name,
            password=password,
            password_confirm=password_confirm,
        )
        if not is_valid:
            print(f"[-] Validation error: {error_msg}")
            return 1

        # Provision
        success, message = provision_initial_admin(
            db=db,
            username=username,
            email=email,
            display_name=display_name,
            password=password,
        )

        if success:
            print(f"[+] {message}")
            return 0
        else:
            print(f"[-] {message}")
            return 1

    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
