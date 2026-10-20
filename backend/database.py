from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os
from dotenv import load_dotenv

backend_env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.isfile(backend_env_path):
    load_dotenv(dotenv_path=backend_env_path)
else:
    load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is not set. "
        "Create a backend/.env file with your PostgreSQL connection string."
    )


def resolve_database_url(url: str) -> str:
    """Normalize and resolve database URLs to ensure compatibility between

    modern Psycopg 3 (psycopg) and legacy/local development (psycopg2).

    1. Normalizes legacy 'postgres://' to 'postgresql://'.
    2. Preserves explicit dialect qualifiers (e.g. 'postgresql+psycopg://',
       'postgresql+psycopg2://', 'sqlite://') unchanged.
    3. For generic 'postgresql://' URLs:
       - Prefers 'psycopg' (Psycopg 3) if installed.
       - Falls back to 'psycopg2' if only psycopg2 is installed, preserving
         local development compatibility without requiring environment changes.
    """
    if not url:
        return url

    # Normalize deprecated postgres:// prefix
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]

    # If the URL is not a generic postgresql:// URL (e.g. already has a driver
    # specified like postgresql+psycopg:// or postgresql+psycopg2://, or is sqlite://),
    # preserve it as-is.
    if not url.startswith("postgresql://"):
        return url

    # Probe for Psycopg 3 (psycopg) first (modern default for SQLAlchemy 2.1+)
    try:
        import psycopg  # noqa: F401
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    except ImportError:
        pass

    # Fall back to Psycopg 2 (psycopg2) if available (preserves local dev compatibility)
    try:
        import psycopg2  # noqa: F401
        return "postgresql+psycopg2://" + url[len("postgresql://"):]
    except ImportError:
        pass

    return url


engine = create_engine(resolve_database_url(DATABASE_URL))

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()
