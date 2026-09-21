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

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()