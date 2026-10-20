"""Stage 14B Runtime Health & Deployment Tests.

Verifies:
1. GET /health/live returns HTTP 200 without requiring database or authentication.
2. GET /health/ready returns HTTP 200 when database is healthy.
3. GET /health/ready returns HTTP 503 and safe generic detail when database is unavailable.
4. Health probes never leak sensitive connection details, credentials, or tracebacks.
5. JWT_SECRET_KEY safe failure semantics (missing, empty, and known placeholder values).
6. Production startup verification enforces secret requirements.
7. Database driver resolution and requirements.txt dependency verification.
"""

import os
import sys
import unittest
from unittest import mock
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.exc import OperationalError
from fastapi.testclient import TestClient

# Setup sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import models
import main
from auth.security import get_jwt_secret_key, INSECURE_PLACEHOLDER_SECRETS

TEST_SECRET = "stage-14b-test-jwt-secret-key-at-least-32-chars-long"


class TestStage14BHealthAndDeployment(unittest.TestCase):
    """Test suite for Stage 14B health endpoints and configuration security."""

    def setUp(self):
        self.env_patcher = mock.patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET})
        self.env_patcher.start()

        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        models.Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

        self.session_patcher = mock.patch("main.SessionLocal", side_effect=lambda: self.SessionLocal())
        self.session_patcher.start()

        self.client = TestClient(main.app)

    def tearDown(self):
        self.session_patcher.stop()
        models.Base.metadata.drop_all(bind=self.engine)
        self.env_patcher.stop()

    # -------------------------------------------------------------------------
    # 1. Health Liveness Probe (/health/live)
    # -------------------------------------------------------------------------

    def test_01_health_live_returns_200(self):
        """GET /health/live reports healthy process status with HTTP 200."""
        response = self.client.get("/health/live")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "healthy"})

    def test_02_health_live_does_not_require_database(self):
        """GET /health/live succeeds even if database SessionLocal raises an error."""
        with mock.patch("main.SessionLocal", side_effect=Exception("Database down")):
            response = self.client.get("/health/live")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"status": "healthy"})

    def test_03_health_live_does_not_require_authentication(self):
        """GET /health/live is a public probe that never requires Authorization header."""
        # Test without any auth headers
        response = self.client.get("/health/live")
        self.assertEqual(response.status_code, 200)

    # -------------------------------------------------------------------------
    # 2. Health Readiness Probe (/health/ready)
    # -------------------------------------------------------------------------

    def test_04_health_ready_returns_200_when_database_connected(self):
        """GET /health/ready returns HTTP 200 and ready status when database responds."""
        response = self.client.get("/health/ready")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("status"), "ready")
        self.assertEqual(data.get("database"), "connected")

    def test_05_health_ready_returns_503_when_database_unavailable(self):
        """GET /health/ready returns HTTP 503 when the database check raises an error."""
        with mock.patch("main.SessionLocal", side_effect=OperationalError("connection refused", {}, None)):
            response = self.client.get("/health/ready")
            self.assertEqual(response.status_code, 503)
            data = response.json()
            self.assertEqual(data.get("detail"), "Database unavailable")

    def test_06_health_ready_does_not_leak_sensitive_details(self):
        """GET /health/ready error response contains no connection strings, tracebacks, or secrets."""
        with mock.patch("main.SessionLocal", side_effect=OperationalError(
            "FATAL: password authentication failed for user 'postgres' at postgresql://postgres:secret123@db:5432/ai_grc",
            {},
            None,
        )):
            response = self.client.get("/health/ready")
            self.assertEqual(response.status_code, 503)
            content = response.text
            self.assertNotIn("secret123", content)
            self.assertNotIn("postgresql://", content)
            self.assertNotIn("FATAL", content)
            self.assertNotIn("postgres", content)
            self.assertEqual(response.json(), {"detail": "Database unavailable"})

    def test_07_health_ready_does_not_require_authentication(self):
        """GET /health/ready is accessible without Authorization headers for container orchestrators."""
        response = self.client.get("/health/ready")
        self.assertEqual(response.status_code, 200)

    # -------------------------------------------------------------------------
    # 3. Authentication Configuration & Secret Validation
    # -------------------------------------------------------------------------

    def test_08_get_jwt_secret_key_fails_safely_when_missing(self):
        """get_jwt_secret_key raises RuntimeError when JWT_SECRET_KEY is absent or empty."""
        with mock.patch.dict(os.environ, {"JWT_SECRET_KEY": ""}, clear=False):
            with self.assertRaises(RuntimeError) as ctx:
                get_jwt_secret_key()
            self.assertIn("JWT_SECRET_KEY", str(ctx.exception))

    def test_09_get_jwt_secret_key_rejects_insecure_placeholders(self):
        """get_jwt_secret_key rejects known tracked placeholder values."""
        for placeholder in INSECURE_PLACEHOLDER_SECRETS:
            with mock.patch.dict(os.environ, {"JWT_SECRET_KEY": placeholder}, clear=False):
                with self.assertRaises(RuntimeError) as ctx:
                    get_jwt_secret_key()
                self.assertIn("insecure placeholder", str(ctx.exception).lower())

    def test_10_production_startup_fails_safely_if_secret_missing(self):
        """main.on_startup() in production mode raises RuntimeError if JWT_SECRET_KEY is absent."""
        with mock.patch.dict(os.environ, {"ENV": "production", "JWT_SECRET_KEY": ""}, clear=False):
            with self.assertRaises(RuntimeError):
                main.on_startup()

    def test_11_production_startup_fails_safely_if_secret_placeholder(self):
        """main.on_startup() in production mode raises RuntimeError if JWT_SECRET_KEY is placeholder."""
        with mock.patch.dict(os.environ, {
            "ENV": "production",
            "JWT_SECRET_KEY": "replace-with-a-long-random-secret",
        }, clear=False):
            with self.assertRaises(RuntimeError):
                main.on_startup()

    # -------------------------------------------------------------------------
    # 4. Database Driver Resolution & Deployment Dependency Verification
    # -------------------------------------------------------------------------

    def test_12_resolve_database_url_preserves_explicit_dialects(self):
        """resolve_database_url preserves URLs with explicit dialects (psycopg, psycopg2, sqlite)."""
        from database import resolve_database_url
        self.assertEqual(
            resolve_database_url("postgresql+psycopg://user:pass@db:5432/ai_grc"),
            "postgresql+psycopg://user:pass@db:5432/ai_grc",
        )
        self.assertEqual(
            resolve_database_url("postgresql+psycopg2://user:pass@localhost:5432/ai_grc"),
            "postgresql+psycopg2://user:pass@localhost:5432/ai_grc",
        )
        self.assertEqual(
            resolve_database_url("sqlite:///:memory:"),
            "sqlite:///:memory:",
        )

    def test_13_resolve_database_url_prefers_psycopg_when_installed(self):
        """Generic postgresql:// resolves to postgresql+psycopg:// when psycopg is available."""
        from database import resolve_database_url
        with mock.patch.dict(sys.modules, {"psycopg": mock.MagicMock()}):
            resolved = resolve_database_url("postgresql://postgres:pass@db:5432/ai_grc")
            self.assertEqual(resolved, "postgresql+psycopg://postgres:pass@db:5432/ai_grc")

    def test_14_resolve_database_url_falls_back_to_psycopg2_for_local_dev(self):
        """Generic postgresql:// falls back to postgresql+psycopg2:// when only psycopg2 is available."""
        from database import resolve_database_url
        with mock.patch.dict(sys.modules, {"psycopg": None, "psycopg2": mock.MagicMock()}):
            resolved = resolve_database_url("postgresql://postgres:pass@localhost:5432/ai_grc")
            self.assertEqual(resolved, "postgresql+psycopg2://postgres:pass@localhost:5432/ai_grc")

    def test_15_resolve_database_url_normalizes_legacy_postgres_prefix(self):
        """Deprecated postgres:// is normalized and resolved."""
        from database import resolve_database_url
        with mock.patch.dict(sys.modules, {"psycopg": mock.MagicMock()}):
            resolved = resolve_database_url("postgres://postgres:pass@db:5432/ai_grc")
            self.assertTrue(resolved.startswith("postgresql+psycopg://"))

    def test_16_requirements_declares_compatible_psycopg3_without_duplicates(self):
        """requirements.txt declares compatible Psycopg 3 package without redundant duplicate drivers."""
        req_path = BASE_DIR / "requirements.txt"
        self.assertTrue(req_path.exists(), "requirements.txt must exist")
        content = req_path.read_text(encoding="utf-8")
        lines = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]

        # Must declare psycopg or psycopg[binary]
        has_psycopg = any("psycopg" in line and not line.startswith("psycopg2") for line in lines)
        self.assertTrue(has_psycopg, "requirements.txt must declare compatible Psycopg 3 package (e.g. psycopg[binary])")

        # Must not declare redundant psycopg2 alongside psycopg ("Do not blindly install multiple database drivers")
        has_psycopg2 = any("psycopg2" in line for line in lines)
        self.assertFalse(has_psycopg2, "requirements.txt must not declare redundant legacy psycopg2 alongside psycopg")

    def test_17_postgresql_psycopg_engine_loads_without_modulenotfound(self):
        """SQLAlchemy postgresql+psycopg dialect loads its DBAPI without ModuleNotFoundError."""
        try:
            import psycopg  # noqa: F401
        except ImportError:
            self.skipTest("psycopg not installed in test environment")

        from sqlalchemy import create_engine
        engine = create_engine("postgresql+psycopg://postgres:dummy@localhost:5432/ai_grc")
        self.assertEqual(engine.dialect.name, "postgresql")
        self.assertEqual(engine.dialect.driver, "psycopg")


if __name__ == "__main__":
    unittest.main()
