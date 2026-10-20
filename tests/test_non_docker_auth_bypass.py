"""Unit and integration tests for non-Docker login bypass and dev-login endpoint.

Verifies:
1. POST /auth/dev-login generates a valid Administrator JWT token in non-production.
2. POST /auth/dev-login is forbidden (HTTP 403) in production mode.
3. Bearer dev-bypass-token is accepted by get_current_user in non-production mode.
4. Bearer dev-bypass-token is rejected in production mode.
"""

import os
import sys
from pathlib import Path
import unittest
from unittest import mock

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

import models
import main
from auth.security import decode_access_token

TEST_SECRET = "test-jwt-secret-key-at-least-32-chars-long-123456"


class TestNonDockerAuthBypass(unittest.TestCase):
    """Test suite for non-Docker authentication bypass behaviors."""

    def setUp(self):
        self.env_patcher = mock.patch.dict(os.environ, {
            "JWT_SECRET_KEY": TEST_SECRET,
            "ENV": "development",
        })
        self.env_patcher.start()

        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        models.Base.metadata.create_all(bind=self.engine)
        self.TestingSessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        self.session_patcher = mock.patch("main.SessionLocal", side_effect=self.TestingSessionLocal)
        self.session_patcher.start()
        self.auth_session_patcher = mock.patch("auth.dependencies.SessionLocal", side_effect=self.TestingSessionLocal)
        self.auth_session_patcher.start()

        self.client = TestClient(main.app)

    def tearDown(self):
        self.session_patcher.stop()
        self.auth_session_patcher.stop()
        models.Base.metadata.drop_all(bind=self.engine)
        self.env_patcher.stop()

    def test_dev_login_success_non_production(self):
        """POST /auth/dev-login provisions dev admin and returns valid JWT in non-production."""
        response = self.client.post("/auth/dev-login")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["user"]["role"], "Administrator")
        self.assertTrue(data["user"]["is_active"])

        # Verify JWT token payload
        payload = decode_access_token(data["access_token"])
        self.assertEqual(payload["username"], data["user"]["username"])
        self.assertEqual(payload["role"], "Administrator")

    def test_dev_login_forbidden_in_production(self):
        """POST /auth/dev-login returns HTTP 403 Forbidden when ENV=production."""
        with mock.patch.dict(os.environ, {"ENV": "production", "AUTH_DEV_LOGIN_ENABLED": "false"}):
            response = self.client.post("/auth/dev-login")
            self.assertEqual(response.status_code, 403)
            self.assertIn("disabled in production", response.json()["detail"])

    def test_dev_bypass_token_accepted_in_dependencies(self):
        """Bearer dev-bypass-token resolves to Administrator user in non-production mode."""
        response = self.client.get(
            "/auth/me",
            headers={"Authorization": "Bearer dev-bypass-token"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["role"], "Administrator")
        self.assertTrue(data["is_active"])

    def test_dev_bypass_token_rejected_in_production(self):
        """Bearer dev-bypass-token fails authentication in production mode."""
        with mock.patch.dict(os.environ, {"ENV": "production", "AUTH_DEV_LOGIN_ENABLED": "false"}):
            response = self.client.get(
                "/auth/me",
                headers={"Authorization": "Bearer dev-bypass-token"},
            )
            self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
