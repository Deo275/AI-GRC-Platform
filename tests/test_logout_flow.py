"""Stage 13D.1 / Stage 14 Logout Behavior Test Suite.

Verifies:
1. POST /auth/logout with valid Bearer token returns HTTP 200 and logs USER_LOGOUT audit event.
2. POST /auth/logout without Authorization header returns HTTP 200 gracefully.
3. POST /auth/logout with invalid or malformed Bearer token returns HTTP 200 gracefully.
4. Protected endpoints (/auth/me, /scan, /reports/executive-summary) strictly reject requests
   once the token is removed/missing (HTTP 401 Unauthorized).
"""

import os
import sys
from pathlib import Path
import unittest
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import models
import main
from auth.security import hash_password, create_access_token

TEST_SECRET = "test-jwt-secret-key-at-least-32-chars-long-123456"


class TestLogoutBehavior(unittest.TestCase):
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

        self.db = self.TestingSessionLocal()

        # Create active test user
        self.user = models.User(
            username="analyst_logout_test",
            email="analyst@example.com",
            display_name="Test Analyst",
            password_hash=hash_password("ValidPassword123!"),
            role="Security Analyst",
            is_active=True,
        )
        self.db.add(self.user)
        self.db.commit()
        self.db.refresh(self.user)

        self.token = create_access_token(
            subject=self.user.id,
            username=self.user.username,
            role=self.user.role,
        )

        self.client = TestClient(main.app)

    def tearDown(self):
        self.db.close()
        self.session_patcher.stop()
        self.auth_session_patcher.stop()
        models.Base.metadata.drop_all(bind=self.engine)
        self.env_patcher.stop()

    def test_authenticated_logout_success_and_audit_event(self):
        """Authenticated user calling POST /auth/logout receives 200 and an audit record is created."""
        response = self.client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["message"], "Successfully logged out.")

        # Verify audit log record
        audit_entry = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "USER_LOGOUT")
            .first()
        )
        self.assertIsNotNone(audit_entry, "Audit event USER_LOGOUT should be persisted on logout")
        self.assertEqual(audit_entry.actor, self.user.username)
        self.assertEqual(audit_entry.entity_type, "User")
        self.assertEqual(audit_entry.entity_id, self.user.id)
        self.assertIn("signed out successfully", audit_entry.description)

    def test_unauthenticated_logout_succeeds_gracefully(self):
        """Unauthenticated logout without Authorization header returns 200 without error."""
        response = self.client.post("/auth/logout")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["message"], "Successfully logged out.")

    def test_invalid_token_logout_succeeds_gracefully(self):
        """Logout with invalid or malformed Bearer token returns 200 without error."""
        response = self.client.post(
            "/auth/logout",
            headers={"Authorization": "Bearer not-a-valid-jwt-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["message"], "Successfully logged out.")

    def test_protected_endpoints_reject_after_token_removed(self):
        """Protected endpoints return 401 Unauthorized when token is absent/removed."""
        # 1. /auth/me
        res_me = self.client.get("/auth/me")
        self.assertEqual(res_me.status_code, 401)
        self.assertIn("Missing Authorization header", res_me.json()["detail"])

        # 2. /reports/executive-summary
        res_rep = self.client.get("/reports/executive-summary")
        self.assertEqual(res_rep.status_code, 401)

        # 3. /scan
        res_scan = self.client.post("/scan?target=192.168.1.1")
        self.assertEqual(res_scan.status_code, 401)


if __name__ == "__main__":
    unittest.main()
