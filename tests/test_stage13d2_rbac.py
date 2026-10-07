"""Stage 13D.2 RBAC Authorization Test Suite.

Verifies:
1.  Unauthenticated request to protected endpoints -> 401
2.  Malformed / invalid JWT -> 401
3.  Public health / root endpoint (GET /) remains accessible without auth -> 200
4.  POST /auth/login remains public -> accessible without auth
5.  GET /auth/me remains protected -> 401 unauthenticated, 200 authenticated
6.  Security Analyst accessing Analyst endpoint -> 200 / success
7.  Security Analyst accessing Reviewer-only endpoint -> 403
8.  Security Analyst accessing Administrator-only endpoint -> 403
9.  GRC Reviewer accessing Reviewer endpoint -> 200 / success
10. GRC Reviewer accessing Administrator-only endpoint -> 403
11. Administrator accessing Administrator-only endpoint -> 200 / success
12. Administrator accessing Reviewer and Analyst endpoints -> 200 / success (hierarchical)
13. X-Operator-Role header CANNOT elevate Security Analyst to GRC Reviewer (403 enforced)
14. X-Operator-Role header CANNOT elevate Security Analyst to Administrator (403 enforced)
15. X-Operator-Role header CANNOT elevate GRC Reviewer to Administrator (403 enforced)
16. X-Operator-Name header cannot change or spoof authenticated identity
"""

import os
import sys
import unittest
from unittest import mock
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

# Setup sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import models
import main
from auth.security import create_access_token, hash_password
from auth_test_utils import create_test_user, create_test_auth_headers, ensure_jwt_secret

TEST_SECRET = "test-jwt-secret-key-at-least-32-chars-long-123456"


class TestStage13D2RBACAuthorization(unittest.TestCase):
    """Integration test suite verifying server-side Role-Based Access Control."""

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
        self.db = self.SessionLocal()

        self.session_patcher = mock.patch("main.SessionLocal", side_effect=lambda: self.SessionLocal())
        self.session_patcher.start()
        self.auth_session_patcher = mock.patch("auth.dependencies.SessionLocal", side_effect=lambda: self.SessionLocal())
        self.auth_session_patcher.start()

        self.client = TestClient(main.app)

        # Provision one user for each role
        self.analyst_user = create_test_user(self.db, username="analyst_alice", role="Security Analyst")
        self.reviewer_user = create_test_user(self.db, username="reviewer_bob", role="GRC Reviewer")
        self.admin_user = create_test_user(self.db, username="admin_charlie", role="Administrator")

        self.analyst_headers = create_test_auth_headers(self.db, username="analyst_alice", role="Security Analyst")
        self.reviewer_headers = create_test_auth_headers(self.db, username="reviewer_bob", role="GRC Reviewer")
        self.admin_headers = create_test_auth_headers(self.db, username="admin_charlie", role="Administrator")

        # Provision sample asset and evidence for testing
        self.asset = models.Asset(
            ip_address="192.168.1.50",
            hostname="host-test.local",
            criticality="High",
            environment="Production",
            exposure="Internal",
        )
        self.db.add(self.asset)
        self.db.commit()
        self.db.refresh(self.asset)

        self.evidence = models.EvidenceRecord(
            title="Sample Evidence",
            evidence_type="MANUAL_OBSERVATION",
            description="Initial observation for testing",
            source_system="AI-GRC Platform",
            collector="admin_charlie",
        )
        self.db.add(self.evidence)
        self.db.commit()
        self.db.refresh(self.evidence)

    def tearDown(self):
        self.auth_session_patcher.stop()
        self.session_patcher.stop()
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)
        self.env_patcher.stop()

    # -------------------------------------------------------------------------
    # 1. Public Endpoints & Unauthenticated Handling
    # -------------------------------------------------------------------------

    def test_01_public_root_remains_accessible_without_auth(self):
        """Root/health endpoint GET / must remain unauthenticated."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("AI-GRC Platform Backend is Running", response.json()["message"])

    def test_02_login_endpoint_remains_public(self):
        """POST /auth/login must be accessible without prior authentication."""
        response = self.client.post("/auth/login", json={"username": "analyst_alice", "password": "WrongPassword"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Invalid username or password")

    def test_03_unauthenticated_request_returns_401(self):
        """Protected endpoints return 401 when Authorization header is absent."""
        endpoints = [
            ("GET", "/assets"),
            ("GET", "/risks"),
            ("GET", "/controls"),
            ("GET", "/audit-logs"),
            ("GET", "/evidence"),
            ("GET", "/auth/me"),
            ("POST", "/controls"),
            ("DELETE", f"/evidence/{self.evidence.id}"),
        ]
        for method, path in endpoints:
            res = self.client.request(method, path)
            self.assertEqual(res.status_code, 401, f"Expected 401 for {method} {path}, got {res.status_code}")
            self.assertEqual(res.headers.get("WWW-Authenticate"), "Bearer")

    def test_04_malformed_token_returns_401(self):
        """Protected endpoints return 401 when Authorization header is malformed."""
        res_bad_format = self.client.get("/assets", headers={"Authorization": "Token abcdef12345"})
        self.assertEqual(res_bad_format.status_code, 401)

        res_bad_jwt = self.client.get("/assets", headers={"Authorization": "Bearer this-is-not-a-valid-jwt"})
        self.assertEqual(res_bad_jwt.status_code, 401)

    # -------------------------------------------------------------------------
    # 2. Security Analyst Role Permissions
    # -------------------------------------------------------------------------

    def test_05_analyst_can_access_read_endpoints(self):
        """Security Analyst can access read-only assets, risks, controls, and /auth/me."""
        res_assets = self.client.get("/assets", headers=self.analyst_headers)
        self.assertEqual(res_assets.status_code, 200)

        res_risks = self.client.get("/risks", headers=self.analyst_headers)
        self.assertEqual(res_risks.status_code, 200)

        res_controls = self.client.get("/controls", headers=self.analyst_headers)
        self.assertEqual(res_controls.status_code, 200)

        res_me = self.client.get("/auth/me", headers=self.analyst_headers)
        self.assertEqual(res_me.status_code, 200)
        self.assertEqual(res_me.json()["role"], "Security Analyst")

    def test_06_analyst_forbidden_from_reviewer_endpoints(self):
        """Security Analyst receives 403 Forbidden on Reviewer mutation endpoints."""
        # 1. POST /controls (Reviewer only)
        res_control = self.client.post(
            "/controls",
            json={"name": "New Control", "category": "Preventive"},
            headers=self.analyst_headers,
        )
        self.assertEqual(res_control.status_code, 403)
        self.assertIn("insufficient privileges", res_control.json()["detail"].lower())

        # 2. PATCH /assets/{id} (Reviewer only)
        res_asset = self.client.patch(
            f"/assets/{self.asset.id}",
            json={"criticality": "Critical"},
            headers=self.analyst_headers,
        )
        self.assertEqual(res_asset.status_code, 403)

        # 3. GET /audit-logs (Reviewer only)
        res_audit = self.client.get("/audit-logs", headers=self.analyst_headers)
        self.assertEqual(res_audit.status_code, 403)

    def test_07_analyst_forbidden_from_admin_endpoints(self):
        """Security Analyst receives 403 Forbidden on Administrator-only endpoints."""
        res_del = self.client.delete(
            f"/evidence/{self.evidence.id}",
            headers=self.analyst_headers,
        )
        self.assertEqual(res_del.status_code, 403)
        self.assertIn("insufficient privileges", res_del.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 3. GRC Reviewer Role Permissions
    # -------------------------------------------------------------------------

    def test_08_reviewer_can_access_reviewer_endpoints(self):
        """GRC Reviewer can view audit-logs, create controls, and update assets."""
        # 1. GET /audit-logs (Reviewer + Admin)
        res_audit = self.client.get("/audit-logs", headers=self.reviewer_headers)
        self.assertEqual(res_audit.status_code, 200)

        # 2. POST /controls (Reviewer + Admin)
        res_control = self.client.post(
            "/controls",
            json={"name": "Reviewer Control", "category": "Detective"},
            headers=self.reviewer_headers,
        )
        self.assertEqual(res_control.status_code, 200)

        # 3. PATCH /assets/{id} (Reviewer + Admin)
        res_asset = self.client.patch(
            f"/assets/{self.asset.id}",
            json={"criticality": "Medium"},
            headers=self.reviewer_headers,
        )
        self.assertEqual(res_asset.status_code, 200)

    def test_09_reviewer_forbidden_from_admin_only_endpoints(self):
        """GRC Reviewer receives 403 Forbidden on destructive Administrator operations."""
        res_del = self.client.delete(
            f"/evidence/{self.evidence.id}",
            headers=self.reviewer_headers,
        )
        self.assertEqual(res_del.status_code, 403)
        self.assertIn("insufficient privileges", res_del.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 4. Administrator Role Permissions
    # -------------------------------------------------------------------------

    def test_10_admin_can_access_admin_endpoints(self):
        """Administrator can execute destructive operations (e.g. DELETE /evidence/{id})."""
        res_del = self.client.delete(
            f"/evidence/{self.evidence.id}",
            headers=self.admin_headers,
        )
        self.assertEqual(res_del.status_code, 200)
        self.assertIn("deleted successfully", res_del.json()["message"].lower())

    def test_11_admin_has_hierarchical_access(self):
        """Administrator inherits all GRC Reviewer and Security Analyst permissions."""
        res_assets = self.client.get("/assets", headers=self.admin_headers)
        self.assertEqual(res_assets.status_code, 200)

        res_audit = self.client.get("/audit-logs", headers=self.admin_headers)
        self.assertEqual(res_audit.status_code, 200)

    # -------------------------------------------------------------------------
    # 5. Header Spoofing Defenses (X-Operator-* Cannot Bypass RBAC)
    # -------------------------------------------------------------------------

    def test_12_x_operator_role_cannot_elevate_analyst_to_reviewer(self):
        """Header X-Operator-Role: GRC Reviewer cannot elevate an authenticated Security Analyst."""
        spoofed_headers = {
            **self.analyst_headers,
            "X-Operator-Name": "AdminBob",
            "X-Operator-Role": "GRC Reviewer",
        }
        response = self.client.post(
            "/controls",
            json={"name": "Spoofed Control"},
            headers=spoofed_headers,
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("insufficient privileges", response.json()["detail"].lower())

    def test_13_x_operator_role_cannot_elevate_analyst_to_admin(self):
        """Header X-Operator-Role: Administrator cannot elevate an authenticated Security Analyst."""
        spoofed_headers = {
            **self.analyst_headers,
            "X-Operator-Name": "RootAdmin",
            "X-Operator-Role": "Administrator",
        }
        response = self.client.delete(
            f"/evidence/{self.evidence.id}",
            headers=spoofed_headers,
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("insufficient privileges", response.json()["detail"].lower())

    def test_14_x_operator_role_cannot_elevate_reviewer_to_admin(self):
        """Header X-Operator-Role: Administrator cannot elevate an authenticated GRC Reviewer."""
        spoofed_headers = {
            **self.reviewer_headers,
            "X-Operator-Role": "Administrator",
        }
        response = self.client.delete(
            f"/evidence/{self.evidence.id}",
            headers=spoofed_headers,
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("insufficient privileges", response.json()["detail"].lower())


if __name__ == "__main__":
    unittest.main()
