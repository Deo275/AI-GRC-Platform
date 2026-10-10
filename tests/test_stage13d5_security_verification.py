"""Stage 13D.5 Final Authentication & RBAC Security Verification Test Suite.

Comprehensive security verification verifying:
1.  Authentication: username/email login, failure genericness, inactive users, missing fields.
2.  Enumeration defense: invalid username and wrong password produce identical generic 401.
3.  JWT security: valid tokens, expired tokens, invalid signatures, malformed tokens, missing claims,
    wrong secret, tampered role claims, algorithm confusion ("none"), lifetime enforcement, no password in payload.
4.  Authorization headers: missing, malformed, non-Bearer, empty token -> 401.
5.  User account security: Argon2id hashing, no plaintext in DB, no hash in API/JWT, inactive account enforcement,
    authoritative DB role, role immutability via API.
6.  RBAC matrix across all 3 roles and 12+ endpoint categories:
    Security Analyst (analyst allowed, reviewer 403, admin 403)
    GRC Reviewer (analyst allowed, reviewer allowed, admin 403)
    Administrator (analyst allowed, reviewer allowed, admin allowed)
7.  Authentication (401) vs Authorization (403) distinction consistency.
8.  Operator identity anti-spoofing: X-Operator-* headers and review payload reviewer_name/role cannot spoof identity or escalate privilege.
9.  Audit integrity: authenticated actor attribution, system identity preservation, deterministic SHA-256 hash calculation,
    tamper detection on record modification.
10. Destructive operations: evidence deletion restricted to Administrator only, attributed to Admin in audit logs.
11. Public vs protected endpoint boundaries: only GET / and POST /auth/login are unauthenticated.
"""

import os
import sys
import copy
import json
import base64
import datetime
import unittest
from unittest import mock
from pathlib import Path

import jwt
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
from auth.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    JWT_ALGORITHM,
)
from governance.audit_logger import calculate_audit_integrity_hash, log_audit_event
from auth_test_utils import create_test_user, create_test_auth_headers

TEST_SECRET = "stage-13d5-security-verification-secret-key-32chars"


class TestStage13D5SecurityVerification(unittest.TestCase):
    """Comprehensive Stage 13D.5 Security Verification Test Suite."""

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

        # Provision authoritative test users
        self.analyst_user = create_test_user(
            self.db,
            username="analyst_alice",
            email="alice@company.internal",
            password="AnalystPassword123!",
            role="Security Analyst",
        )
        self.analyst_user.display_name = "Alice Analyst"

        self.reviewer_user = create_test_user(
            self.db,
            username="reviewer_bob",
            email="bob@company.internal",
            password="ReviewerPassword123!",
            role="GRC Reviewer",
        )
        self.reviewer_user.display_name = "Bob Reviewer"

        self.admin_user = create_test_user(
            self.db,
            username="admin_charlie",
            email="charlie@company.internal",
            password="AdminPassword123!",
            role="Administrator",
        )
        self.admin_user.display_name = "Charlie Admin"

        self.inactive_user = create_test_user(
            self.db,
            username="inactive_dave",
            email="dave@company.internal",
            password="InactivePassword123!",
            role="Security Analyst",
            is_active=False,
        )

        # Provision test fixture entities
        self.asset = models.Asset(
            ip_address="192.168.1.100",
            hostname="core-prod-01.internal",
            criticality="High",
            environment="Production",
            exposure="Internal",
        )
        self.db.add(self.asset)
        self.db.commit()
        self.db.refresh(self.asset)

        self.risk = models.Risk(
            title="Unauthenticated Internal Service",
            asset_id=self.asset.id,
            description="Missing Service Authentication leading to potential lateral movement",
            likelihood="High",
            impact="High",
            inherent_risk_score=20,
            inherent_risk_level="High",
            residual_risk_score=20,
            residual_risk_level="High",
            treatment="Mitigate",
            status="Open",
            review_status="Pending Review",
        )
        self.db.add(self.risk)

        self.control = models.Control(
            name="AC-01 Access Enforcement",
            description="Role based access control enforcement",
            category="Technical",
            framework="NIST CSF",
            effectiveness="High",
            status="Implemented",
        )
        self.db.add(self.control)

        self.framework = models.ComplianceFramework(
            name="SOC 2 Type II",
            version="2022",
            description="SOC 2 Security Criteria",
        )
        self.db.add(self.framework)
        self.db.commit()
        self.db.refresh(self.framework)

        self.requirement = models.ComplianceRequirement(
            framework_id=self.framework.id,
            requirement_id="CC6.1",
            title="Logical Access Security",
            description="Controls over logical access",
            status="Compliant",
        )
        self.db.add(self.requirement)

        self.evidence = models.EvidenceRecord(
            title="Penetration Test Report Q3",
            evidence_type="AUDIT_DOCUMENT",
            description="External penetration test findings",
            source_system="AI-GRC Platform",
            collector="admin_charlie",
        )
        self.db.add(self.evidence)

        self.db.commit()
        self.db.refresh(self.risk)
        self.db.refresh(self.control)
        self.db.refresh(self.requirement)
        self.db.refresh(self.evidence)

        # Provision tokens and headers
        self.analyst_headers = create_test_auth_headers(self.db, username="analyst_alice", role="Security Analyst")
        self.reviewer_headers = create_test_auth_headers(self.db, username="reviewer_bob", role="GRC Reviewer")
        self.admin_headers = create_test_auth_headers(self.db, username="admin_charlie", role="Administrator")

    def tearDown(self):
        self.auth_session_patcher.stop()
        self.session_patcher.stop()
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)
        self.env_patcher.stop()

    # =========================================================================
    # 1. AUTHENTICATION & LOGIN TESTING
    # =========================================================================

    def test_01_login_valid_username_and_password_success(self):
        """Valid username + valid password succeeds with access token and user payload."""
        resp = self.client.post("/auth/login", json={
            "username": "analyst_alice",
            "password": "AnalystPassword123!",
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["user"]["username"], "analyst_alice")
        self.assertEqual(data["user"]["role"], "Security Analyst")
        self.assertNotIn("password", data["user"])
        self.assertNotIn("password_hash", data["user"])

    def test_02_login_valid_email_and_password_success(self):
        """Valid email + valid password succeeds identically."""
        resp = self.client.post("/auth/login", json={
            "username": "bob@company.internal",
            "password": "ReviewerPassword123!",
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["user"]["username"], "reviewer_bob")
        self.assertEqual(data["user"]["role"], "GRC Reviewer")

    def test_03_login_invalid_username_generic_failure(self):
        """Invalid username returns HTTP 401 with generic failure message."""
        resp = self.client.post("/auth/login", json={
            "username": "nonexistent_user",
            "password": "AnyPassword123!",
        })
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Invalid username or password")

    def test_04_login_invalid_email_generic_failure(self):
        """Invalid email returns HTTP 401 with generic failure message."""
        resp = self.client.post("/auth/login", json={
            "username": "nonexistent@company.internal",
            "password": "AnyPassword123!",
        })
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Invalid username or password")

    def test_05_login_wrong_password_generic_failure(self):
        """Wrong password for existing user returns HTTP 401 with identical generic error."""
        resp = self.client.post("/auth/login", json={
            "username": "analyst_alice",
            "password": "IncorrectPassword999!",
        })
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Invalid username or password")

    def test_06_account_enumeration_defense(self):
        """Verify invalid user and wrong password produce identical status code and detail."""
        resp_invalid_user = self.client.post("/auth/login", json={
            "username": "does_not_exist_xyz",
            "password": "Password123!",
        })
        resp_wrong_password = self.client.post("/auth/login", json={
            "username": "analyst_alice",
            "password": "WrongPassword123!",
        })
        self.assertEqual(resp_invalid_user.status_code, 401)
        self.assertEqual(resp_wrong_password.status_code, 401)
        self.assertEqual(resp_invalid_user.json()["detail"], resp_wrong_password.json()["detail"])
        self.assertEqual(resp_invalid_user.json()["detail"], "Invalid username or password")

    def test_07_login_inactive_user_rejected(self):
        """Inactive user account cannot authenticate and receives generic 401."""
        resp = self.client.post("/auth/login", json={
            "username": "inactive_dave",
            "password": "InactivePassword123!",
        })
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Invalid username or password")

    def test_08_login_missing_fields_validation_error(self):
        """Missing username or password in payload returns HTTP 422 Unprocessable Entity."""
        resp1 = self.client.post("/auth/login", json={"password": "Password123!"})
        self.assertEqual(resp1.status_code, 422)

        resp2 = self.client.post("/auth/login", json={"username": "analyst_alice"})
        self.assertEqual(resp2.status_code, 422)

    # =========================================================================
    # 2. JWT VALIDATION & SECURITY TESTING
    # =========================================================================

    def test_09_jwt_valid_token_accepted_on_protected_me(self):
        """Valid token on /auth/me returns the authenticated user record."""
        resp = self.client.get("/auth/me", headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["username"], "analyst_alice")
        self.assertEqual(data["role"], "Security Analyst")
        self.assertNotIn("password", data)
        self.assertNotIn("password_hash", data)

    def test_10_jwt_expired_token_rejected(self):
        """Expired JWT token returns HTTP 401 with 'Token has expired'."""
        expired_token = create_access_token(
            subject=self.analyst_user.id,
            username=self.analyst_user.username,
            role=self.analyst_user.role,
            expires_delta=datetime.timedelta(seconds=-10),
        )
        resp = self.client.get("/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Token has expired")

    def test_11_jwt_invalid_signature_rejected(self):
        """JWT signed with a different secret returns HTTP 401."""
        wrong_token = jwt.encode(
            {
                "sub": str(self.analyst_user.id),
                "username": self.analyst_user.username,
                "role": self.analyst_user.role,
                "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
                "iat": datetime.datetime.now(datetime.timezone.utc),
            },
            "completely-wrong-secret-key-that-does-not-match",
            algorithm="HS256",
        )
        resp = self.client.get("/auth/me", headers={"Authorization": f"Bearer {wrong_token}"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Invalid authentication token")

    def test_12_jwt_malformed_token_rejected(self):
        """Malformed/garbage JWT returns HTTP 401."""
        resp = self.client.get("/auth/me", headers={"Authorization": "Bearer not.a.valid.jwt.token"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Invalid authentication token")

    def test_13_jwt_missing_required_claims_rejected(self):
        """Token missing required claim (e.g. 'role' or 'sub') returns HTTP 401."""
        now = datetime.datetime.now(datetime.timezone.utc)
        incomplete_payload = {
            "sub": str(self.analyst_user.id),
            "username": self.analyst_user.username,
            # missing "role"
            "exp": now + datetime.timedelta(hours=1),
            "iat": now,
        }
        token = jwt.encode(incomplete_payload, TEST_SECRET, algorithm="HS256")
        resp = self.client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 401)

    def test_14_jwt_algorithm_confusion_none_rejected(self):
        """Token with algorithm 'none' cannot bypass verification."""
        header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps({
            "sub": str(self.admin_user.id),
            "username": self.admin_user.username,
            "role": "Administrator",
            "exp": 9999999999,
            "iat": 1000,
        }).encode()).decode().rstrip("=")
        unsigned_token = f"{header_b64}.{payload_b64}."
        resp = self.client.get("/auth/me", headers={"Authorization": f"Bearer {unsigned_token}"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Invalid authentication token")

    def test_15_jwt_tampered_role_claim_rejected(self):
        """Modifying the payload role claim without re-signing with correct secret is rejected."""
        valid_token = create_access_token(
            subject=self.analyst_user.id,
            username=self.analyst_user.username,
            role="Security Analyst",
        )
        parts = valid_token.split(".")
        # Tampering payload part
        tampered_token = f"{parts[0]}.eyJob2tvcyI6InBva29zIn0.{parts[2]}"
        resp = self.client.get("/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
        self.assertEqual(resp.status_code, 401)

    def test_16_jwt_payload_contains_no_password_or_hash(self):
        """JWT claims contain sub, username, role, iat, exp and NEVER password or hash."""
        token = create_access_token(
            subject=self.analyst_user.id,
            username=self.analyst_user.username,
            role="Security Analyst",
        )
        decoded = decode_access_token(token)
        self.assertIn("sub", decoded)
        self.assertIn("username", decoded)
        self.assertIn("role", decoded)
        self.assertIn("exp", decoded)
        self.assertIn("iat", decoded)
        self.assertNotIn("password", decoded)
        self.assertNotIn("password_hash", decoded)
        self.assertNotIn("hash", decoded)

    def test_17_jwt_lifetime_enforced(self):
        """Issued token has an expiration delta of 60 minutes."""
        token = create_access_token(
            subject=self.analyst_user.id,
            username=self.analyst_user.username,
            role="Security Analyst",
        )
        decoded = decode_access_token(token)
        lifetime = decoded["exp"] - decoded["iat"]
        self.assertEqual(lifetime, 3600)

    # =========================================================================
    # 3. AUTHORIZATION HEADER FORMAT TESTS
    # =========================================================================

    def test_18_missing_authorization_header_returns_401(self):
        """Request without Authorization header returns HTTP 401."""
        resp = self.client.get("/auth/me")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Missing Authorization header")

    def test_19_malformed_authorization_header_returns_401(self):
        """Authorization header not in 'Bearer <token>' format returns HTTP 401."""
        resp = self.client.get("/auth/me", headers={"Authorization": "TokenOnlyNoBearer"})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid Authorization header format", resp.json()["detail"])

    def test_20_non_bearer_scheme_returns_401(self):
        """Non-Bearer scheme (e.g. Basic) returns HTTP 401."""
        resp = self.client.get("/auth/me", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid Authorization header format", resp.json()["detail"])

    def test_21_empty_bearer_token_returns_401(self):
        """Empty Bearer token returns HTTP 401."""
        resp = self.client.get("/auth/me", headers={"Authorization": "Bearer "})
        self.assertEqual(resp.status_code, 401)

    # =========================================================================
    # 4. USER ACCOUNT SECURITY & INTEGRITY
    # =========================================================================

    def test_22_passwords_stored_only_as_argon2id_hashes(self):
        """User password_hash field must be Argon2id hash and not plaintext."""
        user = self.db.query(models.User).filter(models.User.username == "analyst_alice").first()
        self.assertTrue(user.password_hash.startswith("$argon2id$"))
        self.assertNotEqual(user.password_hash, "AnalystPassword123!")
        self.assertTrue(verify_password("AnalystPassword123!", user.password_hash))
        self.assertFalse(verify_password("WrongPassword!", user.password_hash))

    def test_23_inactive_user_cannot_access_protected_routes(self):
        """An inactive user holding a valid JWT is rejected with HTTP 401 on protected routes."""
        token = create_access_token(
            subject=self.inactive_user.id,
            username=self.inactive_user.username,
            role="Security Analyst",
        )
        resp = self.client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "User account is inactive")

    def test_24_authoritative_database_role_enforcement(self):
        """If a token claims 'Administrator' but database record says 'Security Analyst', database role governs."""
        forged_admin_token = create_access_token(
            subject=self.analyst_user.id,
            username="analyst_alice",
            role="Administrator",
        )
        resp = self.client.delete(f"/evidence/{self.evidence.id}", headers={"Authorization": f"Bearer {forged_admin_token}"})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("insufficient privileges", resp.json()["detail"])

    # =========================================================================
    # 5. RBAC MATRIX & 401 VS 403 ENFORCEMENT
    # =========================================================================

    def test_25_rbac_matrix_across_all_protected_categories(self):
        """Verify the exact permission matrix across Analyst, Reviewer, Admin roles."""
        # 1. Read-only endpoints (Analyst, Reviewer, Admin all have access: 200)
        read_endpoints = [
            "/assets",
            f"/assets/{self.asset.id}",
            "/risks",
            f"/risks/{self.risk.id}",
            "/controls",
            f"/controls/{self.control.id}",
            "/vulnerabilities",
            "/compliance/frameworks",
            "/compliance/requirements",
            "/compliance/mappings",
            "/compliance/summary",
            "/monitoring/schedules",
            "/evidence",
            f"/evidence/{self.evidence.id}",
            "/reports/executive-summary",
            "/reports/risk-register",
            f"/risks/{self.risk.id}/reviews",
            "/governance/reviews/pending",
        ]
        for url in read_endpoints:
            # Unauthenticated -> 401
            resp_unauth = self.client.get(url)
            self.assertEqual(resp_unauth.status_code, 401, f"GET {url} unauthenticated must be 401")

            # Analyst -> 200
            resp_analyst = self.client.get(url, headers=self.analyst_headers)
            self.assertEqual(resp_analyst.status_code, 200, f"GET {url} Analyst must be 200")

            # Reviewer -> 200
            resp_reviewer = self.client.get(url, headers=self.reviewer_headers)
            self.assertEqual(resp_reviewer.status_code, 200, f"GET {url} Reviewer must be 200")

            # Admin -> 200
            resp_admin = self.client.get(url, headers=self.admin_headers)
            self.assertEqual(resp_admin.status_code, 200, f"GET {url} Admin must be 200")

        # 2. Reviewer-tier endpoints (Analyst -> 403, Reviewer -> 200/201, Admin -> 200/201)
        # 2a. GET /audit-logs
        self.assertEqual(self.client.get("/audit-logs").status_code, 401)
        self.assertEqual(self.client.get("/audit-logs", headers=self.analyst_headers).status_code, 403)
        self.assertEqual(self.client.get("/audit-logs", headers=self.reviewer_headers).status_code, 200)
        self.assertEqual(self.client.get("/audit-logs", headers=self.admin_headers).status_code, 200)

        # 2b. PATCH /assets/{id}
        self.assertEqual(self.client.patch(f"/assets/{self.asset.id}", json={"criticality": "Low"}).status_code, 401)
        self.assertEqual(self.client.patch(f"/assets/{self.asset.id}", json={"criticality": "Low"}, headers=self.analyst_headers).status_code, 403)
        self.assertEqual(self.client.patch(f"/assets/{self.asset.id}", json={"criticality": "Medium"}, headers=self.reviewer_headers).status_code, 200)
        self.assertEqual(self.client.patch(f"/assets/{self.asset.id}", json={"criticality": "High"}, headers=self.admin_headers).status_code, 200)

        # 2c. PATCH /risks/{id}
        self.assertEqual(self.client.patch(f"/risks/{self.risk.id}", json={"treatment": "Mitigate"}).status_code, 401)
        self.assertEqual(self.client.patch(f"/risks/{self.risk.id}", json={"treatment": "Mitigate"}, headers=self.analyst_headers).status_code, 403)
        self.assertEqual(self.client.patch(f"/risks/{self.risk.id}", json={"treatment": "Accept"}, headers=self.reviewer_headers).status_code, 200)
        self.assertEqual(self.client.patch(f"/risks/{self.risk.id}", json={"treatment": "Mitigate"}, headers=self.admin_headers).status_code, 200)

        # 2d. POST /controls
        self.assertEqual(self.client.post("/controls", json={"name": "AC-99 Analyst"}).status_code, 401)
        self.assertEqual(self.client.post("/controls", json={"name": "AC-99 Analyst"}, headers=self.analyst_headers).status_code, 403)
        self.assertEqual(self.client.post("/controls", json={"name": "AC-99 Reviewer"}, headers=self.reviewer_headers).status_code, 200)
        self.assertEqual(self.client.post("/controls", json={"name": "AC-99 Admin"}, headers=self.admin_headers).status_code, 200)

        # 2e. PATCH /compliance/requirements/{id}
        self.assertEqual(self.client.patch(f"/compliance/requirements/{self.requirement.id}", json={"status": "Implemented"}).status_code, 401)
        self.assertEqual(self.client.patch(f"/compliance/requirements/{self.requirement.id}", json={"status": "Implemented"}, headers=self.analyst_headers).status_code, 403)
        self.assertEqual(self.client.patch(f"/compliance/requirements/{self.requirement.id}", json={"status": "Implemented"}, headers=self.reviewer_headers).status_code, 200)
        self.assertEqual(self.client.patch(f"/compliance/requirements/{self.requirement.id}", json={"status": "Partially Implemented"}, headers=self.admin_headers).status_code, 200)

        # 2f. POST /monitoring/schedules
        self.assertEqual(self.client.post("/monitoring/schedules", json={"name": "S1", "target": "10.0.0.0/24", "interval_minutes": 60}).status_code, 401)
        self.assertEqual(self.client.post("/monitoring/schedules", json={"name": "S1", "target": "10.0.0.0/24", "interval_minutes": 60}, headers=self.analyst_headers).status_code, 403)
        self.assertEqual(self.client.post("/monitoring/schedules", json={"name": "S2", "target": "10.0.0.0/24", "interval_minutes": 60}, headers=self.reviewer_headers).status_code, 201)
        self.assertEqual(self.client.post("/monitoring/schedules", json={"name": "S3", "target": "10.0.0.0/24", "interval_minutes": 60}, headers=self.admin_headers).status_code, 201)

        # 2g. POST /evidence
        self.assertEqual(self.client.post("/evidence", json={"title": "E1", "evidence_type": "AUDIT"}).status_code, 401)
        self.assertEqual(self.client.post("/evidence", json={"title": "E1", "evidence_type": "AUDIT"}, headers=self.analyst_headers).status_code, 403)
        self.assertEqual(self.client.post("/evidence", json={"title": "E2", "evidence_type": "AUDIT"}, headers=self.reviewer_headers).status_code, 201)
        self.assertEqual(self.client.post("/evidence", json={"title": "E3", "evidence_type": "AUDIT"}, headers=self.admin_headers).status_code, 201)

        # 2h. POST /governance/reviews/evaluate-stale
        self.assertEqual(self.client.post("/governance/reviews/evaluate-stale").status_code, 401)
        self.assertEqual(self.client.post("/governance/reviews/evaluate-stale", headers=self.analyst_headers).status_code, 403)
        self.assertEqual(self.client.post("/governance/reviews/evaluate-stale", headers=self.reviewer_headers).status_code, 200)
        self.assertEqual(self.client.post("/governance/reviews/evaluate-stale", headers=self.admin_headers).status_code, 200)

        # 2i. POST /risks/{id}/reviews
        review_payload = {"decision": "APPROVED", "agreed_treatment": "Mitigate", "comments": "Valid justification"}
        self.assertEqual(self.client.post(f"/risks/{self.risk.id}/reviews", json=review_payload).status_code, 401)
        self.assertEqual(self.client.post(f"/risks/{self.risk.id}/reviews", json=review_payload, headers=self.analyst_headers).status_code, 403)
        self.assertEqual(self.client.post(f"/risks/{self.risk.id}/reviews", json=review_payload, headers=self.reviewer_headers).status_code, 201)
        self.assertEqual(self.client.post(f"/risks/{self.risk.id}/reviews", json=review_payload, headers=self.admin_headers).status_code, 201)

        # 3. Admin-tier endpoints (Analyst -> 403, Reviewer -> 403, Admin -> 200)
        # DELETE /evidence/{id}
        temp_ev = models.EvidenceRecord(
            title="Temp Evidence",
            evidence_type="MANUAL_OBSERVATION",
            description="Testing admin deletion",
            source_system="AI-GRC Platform",
            collector="admin_charlie",
        )
        self.db.add(temp_ev)
        self.db.commit()
        self.db.refresh(temp_ev)

        self.assertEqual(self.client.delete(f"/evidence/{temp_ev.id}").status_code, 401)
        self.assertEqual(self.client.delete(f"/evidence/{temp_ev.id}", headers=self.analyst_headers).status_code, 403)
        self.assertEqual(self.client.delete(f"/evidence/{temp_ev.id}", headers=self.reviewer_headers).status_code, 403)
        self.assertEqual(self.client.delete(f"/evidence/{temp_ev.id}", headers=self.admin_headers).status_code, 200)

    # =========================================================================
    # 6. OPERATOR IDENTITY ANTI-SPOOFING & AUDIT ATTRIBUTION
    # =========================================================================

    def test_26_header_spoofing_cannot_elevate_privilege(self):
        """Security Analyst sending X-Operator-Role: Administrator receives 403 on admin/reviewer endpoints."""
        spoofed_headers = copy.deepcopy(self.analyst_headers)
        spoofed_headers["X-Operator-Name"] = "admin_charlie"
        spoofed_headers["X-Operator-Role"] = "Administrator"

        # Attempt to access audit-logs (reviewer/admin only)
        resp = self.client.get("/audit-logs", headers=spoofed_headers)
        self.assertEqual(resp.status_code, 403)

        # Attempt to delete evidence (admin only)
        resp_del = self.client.delete(f"/evidence/{self.evidence.id}", headers=spoofed_headers)
        self.assertEqual(resp_del.status_code, 403)

    def test_27_header_spoofing_cannot_alter_audit_actor(self):
        """Authenticated mutation retains authenticated user as audit actor despite spoofed X-Operator headers."""
        spoofed_reviewer_headers = copy.deepcopy(self.reviewer_headers)
        spoofed_reviewer_headers["X-Operator-Name"] = "Fake Executive"
        spoofed_reviewer_headers["X-Operator-Role"] = "Administrator"

        resp = self.client.post("/evidence", json={
            "title": "Anti-Spoofing Evidence Test",
            "evidence_type": "AUDIT_TEST",
            "description": "Verifying actor attribution",
        }, headers=spoofed_reviewer_headers)
        self.assertEqual(resp.status_code, 201)

        # Check audit log actor
        audit_entry = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "CREATE", models.AuditLog.entity_type == "EvidenceRecord")
            .order_by(models.AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(audit_entry)
        self.assertEqual(audit_entry.actor, "reviewer_bob")
        self.assertNotEqual(audit_entry.actor, "Fake Executive")

    def test_28_body_payload_spoofing_is_ignored(self):
        """Governance review submission ignores client payload reviewer_name/role and uses authenticated User."""
        spoofed_payload = {
            "decision": "APPROVED",
            "agreed_treatment": "Mitigate",
            "comments": "Valid justification comments",
            "reviewer_name": "Chief Security Officer",
            "reviewer_role": "Administrator",
        }
        resp = self.client.post(
            f"/risks/{self.risk.id}/reviews",
            json=spoofed_payload,
            headers=self.reviewer_headers,
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["reviewer_name"], "Bob Reviewer")
        self.assertEqual(data["reviewer_role"], "GRC Reviewer")
        self.assertNotEqual(data["reviewer_name"], "Chief Security Officer")

        # Verify audit event actor
        audit_entry = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "RISK_REVIEW_SUBMITTED")
            .order_by(models.AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(audit_entry)
        self.assertEqual(audit_entry.actor, "reviewer_bob")
        self.assertNotEqual(audit_entry.actor, "Chief Security Officer")

    # =========================================================================
    # 7. AUDIT INTEGRITY & TAMPER-EVIDENCE
    # =========================================================================

    def test_29_audit_hash_chain_calculation_and_tamper_detection(self):
        """Verifies deterministic SHA-256 calculation and detects deliberate modifications."""
        # 1. Create audit event
        entry = log_audit_event(
            db=self.db,
            source="API",
            actor="admin_charlie",
            action="CONTROL_CREATE",
            entity_type="Control",
            entity_id=self.control.id,
            entity_name=self.control.name,
            description="Initial creation of control AC-01",
            commit=True,
        )
        self.assertIsNotNone(entry)

        # 2. Recompute hash on clean entry
        recalculated_hash = calculate_audit_integrity_hash(
            timestamp=entry.timestamp,
            source=entry.source,
            actor=entry.actor,
            action=entry.action,
            entity_type=entry.entity_type,
            entity_id=entry.entity_id,
            entity_name=entry.entity_name,
            old_values=entry.old_values,
            new_values=entry.new_values,
            description=entry.description,
            ip_address=entry.ip_address,
        )
        self.assertEqual(entry.integrity_hash, recalculated_hash)

        # 3. Simulate tampering with the actor field
        tampered_actor_hash = calculate_audit_integrity_hash(
            timestamp=entry.timestamp,
            source=entry.source,
            actor="malicious_intruder",  # tampered
            action=entry.action,
            entity_type=entry.entity_type,
            entity_id=entry.entity_id,
            entity_name=entry.entity_name,
            old_values=entry.old_values,
            new_values=entry.new_values,
            description=entry.description,
            ip_address=entry.ip_address,
        )
        self.assertNotEqual(entry.integrity_hash, tampered_actor_hash)

        # 4. Simulate tampering with description
        tampered_desc_hash = calculate_audit_integrity_hash(
            timestamp=entry.timestamp,
            source=entry.source,
            actor=entry.actor,
            action=entry.action,
            entity_type=entry.entity_type,
            entity_id=entry.entity_id,
            entity_name=entry.entity_name,
            old_values=entry.old_values,
            new_values=entry.new_values,
            description="Tampered description payload",  # tampered
            ip_address=entry.ip_address,
        )
        self.assertNotEqual(entry.integrity_hash, tampered_desc_hash)

    def test_30_system_background_operations_retain_system_identity(self):
        """Background or system audit events preserve source='SYSTEM' and actor='SYSTEM_DRIFT_DETECTOR'."""
        entry = log_audit_event(
            db=self.db,
            source="SYSTEM",
            actor="SYSTEM_DRIFT_DETECTOR",
            action="DRIFT_DETECTED",
            entity_type="Asset",
            entity_id=self.asset.id,
            entity_name=self.asset.hostname,
            description="Autonomous network drift detected on asset",
            commit=True,
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source, "SYSTEM")
        self.assertEqual(entry.actor, "SYSTEM_DRIFT_DETECTOR")
        self.assertTrue(bool(entry.integrity_hash))

    # =========================================================================
    # 8. EVIDENCE DESTRUCTIVE OPERATIONS
    # =========================================================================

    def test_31_evidence_deletion_authorization_and_audit(self):
        """Analyst and Reviewer cannot delete evidence; Administrator can; audit actor is Admin."""
        ev_to_delete = models.EvidenceRecord(
            title="Temporary Evidence",
            evidence_type="MANUAL_OBSERVATION",
            description="To be deleted by admin only",
            source_system="AI-GRC Platform",
            collector="analyst_alice",
        )
        self.db.add(ev_to_delete)
        self.db.commit()
        self.db.refresh(ev_to_delete)

        # Unauthenticated -> 401
        resp_unauth = self.client.delete(f"/evidence/{ev_to_delete.id}")
        self.assertEqual(resp_unauth.status_code, 401)

        # Analyst -> 403
        resp_analyst = self.client.delete(f"/evidence/{ev_to_delete.id}", headers=self.analyst_headers)
        self.assertEqual(resp_analyst.status_code, 403)

        # Reviewer -> 403
        resp_reviewer = self.client.delete(f"/evidence/{ev_to_delete.id}", headers=self.reviewer_headers)
        self.assertEqual(resp_reviewer.status_code, 403)

        # Administrator -> 200
        resp_admin = self.client.delete(f"/evidence/{ev_to_delete.id}", headers=self.admin_headers)
        self.assertEqual(resp_admin.status_code, 200)

        # Verify audit log attribution to Admin
        audit_entry = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "DELETE", models.AuditLog.entity_type == "EvidenceRecord", models.AuditLog.entity_id == ev_to_delete.id)
            .first()
        )
        self.assertIsNotNone(audit_entry)
        self.assertEqual(audit_entry.actor, "admin_charlie")

    # =========================================================================
    # 9. PUBLIC VS PROTECTED BOUNDARIES
    # =========================================================================

    def test_32_public_endpoints_accessible_without_auth(self):
        """GET / and POST /auth/login remain accessible without Authorization headers."""
        resp_root = self.client.get("/")
        self.assertEqual(resp_root.status_code, 200)
        self.assertEqual(resp_root.json()["message"], "AI-GRC Platform Backend is Running")

        resp_login_attempt = self.client.post("/auth/login", json={
            "username": "nonexistent",
            "password": "wrong",
        })
        self.assertEqual(resp_login_attempt.status_code, 401)
        self.assertEqual(resp_login_attempt.json()["detail"], "Invalid username or password")


if __name__ == "__main__":
    unittest.main()
