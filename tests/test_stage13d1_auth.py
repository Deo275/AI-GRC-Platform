"""Stage 13D.1 Authentication Foundation Test Suite.

Verifies:
1.  Password hashing does not return plaintext.
2.  Password verification succeeds for the correct password.
3.  Password verification fails for an incorrect password.
4.  Login succeeds with valid credentials.
5.  Login fails with incorrect credentials.
6.  Login does not reveal whether a username exists.
7.  JWT contains expected claims.
8.  Expired JWT is rejected.
9.  Invalid JWT signature is rejected.
10. Missing Authorization header returns 401.
11. GET /auth/me returns the authenticated user.
12. Inactive user cannot authenticate.
13. Bootstrap disabled creates no demo users.
14. Bootstrap enabled with configured passwords creates users.
15. Bootstrap never overwrites existing users.
16. Bootstrap fails safely if enabled without passwords.
"""

import os
import sys
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
    get_jwt_secret_key,
    JWT_ALGORITHM,
)
from auth.bootstrap import run_dev_bootstrap

TEST_SECRET = "test-jwt-secret-key-at-least-32-chars-long-123456"


class TestStage13D1AuthFoundation(unittest.TestCase):
    """Unit and integration tests for Stage 13D.1 Authentication Foundation."""

    def setUp(self):
        # Configure test JWT secret
        self.env_patcher = mock.patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET})
        self.env_patcher.start()

        # Isolated SQLite in-memory database
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        models.Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.SessionLocal()

        # Patch SessionLocal across main and auth dependencies
        self.session_patcher = mock.patch("main.SessionLocal", side_effect=lambda: self.SessionLocal())
        self.session_patcher.start()
        self.auth_session_patcher = mock.patch("auth.dependencies.SessionLocal", side_effect=lambda: self.SessionLocal())
        self.auth_session_patcher.start()

        self.client = TestClient(main.app)

    def tearDown(self):
        self.auth_session_patcher.stop()
        self.session_patcher.stop()
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)
        self.env_patcher.stop()

    # -------------------------------------------------------------------------
    # 1. Password Hashing & Verification
    # -------------------------------------------------------------------------

    def test_01_password_hashing_does_not_return_plaintext(self):
        """1. Password hashing must use Argon2id and never return plaintext."""
        password = "SuperSecretPassword123!"
        hashed = hash_password(password)

        self.assertNotEqual(password, hashed)
        self.assertNotIn(password, hashed)
        self.assertTrue(hashed.startswith("$argon2id$"))

    def test_02_password_verification_succeeds_for_correct_password(self):
        """2. Password verification succeeds for the exact plaintext password."""
        password = "CorrectHorseBatteryStaple"
        hashed = hash_password(password)

        self.assertTrue(verify_password(password, hashed))

    def test_03_password_verification_fails_for_incorrect_password(self):
        """3. Password verification fails for an incorrect password or malformed hash."""
        password = "CorrectPassword"
        hashed = hash_password(password)

        self.assertFalse(verify_password("WrongPassword", hashed))
        self.assertFalse(verify_password("", hashed))
        self.assertFalse(verify_password(password, ""))
        self.assertFalse(verify_password(password, "malformed$hash$value"))

    # -------------------------------------------------------------------------
    # 2. Login Flow & Credential Validation
    # -------------------------------------------------------------------------

    def test_04_login_succeeds_with_valid_credentials(self):
        """4. Login succeeds with valid credentials, returning token and updating last_login_at."""
        raw_password = "ValidPassword123!"
        user = models.User(
            username="analyst_test",
            email="analyst@example.com",
            display_name="Test Analyst",
            password_hash=hash_password(raw_password),
            role="Security Analyst",
            is_active=True,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        self.assertIsNone(user.last_login_at)

        response = self.client.post(
            "/auth/login",
            json={"username": "analyst_test", "password": raw_password},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["expires_in"], 3600)
        self.assertIn("user", data)
        self.assertEqual(data["user"]["username"], "analyst_test")
        self.assertEqual(data["user"]["email"], "analyst@example.com")
        self.assertEqual(data["user"]["role"], "Security Analyst")
        self.assertNotIn("password_hash", data["user"])

        # Verify last_login_at was updated in database
        self.db.refresh(user)
        self.assertIsNotNone(user.last_login_at)

        # Also verify login with email
        response_email = self.client.post(
            "/auth/login",
            json={"username": "analyst@example.com", "password": raw_password},
        )
        self.assertEqual(response_email.status_code, 200)

    def test_05_login_fails_with_incorrect_credentials(self):
        """5. Login fails with incorrect password returning HTTP 401."""
        raw_password = "ValidPassword123!"
        user = models.User(
            username="analyst_wrong",
            email="analyst_wrong@example.com",
            display_name="Test Analyst",
            password_hash=hash_password(raw_password),
            role="Security Analyst",
            is_active=True,
        )
        self.db.add(user)
        self.db.commit()

        response = self.client.post(
            "/auth/login",
            json={"username": "analyst_wrong", "password": "WrongPassword!"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Invalid username or password")
        self.db.refresh(user)
        self.assertIsNone(user.last_login_at)

    def test_06_login_does_not_reveal_whether_username_exists(self):
        """6. Login returns identical error for non-existent user and bad password."""
        user = models.User(
            username="existing_user",
            email="existing@example.com",
            display_name="Existing User",
            password_hash=hash_password("Password123!"),
            role="GRC Reviewer",
            is_active=True,
        )
        self.db.add(user)
        self.db.commit()

        # Case A: User does not exist
        res_nonexistent = self.client.post(
            "/auth/login",
            json={"username": "non_existent_user_999", "password": "AnyPassword!"},
        )

        # Case B: User exists, wrong password
        res_wrong_pw = self.client.post(
            "/auth/login",
            json={"username": "existing_user", "password": "WrongPassword!"},
        )

        self.assertEqual(res_nonexistent.status_code, 401)
        self.assertEqual(res_wrong_pw.status_code, 401)
        self.assertEqual(res_nonexistent.json(), res_wrong_pw.json())
        self.assertEqual(res_nonexistent.json()["detail"], "Invalid username or password")

    # -------------------------------------------------------------------------
    # 3. JWT Claims, Expiration, and Validation
    # -------------------------------------------------------------------------

    def test_07_jwt_contains_expected_claims(self):
        """7. JWT contains expected claims: sub, username, role, iat, exp."""
        token = create_access_token(
            subject=101,
            username="sec_lead",
            role="Administrator",
        )

        payload = decode_access_token(token)
        self.assertEqual(payload["sub"], "101")
        self.assertEqual(payload["username"], "sec_lead")
        self.assertEqual(payload["role"], "Administrator")
        self.assertIn("iat", payload)
        self.assertIn("exp", payload)
        self.assertGreater(payload["exp"], payload["iat"])

    def test_08_expired_jwt_is_rejected(self):
        """8. Expired JWT is rejected with HTTP 401."""
        expired_token = create_access_token(
            subject=1,
            username="analyst_expired",
            role="Security Analyst",
            expires_delta=datetime.timedelta(seconds=-10),
        )

        # Direct decode raises ExpiredSignatureError
        with self.assertRaises(jwt.ExpiredSignatureError):
            decode_access_token(expired_token)

        # API endpoint rejects expired token
        response = self.client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn("expired", response.json()["detail"].lower())

    def test_09_invalid_jwt_signature_is_rejected(self):
        """9. JWT with invalid/forged signature is rejected with HTTP 401."""
        different_secret = "different-secret-key-32-chars-long-987654321"
        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "sub": "1",
            "username": "attacker",
            "role": "Administrator",
            "iat": now,
            "exp": now + datetime.timedelta(hours=1),
        }
        forged_token = jwt.encode(payload, different_secret, algorithm="HS256")

        response = self.client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {forged_token}"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn("invalid", response.json()["detail"].lower())

    def test_10_missing_authorization_header_returns_401(self):
        """10. Missing or malformed Authorization header returns HTTP 401."""
        # Missing header
        res1 = self.client.get("/auth/me")
        self.assertEqual(res1.status_code, 401)
        self.assertIn("Missing Authorization header", res1.json()["detail"])

        # Malformed header: Basic scheme
        res2 = self.client.get("/auth/me", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        self.assertEqual(res2.status_code, 401)

        # Malformed header: Bearer without token
        res3 = self.client.get("/auth/me", headers={"Authorization": "Bearer"})
        self.assertEqual(res3.status_code, 401)

    def test_11_get_auth_me_returns_authenticated_user(self):
        """11. GET /auth/me returns the authenticated user profile."""
        user = models.User(
            username="reviewer_me",
            email="reviewer_me@example.com",
            display_name="Lead Reviewer",
            password_hash=hash_password("ReviewerPass123!"),
            role="GRC Reviewer",
            is_active=True,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        token = create_access_token(
            subject=user.id,
            username=user.username,
            role=user.role,
        )

        response = self.client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["id"], user.id)
        self.assertEqual(data["username"], "reviewer_me")
        self.assertEqual(data["email"], "reviewer_me@example.com")
        self.assertEqual(data["display_name"], "Lead Reviewer")
        self.assertEqual(data["role"], "GRC Reviewer")
        self.assertTrue(data["is_active"])
        self.assertNotIn("password_hash", data)

    def test_12_inactive_user_cannot_authenticate(self):
        """12. Inactive user cannot log in or access protected endpoints."""
        raw_pw = "InactivePass123!"
        user = models.User(
            username="disabled_analyst",
            email="disabled@example.com",
            display_name="Disabled Analyst",
            password_hash=hash_password(raw_pw),
            role="Security Analyst",
            is_active=False,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        # Login attempt fails
        login_res = self.client.post(
            "/auth/login",
            json={"username": "disabled_analyst", "password": raw_pw},
        )
        self.assertEqual(login_res.status_code, 401)

        # Even with a pre-existing token, /auth/me rejects inactive account
        token = create_access_token(
            subject=user.id,
            username=user.username,
            role=user.role,
        )
        me_res = self.client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(me_res.status_code, 401)
        self.assertIn("inactive", me_res.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 4. Opt-in Development Bootstrap
    # -------------------------------------------------------------------------

    def test_13_bootstrap_disabled_creates_no_demo_users(self):
        """13. Development bootstrap creates 0 demo users when disabled (default)."""
        with mock.patch.dict(os.environ, {"AUTH_BOOTSTRAP_ENABLED": "false"}):
            created = run_dev_bootstrap(self.db)
            self.assertEqual(created, 0)

        users = self.db.query(models.User).all()
        self.assertEqual(len(users), 0)

    def test_14_bootstrap_enabled_with_configured_passwords_creates_users(self):
        """14. Bootstrap enabled in development creates deterministic demo users."""
        env_vars = {
            "AUTH_BOOTSTRAP_ENABLED": "true",
            "ENV": "development",
            "AUTH_BOOTSTRAP_ANALYST_PASSWORD": "AnalystDemoSecret123!",
            "AUTH_BOOTSTRAP_REVIEWER_PASSWORD": "ReviewerDemoSecret123!",
            "AUTH_BOOTSTRAP_ADMIN_PASSWORD": "AdminDemoSecret123!",
        }
        with mock.patch.dict(os.environ, env_vars):
            created = run_dev_bootstrap(self.db)
            self.assertEqual(created, 3)

        analyst = self.db.query(models.User).filter(models.User.username == "analyst").first()
        self.assertIsNotNone(analyst)
        self.assertEqual(analyst.role, "Security Analyst")
        self.assertTrue(verify_password("AnalystDemoSecret123!", analyst.password_hash))

        reviewer = self.db.query(models.User).filter(models.User.username == "reviewer").first()
        self.assertIsNotNone(reviewer)
        self.assertEqual(reviewer.role, "GRC Reviewer")
        self.assertTrue(verify_password("ReviewerDemoSecret123!", reviewer.password_hash))

        admin = self.db.query(models.User).filter(models.User.username == "admin").first()
        self.assertIsNotNone(admin)
        self.assertEqual(admin.role, "Administrator")
        self.assertTrue(verify_password("AdminDemoSecret123!", admin.password_hash))

        # Verify login endpoint succeeds for bootstrapped account
        res = self.client.post(
            "/auth/login",
            json={"username": "analyst", "password": "AnalystDemoSecret123!"},
        )
        self.assertEqual(res.status_code, 200)

    def test_15_bootstrap_never_overwrites_existing_users(self):
        """15. Bootstrap never overwrites existing users or their credentials."""
        # Pre-seed analyst with custom display name and custom password
        original_pw = "CustomOriginalPassword!"
        pre_existing = models.User(
            username="analyst",
            email="analyst@custom.org",
            display_name="Custom Analyst Name",
            password_hash=hash_password(original_pw),
            role="Security Analyst",
            is_active=True,
        )
        self.db.add(pre_existing)
        self.db.commit()

        env_vars = {
            "AUTH_BOOTSTRAP_ENABLED": "true",
            "ENV": "development",
            "AUTH_BOOTSTRAP_ANALYST_PASSWORD": "DifferentBootstrapPassword123!",
            "AUTH_BOOTSTRAP_REVIEWER_PASSWORD": "ReviewerDemoSecret123!",
            "AUTH_BOOTSTRAP_ADMIN_PASSWORD": "AdminDemoSecret123!",
        }
        with mock.patch.dict(os.environ, env_vars):
            created = run_dev_bootstrap(self.db)
            self.assertEqual(created, 2)  # Only reviewer and admin created

        # Verify original analyst was NOT modified
        refreshed = self.db.query(models.User).filter(models.User.username == "analyst").first()
        self.assertEqual(refreshed.display_name, "Custom Analyst Name")
        self.assertEqual(refreshed.email, "analyst@custom.org")
        self.assertTrue(verify_password(original_pw, refreshed.password_hash))
        self.assertFalse(verify_password("DifferentBootstrapPassword123!", refreshed.password_hash))

    def test_16_bootstrap_fails_safely_when_passwords_are_missing(self):
        """16. Bootstrap fails loudly and creates no users if passwords are not configured."""
        env_vars = {
            "AUTH_BOOTSTRAP_ENABLED": "true",
            "ENV": "development",
            "AUTH_BOOTSTRAP_ANALYST_PASSWORD": "",
            "AUTH_BOOTSTRAP_REVIEWER_PASSWORD": "ReviewerSecret!",
            "AUTH_BOOTSTRAP_ADMIN_PASSWORD": "",
        }
        with mock.patch.dict(os.environ, env_vars):
            with self.assertRaises(RuntimeError) as ctx:
                run_dev_bootstrap(self.db)
            self.assertIn("required environment password variables are missing", str(ctx.exception))

        users = self.db.query(models.User).all()
        self.assertEqual(len(users), 0)


if __name__ == "__main__":
    unittest.main()
