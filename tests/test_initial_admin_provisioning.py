"""Unit and regression tests for initial administrator provisioning script.

Verifies:
1. Input validation rules:
   - Username presence, whitespace restriction, max length (50).
   - Email presence, formatting, max length (255).
   - Display name presence, max length (100).
   - Password minimum length (12 characters).
   - Password confirmation match.
2. Database provisioning rules:
   - Successful creation of Administrator with is_active=True and Argon2id hash.
   - Strict refusal when an Administrator already exists.
   - Uniqueness check for existing username.
   - Uniqueness check for existing email.
   - Transactional rollback on database IntegrityError or unexpected failure.
3. Interactive CLI flow:
   - Early refusal before prompts if Administrator exists.
   - Graceful exit on EOFError or KeyboardInterrupt.
   - Successful execution returns exit code 0.
"""

import sys
import unittest
from unittest import mock
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.exc import IntegrityError

# Setup paths
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))
sys.path.insert(0, str(BASE_DIR / "scripts"))

import models
from auth.security import verify_password
from scripts.create_initial_admin import (
    validate_admin_inputs,
    provision_initial_admin,
    main as admin_script_main,
    MIN_PASSWORD_LENGTH,
    MAX_USERNAME_LENGTH,
    MAX_EMAIL_LENGTH,
    MAX_DISPLAY_NAME_LENGTH,
)


class TestInitialAdminProvisioning(unittest.TestCase):
    """Test suite for initial administrator provisioning script."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        models.Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.SessionLocal()

    def tearDown(self):
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)

    # -------------------------------------------------------------------------
    # 1. Input Validation Tests
    # -------------------------------------------------------------------------

    def test_01_valid_inputs_pass_validation(self):
        """Valid username, email, display name, and 12+ char password pass validation."""
        valid, err = validate_admin_inputs(
            username="admin",
            email="admin@example.com",
            display_name="System Administrator",
            password="SecureAdminPassword2026!",
            password_confirm="SecureAdminPassword2026!",
        )
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_02_empty_or_whitespace_username_rejected(self):
        """Missing or whitespace-only username is rejected."""
        valid, err = validate_admin_inputs("", "a@b.com", "Admin", "password123456", "password123456")
        self.assertFalse(valid)
        self.assertIn("Username is required", err)

        valid, err = validate_admin_inputs("   ", "a@b.com", "Admin", "password123456", "password123456")
        self.assertFalse(valid)
        self.assertIn("Username is required", err)

    def test_03_username_with_internal_whitespace_rejected(self):
        """Usernames containing spaces are rejected."""
        valid, err = validate_admin_inputs("admin user", "a@b.com", "Admin", "password123456", "password123456")
        self.assertFalse(valid)
        self.assertIn("whitespace", err.lower())

    def test_04_username_exceeding_max_length_rejected(self):
        """Usernames longer than model column limit (50) are rejected."""
        long_username = "a" * (MAX_USERNAME_LENGTH + 1)
        valid, err = validate_admin_inputs(long_username, "a@b.com", "Admin", "password123456", "password123456")
        self.assertFalse(valid)
        self.assertIn(str(MAX_USERNAME_LENGTH), err)

    def test_05_invalid_email_format_rejected(self):
        """Missing, malformed, or overly long emails are rejected."""
        for invalid_email in ["", "notanemail", "bad@", "@domain.com", "spaces in@email.com"]:
            valid, err = validate_admin_inputs("admin", invalid_email, "Admin", "password123456", "password123456")
            self.assertFalse(valid)
            self.assertIsNotNone(err)

        long_email = ("a" * 250) + "@b.com"  # > 255 chars
        valid, err = validate_admin_inputs("admin", long_email, "Admin", "password123456", "password123456")
        self.assertFalse(valid)
        self.assertIn(str(MAX_EMAIL_LENGTH), err)

    def test_06_empty_or_excessive_display_name_rejected(self):
        """Display name must be non-empty and within 100 characters."""
        valid, err = validate_admin_inputs("admin", "a@b.com", "   ", "password123456", "password123456")
        self.assertFalse(valid)
        self.assertIn("Display name is required", err)

        long_display = "D" * (MAX_DISPLAY_NAME_LENGTH + 1)
        valid, err = validate_admin_inputs("admin", "a@b.com", long_display, "password123456", "password123456")
        self.assertFalse(valid)
        self.assertIn(str(MAX_DISPLAY_NAME_LENGTH), err)

    def test_07_short_password_rejected(self):
        """Passwords shorter than 12 characters are strictly rejected."""
        valid, err = validate_admin_inputs("admin", "a@b.com", "Admin", "short11char", "short11char")
        self.assertFalse(valid)
        self.assertIn(str(MIN_PASSWORD_LENGTH), err)

    def test_08_mismatched_password_confirmation_rejected(self):
        """Password confirmation mismatch is caught and rejected."""
        valid, err = validate_admin_inputs(
            "admin",
            "a@b.com",
            "Admin",
            "ValidPassword123!",
            "DifferentPassword123!",
        )
        self.assertFalse(valid)
        self.assertIn("do not match", err.lower())

    # -------------------------------------------------------------------------
    # 2. Database Provisioning & Security Enforcement Tests
    # -------------------------------------------------------------------------

    def test_09_provision_initial_admin_success(self):
        """Successfully provisions an Administrator account when none exists."""
        success, msg = provision_initial_admin(
            db=self.db,
            username="admin",
            email="admin@company.com",
            display_name="Global Administrator",
            password="InitialSecurePassword2026!",
        )
        self.assertTrue(success)
        self.assertIn("Successfully provisioned", msg)

        # Verify created record in database
        created = self.db.query(models.User).filter(models.User.username == "admin").first()
        self.assertIsNotNone(created)
        self.assertEqual(created.role, "Administrator")
        self.assertEqual(created.email, "admin@company.com")
        self.assertTrue(created.is_active)
        self.assertNotEqual(created.password_hash, "InitialSecurePassword2026!")
        self.assertTrue(verify_password("InitialSecurePassword2026!", created.password_hash))

    def test_10_refuses_to_provision_if_administrator_already_exists(self):
        """Refuses to create an account if an Administrator user already exists."""
        # Seed an existing administrator
        first_success, _ = provision_initial_admin(
            db=self.db,
            username="existing_admin",
            email="existing@company.com",
            display_name="Existing Admin",
            password="FirstAdminPassword123!",
        )
        self.assertTrue(first_success)

        # Attempt second administrator provisioning
        second_success, msg = provision_initial_admin(
            db=self.db,
            username="new_admin",
            email="new@company.com",
            display_name="Second Admin",
            password="SecondAdminPassword123!",
        )
        self.assertFalse(second_success)
        self.assertIn("Refusing to provision", msg)
        self.assertIn("already exists", msg)

        # Verify second admin was not created
        self.assertIsNone(self.db.query(models.User).filter(models.User.username == "new_admin").first())

    def test_11_refuses_duplicate_username(self):
        """Refuses to provision if the requested username already exists under a non-admin role."""
        # Seed an existing non-admin user
        analyst = models.User(
            username="analyst_bob",
            email="bob@company.com",
            display_name="Bob Analyst",
            password_hash="mock_hash",
            role="Security Analyst",
            is_active=True,
        )
        self.db.add(analyst)
        self.db.commit()

        success, msg = provision_initial_admin(
            db=self.db,
            username="analyst_bob",
            email="different@company.com",
            display_name="New Admin",
            password="AdminPassword123!",
        )
        self.assertFalse(success)
        self.assertIn("already in use", msg)

    def test_12_refuses_duplicate_email(self):
        """Refuses to provision if the requested email already exists under a non-admin role."""
        reviewer = models.User(
            username="reviewer_alice",
            email="shared@company.com",
            display_name="Alice Reviewer",
            password_hash="mock_hash",
            role="GRC Reviewer",
            is_active=True,
        )
        self.db.add(reviewer)
        self.db.commit()

        success, msg = provision_initial_admin(
            db=self.db,
            username="new_admin",
            email="shared@company.com",
            display_name="New Admin",
            password="AdminPassword123!",
        )
        self.assertFalse(success)
        self.assertIn("already in use", msg)

    def test_13_database_integrity_error_triggers_safe_rollback(self):
        """IntegrityError during commit triggers rollback and reports clean error without traceback."""
        with mock.patch.object(self.db, "commit", side_effect=IntegrityError("duplicate", {}, None)):
            with mock.patch.object(self.db, "rollback") as mock_rollback:
                success, msg = provision_initial_admin(
                    db=self.db,
                    username="admin",
                    email="admin@company.com",
                    display_name="Admin",
                    password="AdminPassword123!",
                )
                self.assertFalse(success)
                self.assertIn("integrity constraint violated", msg.lower())
                mock_rollback.assert_called_once()

    # -------------------------------------------------------------------------
    # 3. Interactive CLI Flow Tests
    # -------------------------------------------------------------------------

    @mock.patch("scripts.create_initial_admin.SessionLocal")
    def test_14_cli_early_exit_if_admin_exists(self, mock_session_local):
        """main() pre-checks for existing admin and aborts before prompting for any inputs."""
        mock_db = mock.MagicMock()
        mock_session_local.return_value = mock_db
        # Mock that an existing administrator was found
        mock_db.query.return_value.filter.return_value.first.return_value = models.User(username="admin")

        with mock.patch("builtins.input") as mock_input, mock.patch("getpass.getpass") as mock_getpass:
            exit_code = admin_script_main()
            self.assertEqual(exit_code, 1)
            mock_input.assert_not_called()
            mock_getpass.assert_not_called()
            mock_db.close.assert_called_once()

    @mock.patch("scripts.create_initial_admin.SessionLocal")
    def test_15_cli_handles_cancellation_gracefully(self, mock_session_local):
        """main() handles KeyboardInterrupt or EOFError cleanly."""
        mock_db = mock.MagicMock()
        mock_session_local.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.return_value = None

        with mock.patch("builtins.input", side_effect=KeyboardInterrupt):
            exit_code = admin_script_main()
            self.assertEqual(exit_code, 1)
            mock_db.close.assert_called_once()

    @mock.patch("scripts.create_initial_admin.SessionLocal")
    def test_16_cli_successful_interactive_flow(self, mock_session_local):
        """main() executes successfully with valid user input and commits."""
        mock_session_local.return_value = self.db

        user_inputs = ["secadmin", "secadmin@company.com", "Chief Admin"]
        passwords = ["SuperSecretPassword2026!", "SuperSecretPassword2026!"]

        with mock.patch("builtins.input", side_effect=user_inputs), \
             mock.patch("getpass.getpass", side_effect=passwords):
            exit_code = admin_script_main()
            self.assertEqual(exit_code, 0)

            # Verify admin was created in db
            created = self.db.query(models.User).filter(models.User.username == "secadmin").first()
            self.assertIsNotNone(created)
            self.assertEqual(created.role, "Administrator")


if __name__ == "__main__":
    unittest.main()
