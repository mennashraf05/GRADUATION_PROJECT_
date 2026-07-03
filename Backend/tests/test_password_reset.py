import os
import sys
import unittest
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import check_password_hash, generate_password_hash


os.environ["RATELIMIT_FORGOT_PASSWORD"] = "100 per minute"
os.environ["RATELIMIT_RESET_PASSWORD"] = "100 per minute"

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import (  # noqa: E402
    PASSWORD_RESET_GENERIC_MESSAGE,
    PASSWORD_RESET_INVALID_MESSAGE,
    PASSWORD_RESET_SUCCESS_MESSAGE,
    PasswordResetToken,
    RefreshToken,
    User,
    _ensure_auth_security_schema_initialized,
    _password_reset_token_hash,
    app,
    db,
)


class PasswordResetFlowTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.email = f"reset-{uuid.uuid4().hex[:12]}@example.com"
        self.old_password = "OldPassword123!"
        with app.app_context():
            _ensure_auth_security_schema_initialized()
            self.user = User(
                email=self.email,
                full_name="Reset User",
                password_hash=generate_password_hash(self.old_password),
                is_email_verified=True,
            )
            db.session.add(self.user)
            db.session.commit()
            self.user_id = self.user.id

    def tearDown(self):
        with app.app_context():
            PasswordResetToken.query.filter_by(user_id=self.user_id).delete()
            RefreshToken.query.filter_by(user_id=self.user_id).delete()
            User.query.filter_by(id=self.user_id).delete()
            db.session.commit()

    def _create_reset_token(self, token="plain-reset-token", *, expires_delta=timedelta(minutes=30), used=False):
        now = datetime.now(UTC)
        with app.app_context():
            row = PasswordResetToken(
                user_id=self.user_id,
                token_hash=_password_reset_token_hash(token),
                expires_at=now + expires_delta,
                used_at=now if used else None,
                created_at=now,
                updated_at=now,
            )
            db.session.add(row)
            db.session.commit()
            return token

    def test_forgot_password_returns_generic_success_for_existing_email_and_stores_hashed_token(self):
        with patch("app.send_password_reset_email", return_value=True) as send_mail:
            response = self.client.post("/api/auth/forgot-password", json={"email": self.email})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["message"], PASSWORD_RESET_GENERIC_MESSAGE)
        self.assertTrue(send_mail.called)

        raw_token = send_mail.call_args.args[1]
        with app.app_context():
            rows = PasswordResetToken.query.filter_by(user_id=self.user_id, used_at=None).all()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].token_hash, _password_reset_token_hash(raw_token))
            self.assertNotEqual(rows[0].token_hash, raw_token)

    def test_forgot_password_returns_same_generic_success_for_missing_email(self):
        with patch("app.send_password_reset_email", return_value=True) as send_mail:
            response = self.client.post(
                "/api/auth/forgot-password",
                json={"email": "missing-reset-user@example.invalid"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["message"], PASSWORD_RESET_GENERIC_MESSAGE)
        self.assertFalse(send_mail.called)

    def test_reset_password_succeeds_with_valid_token_and_new_password_logs_in(self):
        token = self._create_reset_token()
        response = self.client.post(
            "/api/auth/reset-password",
            json={
                "token": token,
                "newPassword": "NewPassword123!",
                "confirmPassword": "NewPassword123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["message"], PASSWORD_RESET_SUCCESS_MESSAGE)

        with app.app_context():
            user = User.query.get(self.user_id)
            self.assertFalse(check_password_hash(user.password_hash, self.old_password))
            self.assertTrue(check_password_hash(user.password_hash, "NewPassword123!"))
            self.assertEqual(RefreshToken.query.filter_by(user_id=self.user_id).count(), 0)

        old_login = self.client.post(
            "/api/auth/login",
            json={"email": self.email, "password": self.old_password},
            environ_overrides={"REMOTE_ADDR": "198.51.100.30"},
        )
        new_login = self.client.post(
            "/api/auth/login",
            json={"email": self.email, "password": "NewPassword123!"},
            environ_overrides={"REMOTE_ADDR": "198.51.100.31"},
        )
        self.assertEqual(old_login.status_code, 401)
        self.assertEqual(new_login.status_code, 200)

    def test_reset_password_rejects_expired_used_mismatched_and_weak_passwords(self):
        expired_response = self.client.post(
            "/api/auth/reset-password",
            json={
                "token": self._create_reset_token("expired-token", expires_delta=timedelta(minutes=-1)),
                "newPassword": "NewPassword123!",
                "confirmPassword": "NewPassword123!",
            },
        )
        self.assertEqual(expired_response.status_code, 400)
        self.assertEqual(expired_response.get_json()["message"], PASSWORD_RESET_INVALID_MESSAGE)

        used_response = self.client.post(
            "/api/auth/reset-password",
            json={
                "token": self._create_reset_token("used-token", used=True),
                "newPassword": "NewPassword123!",
                "confirmPassword": "NewPassword123!",
            },
        )
        self.assertEqual(used_response.status_code, 400)
        self.assertEqual(used_response.get_json()["message"], PASSWORD_RESET_INVALID_MESSAGE)

        mismatch_response = self.client.post(
            "/api/auth/reset-password",
            json={
                "token": self._create_reset_token("mismatch-token"),
                "newPassword": "NewPassword123!",
                "confirmPassword": "DifferentPassword123!",
            },
        )
        self.assertEqual(mismatch_response.status_code, 400)
        self.assertEqual(mismatch_response.get_json()["message"], "Passwords do not match.")

        weak_response = self.client.post(
            "/api/auth/reset-password",
            json={
                "token": self._create_reset_token("weak-token"),
                "newPassword": "weak",
                "confirmPassword": "weak",
            },
        )
        self.assertEqual(weak_response.status_code, 400)
        self.assertIn("Password must", weak_response.get_json()["message"])


if __name__ == "__main__":
    unittest.main()
