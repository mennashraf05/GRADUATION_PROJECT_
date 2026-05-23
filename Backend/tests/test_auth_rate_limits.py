import os
import sys
import unittest
from pathlib import Path


os.environ["RATELIMIT_LOGIN"] = "5 per minute"
os.environ["RATELIMIT_SIGNUP"] = "3 per minute"
os.environ["RATELIMIT_ADMIN_LOGIN"] = "3 per minute"

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import app  # noqa: E402


RATE_LIMIT_RESPONSE = {
    "error": "rate_limit_exceeded",
    "message": "Too many requests. Please try again later.",
}


class AuthRateLimitTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def post_from_ip(self, path, ip, payload):
        return self.client.post(path, json=payload, environ_overrides={"REMOTE_ADDR": ip})

    def test_invalid_login_attempts_are_rate_limited(self):
        statuses = []
        bodies = []
        for _ in range(6):
            response = self.post_from_ip(
                "/api/auth/login",
                "198.51.100.10",
                {"email": "missing-user-rate-test@example.invalid", "password": "wrong-password"},
            )
            statuses.append(response.status_code)
            bodies.append(response.get_json(silent=True))

        self.assertEqual(statuses[:5], [401, 401, 401, 401, 401])
        self.assertEqual(statuses[5], 429)
        self.assertEqual(bodies[5], RATE_LIMIT_RESPONSE)

    def test_signup_attempts_are_rate_limited(self):
        statuses = []
        bodies = []
        for _ in range(4):
            response = self.post_from_ip("/api/auth/signup", "198.51.100.11", {})
            statuses.append(response.status_code)
            bodies.append(response.get_json(silent=True))

        self.assertEqual(statuses[:3], [400, 400, 400])
        self.assertEqual(statuses[3], 429)
        self.assertEqual(bodies[3], RATE_LIMIT_RESPONSE)

    def test_admin_login_attempts_are_rate_limited(self):
        statuses = []
        bodies = []
        for _ in range(4):
            response = self.post_from_ip("/api/admin/auth/login", "198.51.100.12", {})
            statuses.append(response.status_code)
            bodies.append(response.get_json(silent=True))

        self.assertEqual(statuses[:3], [400, 400, 400])
        self.assertEqual(statuses[3], 429)
        self.assertEqual(bodies[3], RATE_LIMIT_RESPONSE)


if __name__ == "__main__":
    unittest.main()
