import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as app_module  # noqa: E402


class DummyResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class SecuritySimulationTest(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        self.previous_waf_base = os.environ.get("WAF_BASE_URL")
        os.environ["WAF_BASE_URL"] = "https://localhost:8081"
        token = app_module.create_admin_access_token(app_module.ADMIN_EMAIL)
        self.headers = {"Authorization": f"Bearer {token}"}

    def tearDown(self):
        if self.previous_waf_base is None:
            os.environ.pop("WAF_BASE_URL", None)
        else:
            os.environ["WAF_BASE_URL"] = self.previous_waf_base

    def test_tests_endpoint_requires_admin(self):
        response = self.client.get("/api/admin/security-simulation/tests")
        self.assertEqual(response.status_code, 401)

    def test_tests_endpoint_returns_allowlist(self):
        response = self.client.get(
            "/api/admin/security-simulation/tests",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["success"])
        test_ids = {item["test_id"] for item in payload["tests"]}
        self.assertIn("sqli_login", test_ids)
        self.assertIn("brute_force_login", test_ids)
        self.assertNotIn("custom", test_ids)

    def test_run_rejects_unknown_test_id(self):
        response = self.client.post(
            "/api/admin/security-simulation/run",
            json={"test_id": "custom"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertEqual(payload["error"], "invalid_test_id")

    def test_run_uses_predefined_request_only(self):
        with patch.object(app_module.requests, "request", return_value=DummyResponse(403)) as mocked:
            response = self.client.post(
                "/api/admin/security-simulation/run",
                json={
                    "test_id": "sqli_login",
                    "url": "https://evil.example",
                    "payload": "ignored",
                },
                headers=self.headers,
            )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["passed"])
        mocked.assert_called_once()
        _, called_url = mocked.call_args.args[:2]
        self.assertEqual(called_url, "https://localhost:8081/api/auth/login")
        self.assertNotIn("evil.example", called_url)


if __name__ == "__main__":
    unittest.main()
