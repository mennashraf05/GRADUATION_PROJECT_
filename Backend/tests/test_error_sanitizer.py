import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import app  # noqa: E402


def _raise_sensitive_test_error():
    raise Exception(r"C:\secret\path\api_key=123 Traceback provider failure")


class ErrorSanitizerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        endpoint = "_test_sanitized_error"
        if endpoint not in app.view_functions:
            app.add_url_rule(
                "/__test/sanitized-error",
                endpoint,
                _raise_sensitive_test_error,
                methods=["GET"],
            )

    def test_unhandled_errors_do_not_leak_exception_details(self):
        client = app.test_client()
        response = client.get("/__test/sanitized-error")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 500)
        self.assertNotIn(r"C:\\", body)
        self.assertNotIn(r"C:\secret", body)
        self.assertNotIn("/mnt/", body)
        self.assertNotIn("api_key", body)
        self.assertNotIn("Traceback", body)
        self.assertNotIn("provider failure", body)
        self.assertEqual(
            response.get_json(silent=True),
            {
                "success": False,
                "error": "internal_error",
                "message": "Something went wrong. Please try again later.",
            },
        )


if __name__ == "__main__":
    unittest.main()
