import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = BACKEND_DIR.parent
FRONTEND_AUDIT_PAGE = (
    PROJECT_DIR
    / "Cybersecurity Dashboard Design"
    / "src"
    / "components"
    / "admin"
    / "AdminAuditTrailPage.tsx"
)

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as backend_app


class AdminAuditActivityModuleTests(unittest.TestCase):
    def test_admin_audit_module_mapping_accepts_connected_activity_modules(self):
        cases = {
            "password_checker": "Password Checker",
            "password": "Password Checker",
            "file_vault": "File Vault",
            "vault": "File Vault",
            "encrypted_file_vault": "File Vault",
            "identity_leak": "Identity Leak Monitor",
            "identity": "Identity Leak Monitor",
            "osint_monitor": "Identity Leak Monitor",
            "pcap_analysis": "PCAP Analysis",
            "pcap": "PCAP Analysis",
            "settings": "Settings",
        }
        for raw_module, expected_label in cases.items():
            with self.subTest(raw_module=raw_module):
                self.assertEqual(
                    backend_app._admin_audit_module_label(raw_module),
                    expected_label,
                )

    def test_frontend_module_mapping_includes_connected_activity_modules(self):
        source = FRONTEND_AUDIT_PAGE.read_text(encoding="utf-8")
        for module_key in ("password_checker", "file_vault", "identity_leak", "pcap_analysis", "settings"):
            with self.subTest(module_key=module_key):
                self.assertIn(module_key, source)

    def test_trusted_filter_options_exclude_ai_governance(self):
        self.assertNotIn("ai_governance", backend_app.ADMIN_AUDIT_TRUSTED_MODULE_OPTIONS)

    def test_pcap_route_contracts_still_exist(self):
        rules = {str(rule.rule): rule.endpoint for rule in backend_app.app.url_map.iter_rules()}
        for route in (
            "/pcap/analyze",
            "/pcap/analyze-local",
            "/pcap/status/<job_id>",
            "/pcap/result/<job_id>",
            "/pcap/report/<job_id>",
            "/job/<job_id>/export",
            "/api/pcap/cancel/<job_id>",
            "/api/pcap/alerts",
        ):
            with self.subTest(route=route):
                self.assertIn(route, rules)


if __name__ == "__main__":
    unittest.main()
