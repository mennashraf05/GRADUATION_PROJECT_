import tempfile
import unittest
from pathlib import Path

import sys


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from security_utils import ensure_path_within_directory, sanitize_csv_cell


class ExportHardeningTests(unittest.TestCase):
    def test_sanitize_csv_cell_prefixes_formula_values(self):
        self.assertEqual(sanitize_csv_cell("=cmd()"), "'=cmd()")
        self.assertEqual(sanitize_csv_cell("+SUM(A1:A2)"), "'+SUM(A1:A2)")
        self.assertEqual(sanitize_csv_cell("-10"), "'-10")
        self.assertEqual(sanitize_csv_cell("@payload"), "'@payload")
        self.assertEqual(sanitize_csv_cell("\tTabbed"), "'\tTabbed")

    def test_sanitize_csv_cell_preserves_normal_values_and_none(self):
        self.assertEqual(sanitize_csv_cell("Safe text"), "Safe text")
        self.assertEqual(sanitize_csv_cell(None), "")

    def test_path_inside_allowed_directory_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            report = base / "reports" / "report.pdf"
            report.parent.mkdir()
            report.write_bytes(b"%PDF")

            self.assertEqual(ensure_path_within_directory(report, base), report.resolve())

    def test_traversal_path_outside_allowed_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir()
            outside = Path(tmp) / "outside.pdf"
            outside.write_bytes(b"%PDF")

            with self.assertRaises(ValueError):
                ensure_path_within_directory(base / ".." / "outside.pdf", base)

    def test_absolute_path_outside_allowed_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            outside = Path(tmp) / "outside.pdf"
            base.mkdir()
            outside.write_bytes(b"%PDF")

            with self.assertRaises(ValueError):
                ensure_path_within_directory(outside, base)


if __name__ == "__main__":
    unittest.main()
