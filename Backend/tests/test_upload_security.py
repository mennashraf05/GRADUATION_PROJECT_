import io
import sys
import unittest
from pathlib import Path

from werkzeug.datastructures import FileStorage


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from upload_security import validate_pcap_upload, validate_vault_upload  # noqa: E402


def _upload(filename: str, data: bytes, content_type: str | None = None) -> FileStorage:
    return FileStorage(
        stream=io.BytesIO(data),
        filename=filename,
        content_type=content_type,
    )


class UploadSecurityValidationTests(unittest.TestCase):
    def test_pcap_valid_classic_magic_is_accepted(self):
        file_storage = _upload("sample.pcap", b"\xd4\xc3\xb2\xa1pcap-body")

        result = validate_pcap_upload(file_storage, file_storage.filename)

        self.assertTrue(result["ok"])

    def test_pcapng_magic_is_accepted(self):
        file_storage = _upload("sample.pcapng", b"\x0a\x0d\x0d\x0apcapng-body")

        result = validate_pcap_upload(file_storage, file_storage.filename)

        self.assertTrue(result["ok"])

    def test_disguised_executable_pcap_is_rejected_safely(self):
        file_storage = _upload("sample.pcap", b"MZ\x90\x00not-a-pcap")

        result = validate_pcap_upload(file_storage, file_storage.filename)

        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "invalid_file_type")
        self.assertEqual(result["safe_reason"], "invalid_magic")
        self.assertNotIn("MZ", result["public_message"])

    def test_wrong_pcap_extension_is_rejected_even_with_valid_magic(self):
        file_storage = _upload("sample.exe", b"\xd4\xc3\xb2\xa1pcap-body")

        result = validate_pcap_upload(file_storage, file_storage.filename)

        self.assertFalse(result["ok"])
        self.assertEqual(result["safe_reason"], "invalid_extension")

    def test_empty_pcap_is_rejected(self):
        file_storage = _upload("empty.pcap", b"")

        result = validate_pcap_upload(file_storage, file_storage.filename)

        self.assertFalse(result["ok"])
        self.assertEqual(result["safe_reason"], "empty_file")

    def test_pcap_validation_resets_stream_before_processing(self):
        data = b"\xa1\xb2\xc3\xd4full-pcap-content"
        file_storage = _upload("sample.pcap", data)

        result = validate_pcap_upload(file_storage, file_storage.filename)

        self.assertTrue(result["ok"])
        self.assertEqual(file_storage.stream.read(), data)

    def test_vault_dangerous_extension_is_rejected_safely(self):
        for filename in ("malware.exe", "secret.env"):
            with self.subTest(filename=filename):
                file_storage = _upload(filename, b"plain text")

                result = validate_vault_upload(file_storage, file_storage.filename, {"txt", "pdf"})

                self.assertFalse(result["ok"])
                self.assertEqual(result["error_code"], "invalid_file_type")
                self.assertEqual(result["safe_reason"], "invalid_extension")
                self.assertNotIn(filename, result["public_message"])

    def test_vault_normal_text_file_is_accepted(self):
        file_storage = _upload("notes.txt", b"meeting notes\n")

        result = validate_vault_upload(file_storage, file_storage.filename, {"txt", "pdf"})

        self.assertTrue(result["ok"])

    def test_vault_normal_pdf_file_is_accepted(self):
        file_storage = _upload("sample.pdf", b"%PDF-1.7\nbody", "application/pdf")

        result = validate_vault_upload(file_storage, file_storage.filename, {"txt", "pdf"})

        self.assertTrue(result["ok"])

    def test_vault_path_traversal_filename_is_rejected(self):
        file_storage = _upload("../notes.txt", b"meeting notes\n")

        result = validate_vault_upload(file_storage, file_storage.filename, {"txt", "pdf"})

        self.assertFalse(result["ok"])
        self.assertEqual(result["safe_reason"], "invalid_filename")


if __name__ == "__main__":
    unittest.main()
