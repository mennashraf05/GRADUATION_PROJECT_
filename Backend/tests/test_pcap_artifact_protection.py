import json
import shutil
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as backend_app


class PcapArtifactProtectionTests(unittest.TestCase):
    def setUp(self):
        self.job_ids: list[str] = []
        self.artifact_paths: list[Path] = []

    def tearDown(self):
        for job_id in self.job_ids:
            backend_app.jobs.forget(job_id)
            shutil.rmtree(Path(backend_app.JOBS_FOLDER) / job_id, ignore_errors=True)
        for path in self.artifact_paths:
            for candidate in (path, path.with_name(f"{path.name}.enc")):
                if candidate.exists():
                    candidate.unlink()

    def _create_terminal_job_with_artifacts(self):
        raw_dir = Path(backend_app.BASE_RUN_FOLDER)
        raw_dir.mkdir(parents=True, exist_ok=True)
        source_pcap = raw_dir / f"artifact-protection-{uuid.uuid4().hex}.pcap"
        source_csv = raw_dir / f"artifact-protection-{uuid.uuid4().hex}_packets.csv"
        self.artifact_paths.extend([source_pcap, source_csv])
        source_pcap.write_bytes(b"\xd4\xc3\xb2\xa1raw-pcap-bytes")
        source_csv.write_text("frame.time_epoch,ip.src,ip.dst\n1,10.0.0.1,10.0.0.2\n", encoding="utf-8")

        state = backend_app.jobs.create(
            upload_path=str(source_pcap),
            owner_user_id=123,
            owner_user_scope="email:artifact@example.com",
            analysis_key=f"artifact-protection-{uuid.uuid4().hex}",
        )
        self.job_ids.append(state.job_id)
        job_dir = Path(backend_app.JOBS_FOLDER) / state.job_id
        report_path = job_dir / "report.json"
        report_path.write_text(
            json.dumps({"meta": {"pipeline": {"analysis_mode": "base_only"}}, "summary": {}}),
            encoding="utf-8",
        )
        backend_app.jobs.update(
            state.job_id,
            status="done",
            finished_at="2026-04-07T00:00:00+00:00",
            progress=100,
            message="Completed",
            packet_csv_path=str(source_csv),
            report_path=str(report_path),
        )
        return backend_app.jobs.get(state.job_id), source_pcap, source_csv, report_path

    def test_feature_flag_off_leaves_artifacts_unchanged(self):
        state, source_pcap, source_csv, report_path = self._create_terminal_job_with_artifacts()

        with patch.object(backend_app, "PCAP_PROTECT_ARTIFACTS", False):
            metadata = backend_app._protect_pcap_artifacts_after_terminal_state(state)

        self.assertIsNone(metadata)
        self.assertTrue(source_pcap.exists())
        self.assertTrue(source_csv.exists())
        self.assertFalse(source_pcap.with_name(f"{source_pcap.name}.enc").exists())
        self.assertFalse(source_csv.with_name(f"{source_csv.name}.enc").exists())
        self.assertIsNone(getattr(backend_app.jobs.get(state.job_id), "artifact_protection", None))
        self.assertTrue(report_path.exists())
        self.assertIsInstance(json.loads(report_path.read_text(encoding="utf-8")), dict)

    def test_missing_key_records_safe_metadata_without_encrypting(self):
        state, source_pcap, source_csv, report_path = self._create_terminal_job_with_artifacts()

        with patch.object(backend_app, "PCAP_PROTECT_ARTIFACTS", True), patch.object(
            backend_app, "PCAP_ARTIFACT_ENCRYPTION_KEY", ""
        ), patch.object(backend_app, "PCAP_ARTIFACT_ENCRYPTION_MODE", "copy_encrypt_verify"):
            metadata = backend_app._protect_pcap_artifacts_after_terminal_state(state)

        self.assertIsInstance(metadata, dict)
        self.assertEqual(metadata.get("enabled"), False)
        self.assertEqual(metadata.get("reason"), "missing_encryption_key")
        self.assertTrue(source_pcap.exists())
        self.assertTrue(source_csv.exists())

        updated_state = backend_app.jobs.get(state.job_id)
        self.assertEqual(updated_state.artifact_protection.get("reason"), "missing_encryption_key")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(
            report["meta"]["artifact_protection"]["reason"],
            "missing_encryption_key",
        )

    def test_copy_encrypt_verify_delete_protects_raw_pcap_and_packet_csv_only(self):
        state, source_pcap, source_csv, report_path = self._create_terminal_job_with_artifacts()
        original_pcap = source_pcap.read_bytes()
        original_csv = source_csv.read_bytes()

        with patch.object(backend_app, "PCAP_PROTECT_ARTIFACTS", True), patch.object(
            backend_app,
            "PCAP_ARTIFACT_ENCRYPTION_KEY",
            "test-only-artifact-key",
        ), patch.object(backend_app, "PCAP_ARTIFACT_ENCRYPTION_MODE", "copy_encrypt_verify"):
            metadata = backend_app._protect_pcap_artifacts_after_terminal_state(state)

        encrypted_pcap = source_pcap.with_name(f"{source_pcap.name}.enc")
        encrypted_csv = source_csv.with_name(f"{source_csv.name}.enc")

        self.assertEqual(metadata.get("enabled"), True)
        self.assertFalse(source_pcap.exists())
        self.assertFalse(source_csv.exists())
        self.assertTrue(encrypted_pcap.exists())
        self.assertTrue(encrypted_csv.exists())
        self.assertGreater(encrypted_pcap.stat().st_size, len(original_pcap))
        self.assertGreater(encrypted_csv.stat().st_size, len(original_csv))
        self.assertNotEqual(encrypted_pcap.read_bytes(), original_pcap)
        self.assertNotEqual(encrypted_csv.read_bytes(), original_csv)

        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertTrue(report["meta"]["artifact_protection"]["enabled"])
        self.assertTrue(report_path.exists())
        state_path = Path(backend_app.JOBS_FOLDER) / state.job_id / "state.json"
        self.assertTrue(state_path.exists())
        self.assertIsInstance(json.loads(state_path.read_text(encoding="utf-8")), dict)


if __name__ == "__main__":
    unittest.main()
