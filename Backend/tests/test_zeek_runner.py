import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from pcap_engine import zeek_runner


class ZeekRunnerCommandTests(unittest.TestCase):
    def test_linux_path_uses_direct_zeek_command(self):
        with patch.dict(os.environ, {"ZEEK_BIN": "/opt/zeek/bin/zeek"}):
            command, cwd, mode = zeek_runner._build_zeek_command(
                "/app/Backend/pcap_runs/sample.pcap",
                Path("/app/Backend/pcap_runs/job-zeek"),
            )

        self.assertEqual(mode, "linux")
        self.assertEqual(cwd, "/app/Backend/pcap_runs/job-zeek")
        self.assertEqual(
            command,
            [
                "/opt/zeek/bin/zeek",
                "-C",
                "-r",
                "/app/Backend/pcap_runs/sample.pcap",
                "LogAscii::use_json=T",
            ],
        )

    def test_windows_path_preserves_wsl_command(self):
        command, cwd, mode = zeek_runner._build_zeek_command(
            r"E:\GRADUATION_PROJECT\pcap_runs\sample.pcap",
            Path(r"E:\GRADUATION_PROJECT\pcap_runs\job-zeek"),
        )

        self.assertEqual(mode, "wsl")
        self.assertIsNone(cwd)
        self.assertEqual(command[:3], ["wsl", "bash", "-lc"])
        self.assertIn("/mnt/e/GRADUATION_PROJECT/pcap_runs/sample.pcap", command[3])
        self.assertIn("/usr/local/zeek/bin/zeek", command[3])

    def test_relative_path_is_rejected(self):
        with self.assertRaises(ValueError):
            zeek_runner._build_zeek_command("pcap_runs/sample.pcap", Path("out"))

    def test_run_zeek_uses_linux_cwd_and_surfaces_command_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pcap = base / "sample.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1synthetic")
            run_folder = base / "zeek"

            class FakeProcess:
                returncode = 1

                def communicate(self, timeout=None):
                    return "", "zeek missing"

            with patch.object(
                zeek_runner,
                "_build_zeek_command",
                return_value=(["zeek", "-C", "-r", str(pcap), "LogAscii::use_json=T"], str(run_folder), "linux"),
            ), patch.object(zeek_runner.subprocess, "Popen", return_value=FakeProcess()) as popen:
                with self.assertRaisesRegex(Exception, "zeek missing"):
                    zeek_runner.run_zeek(str(pcap), str(base), str(run_folder))

            self.assertEqual(popen.call_args.kwargs.get("cwd"), str(run_folder))


if __name__ == "__main__":
    unittest.main()
