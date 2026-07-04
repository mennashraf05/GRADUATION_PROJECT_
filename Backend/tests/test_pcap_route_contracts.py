import io
import json
import shutil
import sys
import time
import types
import unittest
import zipfile
import uuid
from pathlib import Path
from unittest.mock import patch


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as backend_app


ATTACK_PCAP = BACKEND_DIR / "pcap_runs" / "54c03680-a670-49ac-a215-fee9e2bce665.pcap"


def _fake_report(*, job_id: str, include_zeek: bool) -> dict:
    return {
        "meta": {
            "generated_at": "2026-04-07T00:00:00+00:00",
            "pcap_path": str(ATTACK_PCAP),
            "run_folder": "tshark+cic+zeek" if include_zeek else "tshark+cic",
            "zeek_requested": bool(include_zeek),
            "zeek_enrichment_succeeded": False,
            "zeek_evidence_available": False,
            "analysis_mode": "base_only",
            "comparison": {
                "compared_rows": 1,
                "changed_by_evidence_up": 0,
                "changed_by_evidence_down": 0,
                "base_only_rows": 1,
                "enriched_only_rows": 0,
            },
            "pipeline": {
                "job_id": job_id,
                "zeek_requested": bool(include_zeek),
            },
        },
        "summary": {
            "total_flows": 1,
            "alerts_count": 1,
            "suspicious": 1,
            "malicious": 0,
            "overall_risk": 0.16,
            "risk_level": "Low",
            "risk_context_label": "Isolated Event",
            "risk_display": "Low Risk (Isolated Event)",
            "top_attackers": [{"src_ip": "172.16.0.1", "count_flows": 1}],
            "security_score": 83.0,
            "score_explanation": None,
            "security_score_level": "Warning",
            "top_risk": {
                "name": "ddos",
                "severity": "medium",
                "confidence": 0.6,
                "count": 1,
                "impact": 7.2,
            },
            "security_summary": "Synthetic test report for contract verification.",
            "summary": "Synthetic test report for contract verification.",
            "security_trend": "Elevated - suspicious activity was promoted for review in this session.",
            "cluster_count": 1,
            "severity_counts": {
                "low": 0,
                "medium": 1,
                "high": 0,
                "critical": 0,
            },
        },
        "clusters": [
            {
                "attack_type": "ddos",
                "src_ip": "172.16.0.1",
                "dst_ip": "192.168.10.50",
                "count_flows": 1,
                "top_dst_ports": [{"port": 80, "count": 1}],
                "top_dst_ips": [{"ip": "192.168.10.50", "count": 1}],
                "max_confidence": 0.6,
                "max_threat_confidence": 0.6,
                "max_ml_confidence": 0.83,
                "severity": "Medium",
            }
        ],
        "alerts": [
            {
                "type": "ML",
                "ts": 1499262271.739336,
                "src_ip": "172.16.0.1",
                "dst_ip": "192.168.10.50",
                "dst_port": 80,
                "ml_label": "ddos",
                "ml_confidence": 0.83,
                "classification_confidence": 0.83,
                "confidence": 0.6,
                "threat_confidence": 0.6,
                "severity": "Medium",
                "reason": "DDoS suspected: target connections=4380, failed-connection ratio 1.00, SYN count=23, ml_confidence=0.83",
                "zeek_service": "unknown",
                "zeek_conn_state": "",
                "zeek_proto": "",
                "zeek_duration": 1.0,
                "zeek_bytes": {"orig": 0.0, "resp": 0.0},
                "dns_top_query": "",
                "dns_query_count": 0,
                "http_top_host": "",
                "http_top_uri": "",
                "http_request_count": 0,
                "ssl_top_sni": "",
                "ssl_event_count": 0,
                "heuristic": {"type": "None", "score": 0.0, "reason": ""},
            }
        ],
        "timeline": [
            {
                "ts": 1499262271.739336,
                "src_ip": "172.16.0.1",
                "dst_ip": "192.168.10.50",
                "dst_port": 80,
                "ml_label": "ddos",
                "ml_confidence": 0.83,
                "classification_confidence": 0.83,
                "confidence": 0.6,
                "threat_confidence": 0.6,
                "verdict": "Medium",
            }
        ],
    }


class PcapRouteContractTests(unittest.TestCase):
    def setUp(self):
        self.client = backend_app.app.test_client()
        self.created_job_ids: list[str] = []
        self.created_extra_dirs: list[Path] = []
        self.attack_pcap_created = False
        ATTACK_PCAP.parent.mkdir(parents=True, exist_ok=True)
        if not ATTACK_PCAP.exists():
            ATTACK_PCAP.write_bytes(b"\xd4\xc3\xb2\xa1synthetic-contract-pcap")
            self.attack_pcap_created = True
        self.existing_zeek_job_id = self._create_existing_zeek_job(owner_user_id=9)

    def tearDown(self):
        for job_id in self.created_job_ids:
            backend_app.jobs.forget(job_id)
            shutil.rmtree(Path(backend_app.JOBS_FOLDER) / job_id, ignore_errors=True)
        for path in self.created_extra_dirs:
            shutil.rmtree(path, ignore_errors=True)
        if self.attack_pcap_created and ATTACK_PCAP.exists():
            ATTACK_PCAP.unlink()

    def _auth_user(self, user_id: int):
        email = f"pcap-route-user-{user_id}@example.com"
        return patch.object(
            backend_app,
            "require_full_auth_user",
            return_value=(types.SimpleNamespace(id=user_id, email=email), None),
        )

    def _create_existing_zeek_job(self, *, owner_user_id: int) -> str:
        state = backend_app.jobs.create(
            upload_path=str(ATTACK_PCAP),
            owner_user_id=owner_user_id,
            owner_user_scope=f"email:pcap-route-user-{owner_user_id}@example.com",
            analysis_key=f"test-fixture-{time.time_ns()}",
        )
        self.created_job_ids.append(state.job_id)

        job_dir = Path(backend_app.JOBS_FOLDER) / state.job_id
        report_path = job_dir / "report.json"
        report_path.write_text(
            json.dumps(_fake_report(job_id=state.job_id, include_zeek=True)),
            encoding="utf-8",
        )

        evidence_dir = job_dir / "zeek"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        for evidence_name in backend_app.ZEEK_EVIDENCE_FILES:
            (evidence_dir / evidence_name).write_text(
                f"synthetic {evidence_name} for {state.job_id}\n",
                encoding="utf-8",
            )

        backend_app.jobs.update(
            state.job_id,
            status="done",
            started_at=state.created_at,
            finished_at=state.created_at,
            progress=100,
            message="Completed",
            report_path=str(report_path),
            evidence_dir=str(evidence_dir),
        )
        return state.job_id

    def _create_completed_job_with_evidence_dir(
        self,
        *,
        owner_user_id: int,
        evidence_dir: Path | None,
    ) -> str:
        state = backend_app.jobs.create(
            upload_path=str(ATTACK_PCAP),
            owner_user_id=owner_user_id,
            owner_user_scope=f"email:pcap-route-user-{owner_user_id}@example.com",
            analysis_key=f"test-evidence-fixture-{time.time_ns()}",
        )
        self.created_job_ids.append(state.job_id)

        job_dir = Path(backend_app.JOBS_FOLDER) / state.job_id
        report_path = job_dir / "report.json"
        report_path.write_text(
            json.dumps(_fake_report(job_id=state.job_id, include_zeek=bool(evidence_dir))),
            encoding="utf-8",
        )
        required_files_found = []
        if evidence_dir is not None:
            required_files_found = [
                name
                for name in backend_app.ZEEK_EVIDENCE_FILES
                if (evidence_dir / name).exists()
            ]
        backend_app.jobs.update(
            state.job_id,
            status="done",
            started_at=state.created_at,
            finished_at=state.created_at,
            progress=100,
            message="Completed",
            report_path=str(report_path),
            evidence_dir=str(evidence_dir) if evidence_dir is not None else None,
            zeek_requested=bool(evidence_dir),
            zeek_status=(
                "succeeded"
                if required_files_found
                else "no_logs"
                if evidence_dir is not None
                else "not_requested"
            ),
            zeek_required_files_found=required_files_found,
            zeek_log_count=len(list(evidence_dir.glob("*.log"))) if evidence_dir is not None else 0,
        )
        return state.job_id

    def _wait_for_job(self, job_id: str, timeout_s: float = 5.0):
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            state = backend_app.jobs.get(job_id)
            if state and state.status in {"done", "error"}:
                return state
            time.sleep(0.05)
        self.fail(f"Job {job_id} did not finish within {timeout_s:.1f}s")

    def test_analyze_local_dedup_and_report_export_contract(self):
        required_top_level_keys = {"meta", "summary", "clusters", "alerts", "timeline"}

        def fake_pipeline(**kwargs):
            time.sleep(0.30)
            return _fake_report(
                job_id=str(kwargs.get("job_id") or ""),
                include_zeek=bool(kwargs.get("include_zeek")),
            )

        with self._auth_user(424242), patch.object(
            backend_app, "_create_job_started_notification", return_value=None
        ), patch.object(
            backend_app, "_notify_job_success", return_value=None
        ), patch.object(
            backend_app, "_notify_job_failure", return_value=None
        ), patch.object(
            backend_app, "run_pcap_pipeline", side_effect=fake_pipeline
        ):
            payload = {"pcap_path": str(ATTACK_PCAP), "include_zeek": False}
            first = self.client.post("/pcap/analyze-local", json=payload)
            second = self.client.post("/pcap/analyze-local", json=payload)

            self.assertEqual(first.status_code, 202)
            self.assertEqual(second.status_code, 202)

            first_payload = first.get_json()
            second_payload = second.get_json()

            self.assertIn("job_id", first_payload)
            self.assertEqual(first_payload["job_id"], second_payload["job_id"])
            self.assertTrue(bool(second_payload.get("reused")))

            state = self._wait_for_job(first_payload["job_id"])
            self.assertEqual(state.status, "done")

            status_resp = self.client.get(f"/job/{state.job_id}")
            self.assertEqual(status_resp.status_code, 200)
            status_payload = status_resp.get_json()
            self.assertTrue(bool(status_payload.get("report_available")))
            self.assertIn("report", status_payload)

            report_payload = status_payload["report"]
            self.assertTrue(required_top_level_keys.issubset(report_payload.keys()))
            json.dumps(report_payload, allow_nan=False)

            export_resp = self.client.get(f"/job/{state.job_id}/export?type=report")
            self.assertEqual(export_resp.status_code, 200)
            exported_report = json.loads(export_resp.data)
            self.assertTrue(required_top_level_keys.issubset(exported_report.keys()))
            json.dumps(exported_report, allow_nan=False)
            status_resp.close()
            export_resp.close()

    def test_existing_zeek_job_exports_report_and_evidence_bundle(self):
        required_top_level_keys = {"meta", "summary", "clusters", "alerts", "timeline"}

        with self._auth_user(9):
            status_resp = self.client.get(f"/job/{self.existing_zeek_job_id}")
            self.assertEqual(status_resp.status_code, 200)
            status_payload = status_resp.get_json()
            self.assertTrue(bool(status_payload.get("report_available")))
            self.assertTrue(bool(status_payload.get("evidence_available")))
            json.dumps(status_payload.get("report"), allow_nan=False)

            report_resp = self.client.get(f"/pcap/report/{self.existing_zeek_job_id}")
            self.assertEqual(report_resp.status_code, 200)
            exported_report = json.loads(report_resp.data)
            self.assertTrue(required_top_level_keys.issubset(exported_report.keys()))
            json.dumps(exported_report, allow_nan=False)

            evidence_resp = self.client.get(
                f"/job/{self.existing_zeek_job_id}/export?type=evidence"
            )
            self.assertEqual(evidence_resp.status_code, 200)

            with zipfile.ZipFile(io.BytesIO(evidence_resp.data)) as bundle:
                names = set(bundle.namelist())

            self.assertIn("report.json", names)
            self.assertIn("state.json", names)
            self.assertTrue(any(name.startswith("zeek/") for name in names))
            status_resp.close()
            report_resp.close()
            evidence_resp.close()

    def test_completed_job_exports_evidence_from_run_folder_outside_job_dir(self):
        evidence_dir = Path(backend_app.BASE_RUN_FOLDER) / f"zeek-real-shape-{uuid.uuid4().hex}"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        self.created_extra_dirs.append(evidence_dir)
        (evidence_dir / "conn.log").write_text(
            '{"ts":1,"uid":"C1","id.orig_h":"10.0.0.1","id.resp_h":"10.0.0.2"}\n',
            encoding="utf-8",
        )
        job_id = self._create_completed_job_with_evidence_dir(
            owner_user_id=11,
            evidence_dir=evidence_dir,
        )

        with self._auth_user(11):
            status_resp = self.client.get(f"/job/{job_id}")
            self.assertEqual(status_resp.status_code, 200)
            status_payload = status_resp.get_json()
            self.assertTrue(bool(status_payload.get("report_available")))
            self.assertTrue(bool(status_payload.get("evidence_available")))
            self.assertEqual(status_payload.get("zeek_status"), "succeeded")
            self.assertIn("conn.log", status_payload.get("zeek_required_files_found") or [])

            evidence_resp = self.client.get(f"/job/{job_id}/export?type=evidence")
            self.assertEqual(evidence_resp.status_code, 200)
            with zipfile.ZipFile(io.BytesIO(evidence_resp.data)) as bundle:
                names = set(bundle.namelist())
                conn_payload = bundle.read("zeek/conn.log").decode("utf-8")

            self.assertIn("report.json", names)
            self.assertIn("state.json", names)
            self.assertIn("zeek/conn.log", names)
            self.assertIn('"uid":"C1"', conn_payload)
            status_resp.close()
            evidence_resp.close()

    def test_completed_job_without_zeek_files_keeps_evidence_unavailable(self):
        evidence_dir = Path(backend_app.BASE_RUN_FOLDER) / f"zeek-empty-{uuid.uuid4().hex}"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        self.created_extra_dirs.append(evidence_dir)
        job_id = self._create_completed_job_with_evidence_dir(
            owner_user_id=12,
            evidence_dir=evidence_dir,
        )

        with self._auth_user(12):
            status_resp = self.client.get(f"/job/{job_id}")
            self.assertEqual(status_resp.status_code, 200)
            status_payload = status_resp.get_json()
            self.assertTrue(bool(status_payload.get("report_available")))
            self.assertFalse(bool(status_payload.get("evidence_available")))

            evidence_resp = self.client.get(f"/job/{job_id}/export?type=evidence")
            self.assertEqual(evidence_resp.status_code, 404)
            status_resp.close()
            evidence_resp.close()

    def test_evidence_export_blocks_evidence_dir_outside_pcap_runs(self):
        outside_dir = BACKEND_DIR / f"outside-zeek-{uuid.uuid4().hex}"
        outside_dir.mkdir(parents=True, exist_ok=True)
        self.created_extra_dirs.append(outside_dir)
        (outside_dir / "conn.log").write_text("outside evidence must not export\n", encoding="utf-8")
        job_id = self._create_completed_job_with_evidence_dir(
            owner_user_id=13,
            evidence_dir=outside_dir,
        )

        with self._auth_user(13):
            status_resp = self.client.get(f"/job/{job_id}")
            self.assertEqual(status_resp.status_code, 200)
            status_payload = status_resp.get_json()
            self.assertFalse(bool(status_payload.get("evidence_available")))
            self.assertEqual(status_payload.get("zeek_status"), "failed")

            evidence_resp = self.client.get(f"/job/{job_id}/export?type=evidence")
            self.assertEqual(evidence_resp.status_code, 403)
            status_resp.close()
            evidence_resp.close()

    def test_zeek_failure_does_not_fail_base_pipeline(self):
        state = backend_app.jobs.create(
            upload_path=str(ATTACK_PCAP),
            owner_user_id=14,
            owner_user_scope="email:pcap-route-user-14@example.com",
            analysis_key=f"test-zeek-failure-{time.time_ns()}",
        )
        self.created_job_ids.append(state.job_id)
        evidence_dir = Path(backend_app.BASE_RUN_FOLDER) / f"zeek-failure-{uuid.uuid4().hex}"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        self.created_extra_dirs.append(evidence_dir)
        base_df = backend_app.pd.DataFrame(
            [
                {
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "src_port": 12345,
                    "dst_port": 80,
                    "ip_prot": 6,
                }
            ]
        )

        with patch.object(backend_app, "prepare_zeek_run_folder", return_value=evidence_dir), patch.object(
            backend_app, "run_zeek", side_effect=RuntimeError("synthetic zeek failure")
        ), patch.object(backend_app, "run_tshark_export", return_value=None), patch.object(
            backend_app, "build_cic_features_from_tshark_csv", return_value=base_df.copy()
        ), patch.object(
            backend_app, "_validate_cic_ml_contract", return_value=None
        ), patch.object(
            backend_app, "normalize_port_columns", side_effect=lambda df, **_kwargs: df
        ), patch.object(
            backend_app, "summarize_arp_evidence", return_value=backend_app.pd.DataFrame()
        ), patch.object(
            backend_app, "run_ml_inference", side_effect=lambda df: df
        ), patch.object(
            backend_app, "build_base_detection_frame", side_effect=lambda df: df
        ), patch.object(
            backend_app, "fill_evidence_defaults", side_effect=lambda df: df
        ), patch.object(
            backend_app, "cleanup_numeric_columns", side_effect=lambda df: df
        ), patch.object(
            backend_app, "fuse_scores", side_effect=lambda df, confidence_mode="balanced": df
        ), patch.object(
            backend_app,
            "build_pipeline_mode_comparison_summary",
            return_value={
                "compared_rows": 1,
                "changed_by_evidence_up": 0,
                "changed_by_evidence_down": 0,
                "base_only_rows": 1,
                "enriched_only_rows": 0,
            },
        ), patch.object(
            backend_app, "_log_scoring_summary", return_value=None
        ), patch.object(
            backend_app, "build_report", return_value={"meta": {"pipeline_test": True}}
        ):
            report = backend_app.run_pcap_pipeline(
                pcap_path=str(ATTACK_PCAP),
                job_id=state.job_id,
                include_zeek=True,
                confidence_mode="balanced",
                zeek_status_progress=20,
                ml_progress=60,
                ml_message="Running ML inference",
                zeek_loading_progress=70,
            )

        updated = backend_app.jobs.get(state.job_id)
        self.assertEqual(report, {"meta": {"pipeline_test": True}})
        self.assertEqual(updated.zeek_status, "failed")
        self.assertIn("synthetic zeek failure", updated.zeek_error)


if __name__ == "__main__":
    unittest.main()
