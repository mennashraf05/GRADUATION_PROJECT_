import sys
import time
import types
import unittest
import uuid
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as backend_app


ATTACK_PCAP = BACKEND_DIR / "pcap_runs" / "54c03680-a670-49ac-a215-fee9e2bce665.pcap"


def _fake_benign_report(*, job_id: str) -> dict:
    return {
        "meta": {
            "generated_at": "2026-04-07T00:00:00+00:00",
            "pcap_path": str(ATTACK_PCAP),
            "run_folder": "tshark+cic",
            "zeek_requested": False,
            "zeek_enrichment_succeeded": False,
            "zeek_evidence_available": False,
            "analysis_mode": "base_only",
            "comparison": {
                "compared_rows": 287,
                "changed_by_evidence_up": 0,
                "changed_by_evidence_down": 0,
                "base_only_rows": 287,
                "enriched_only_rows": 0,
            },
            "pipeline": {
                "job_id": job_id,
                "zeek_requested": False,
            },
        },
        "summary": {
            "total_flows": 287,
            "alerts_count": 0,
            "suspicious": 0,
            "malicious": 0,
            "overall_risk": 0.0,
            "risk_level": "Normal",
            "risk_context_label": "Baseline Activity",
            "risk_display": "Normal Activity",
            "top_attackers": [],
            "security_score": 100.0,
            "score_explanation": None,
            "security_score_level": "Secure",
            "top_risk": None,
            "security_summary": "No significant threats detected. Network activity appears normal.",
            "summary": "No significant threats detected. Network activity appears normal.",
            "security_trend": "Traffic stayed within normal operating patterns.",
            "cluster_count": 0,
            "severity_counts": {
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0,
            },
        },
        "clusters": [],
        "alerts": [],
        "timeline": [],
        "risk_per_ip": [],
    }


class PcapAlertPersistenceRegressionTests(unittest.TestCase):
    def setUp(self):
        self.client = backend_app.app.test_client()
        self.created_job_id = None
        self.created_job_ids: list[str] = []
        self.attack_pcap_created = False
        ATTACK_PCAP.parent.mkdir(parents=True, exist_ok=True)
        if not ATTACK_PCAP.exists():
            ATTACK_PCAP.write_bytes(b"\xd4\xc3\xb2\xa1synthetic-alert-pcap")
            self.attack_pcap_created = True
        self.user = backend_app.User(
            email=f"pcap-alert-regression-{uuid.uuid4().hex[:12]}@example.com",
            password_hash=generate_password_hash("Sentinel!12345"),
            full_name="Regression Test User",
            is_email_verified=True,
            is_two_factor_enabled=False,
            two_factor_secret=None,
        )
        with backend_app.app.app_context():
            backend_app.db.session.add(self.user)
            backend_app.db.session.commit()
            self.user_id = int(self.user.id)

    def tearDown(self):
        if self.created_job_id:
            backend_app.jobs.forget(self.created_job_id)
        for job_id in self.created_job_ids:
            backend_app.jobs.forget(job_id)

        with backend_app.app.app_context():
            backend_app.PcapAlertRecord.query.filter_by(user_id=self.user_id).delete()
            backend_app.UserNotification.query.filter_by(user_id=self.user_id).delete()
            backend_app.User.query.filter_by(id=self.user_id).delete()
            backend_app.db.session.commit()
        if self.attack_pcap_created and ATTACK_PCAP.exists():
            ATTACK_PCAP.unlink()

    def _auth_user(self):
        return patch.object(
            backend_app,
            "require_full_auth_user",
            return_value=(
                types.SimpleNamespace(id=self.user_id, email=self.user.email),
                None,
            ),
        )

    def _wait_for_job(self, job_id: str, timeout_s: float = 5.0):
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            state = backend_app.jobs.get(job_id)
            if state and state.status in {"done", "error"}:
                return state
            time.sleep(0.05)
        self.fail(f"Job {job_id} did not finish within {timeout_s:.1f}s")

    def _create_pcap_alert_record(
        self,
        *,
        job_id: str,
        event_at: datetime,
        created_at: datetime,
        alert_key_suffix: str,
        title: str,
    ):
        with backend_app.app.app_context():
            backend_app.db.session.add(
                backend_app.PcapAlertRecord(
                    user_id=self.user_id,
                    job_id=job_id,
                    alert_key=f"{job_id}:{alert_key_suffix}",
                    source_type="pcap_job_summary",
                    type="analysis_result",
                    title=title,
                    message=f"{title} persisted for regression coverage.",
                    severity="medium",
                    status="new",
                    risk_label="Low Risk (Isolated Event)",
                    threats_count=1,
                    flows_analyzed=10,
                    top_pattern="ddos",
                    filename=f"{job_id}.pcap",
                    event_at=event_at,
                    created_at=created_at,
                    metadata_json=json.dumps(
                        {"owner_scope": f"email:{self.user.email.lower()}"}
                    ),
                )
            )
            backend_app.db.session.commit()

    def test_benign_report_persists_summary_alert_and_route_returns_it(self):
        def fake_pipeline(**kwargs):
            return _fake_benign_report(job_id=str(kwargs.get("job_id") or ""))

        with self._auth_user(), patch.object(
            backend_app, "_create_job_started_notification", return_value=None
        ), patch.object(
            backend_app, "_create_job_completed_notifications", return_value=None
        ), patch.object(
            backend_app, "_send_pcap_completion_email", return_value=None
        ), patch.object(
            backend_app, "run_pcap_pipeline", side_effect=fake_pipeline
        ):
            response = self.client.post(
                "/pcap/analyze-local",
                json={"pcap_path": str(ATTACK_PCAP), "include_zeek": False},
            )

            self.assertEqual(response.status_code, 202)
            payload = response.get_json()
            self.assertIsInstance(payload, dict)
            self.created_job_id = str(payload["job_id"])

            state = self._wait_for_job(self.created_job_id)
            self.assertEqual(state.status, "done")
            self.assertEqual(int(state.owner_user_id or 0), self.user_id)

            with backend_app.app.app_context():
                rows = (
                    backend_app.PcapAlertRecord.query.filter_by(
                        user_id=self.user_id,
                        job_id=self.created_job_id,
                    )
                    .order_by(backend_app.PcapAlertRecord.id.asc())
                    .all()
                )

            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(int(row.user_id), self.user_id)
            self.assertEqual(str(row.job_id), self.created_job_id)
            self.assertEqual(str(row.source_type), "pcap_job_summary")
            self.assertEqual(str(row.title), "Network Activity Reviewed")
            self.assertIn("overall risk was assessed as Normal", str(row.message))
            self.assertEqual(str(row.severity), "safe")
            self.assertIsNotNone(row.created_at)

            alerts_response = self.client.get("/api/pcap/alerts?limit=20")
            self.assertEqual(alerts_response.status_code, 200)
            alerts_payload = alerts_response.get_json()
            self.assertIsInstance(alerts_payload, dict)
            self.assertGreaterEqual(int(alerts_payload.get("count") or 0), 1)

            matching_alerts = [
                item
                for item in (alerts_payload.get("alerts") or [])
                if str(item.get("job_id") or "") == self.created_job_id
            ]
            self.assertEqual(len(matching_alerts), 1)
            alert = matching_alerts[0]
            self.assertEqual(int(alert["user_id"]), self.user_id)
            self.assertEqual(str(alert["source_type"]), "pcap_job_summary")
            self.assertEqual(str(alert["title"]), "Network Activity Reviewed")
            self.assertEqual(str(alert["severity"]), "safe")
            self.assertIn("Network activity appears normal", str(alert["message"]))

    def test_alerts_route_returns_canonical_latest_window_after_new_insertions(self):
        base_time = datetime(2026, 4, 7, 12, 0, tzinfo=UTC)

        self._create_pcap_alert_record(
            job_id="job-a",
            event_at=base_time,
            created_at=base_time,
            alert_key_suffix="summary",
            title="Analysis A",
        )
        self._create_pcap_alert_record(
            job_id="job-b",
            event_at=base_time + timedelta(minutes=1),
            created_at=base_time + timedelta(minutes=1),
            alert_key_suffix="summary",
            title="Analysis B",
        )
        self._create_pcap_alert_record(
            job_id="job-c",
            event_at=base_time + timedelta(minutes=2),
            created_at=base_time + timedelta(minutes=2),
            alert_key_suffix="summary",
            title="Analysis C",
        )

        with self._auth_user():
            initial_response = self.client.get("/api/pcap/alerts?limit=3")

        self.assertEqual(initial_response.status_code, 200)
        initial_payload = initial_response.get_json()
        self.assertEqual(int(initial_payload.get("count") or 0), 3)
        self.assertEqual(
            [str(item.get("job_id") or "") for item in (initial_payload.get("alerts") or [])],
            ["job-c", "job-b", "job-a"],
        )

        self._create_pcap_alert_record(
            job_id="job-d",
            event_at=base_time + timedelta(minutes=3),
            created_at=base_time + timedelta(minutes=3),
            alert_key_suffix="summary",
            title="Analysis D",
        )

        with self._auth_user():
            updated_response = self.client.get("/api/pcap/alerts?limit=3")

        self.assertEqual(updated_response.status_code, 200)
        updated_payload = updated_response.get_json()
        updated_alerts = updated_payload.get("alerts") or []

        self.assertEqual(int(updated_payload.get("count") or 0), 3)
        self.assertEqual(
            [str(item.get("job_id") or "") for item in updated_alerts],
            ["job-d", "job-c", "job-b"],
        )
        self.assertEqual(
            len({str(item.get("id") or "") for item in updated_alerts}),
            len(updated_alerts),
        )

    def test_alerts_route_backfills_latest_completed_job_even_when_older_alerts_exist(self):
        base_time = datetime(2026, 4, 7, 12, 0, tzinfo=UTC)
        self._create_pcap_alert_record(
            job_id="older-job",
            event_at=base_time,
            created_at=base_time,
            alert_key_suffix="summary",
            title="Older Analysis",
        )

        latest_job = backend_app.jobs.create(
            upload_path=str(ATTACK_PCAP),
            owner_user_id=self.user_id,
            owner_user_scope=f"email:{self.user.email.lower()}",
            analysis_key=f"latest-backfill-{uuid.uuid4().hex}",
        )
        self.created_job_ids.append(latest_job.job_id)
        report_path = Path(backend_app.JOBS_FOLDER) / latest_job.job_id / "report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        latest_report = _fake_benign_report(job_id=latest_job.job_id)
        latest_report["meta"]["generated_at"] = (base_time + timedelta(minutes=5)).isoformat()
        report_path.write_text(
            json.dumps(latest_report),
            encoding="utf-8",
        )
        backend_app.jobs.update(
            latest_job.job_id,
            status="done",
            started_at=(base_time + timedelta(minutes=4)).isoformat(),
            finished_at=(base_time + timedelta(minutes=5)).isoformat(),
            progress=100,
            message="Completed",
            report_path=str(report_path),
        )

        with self._auth_user():
            response = self.client.get("/api/pcap/alerts?limit=10")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        alerts = payload.get("alerts") or []
        self.assertGreaterEqual(len(alerts), 2)
        self.assertEqual(str(alerts[0].get("job_id") or ""), latest_job.job_id)
        self.assertEqual(str(alerts[0].get("title") or ""), "Network Activity Reviewed")

    def test_clear_visible_alerts_soft_hides_rows_and_keeps_json_contract(self):
        base_time = datetime(2026, 4, 7, 12, 0, tzinfo=UTC)
        self._create_pcap_alert_record(
            job_id="clear-job-a",
            event_at=base_time,
            created_at=base_time,
            alert_key_suffix="summary",
            title="Clear Analysis A",
        )
        self._create_pcap_alert_record(
            job_id="clear-job-b",
            event_at=base_time + timedelta(minutes=1),
            created_at=base_time + timedelta(minutes=1),
            alert_key_suffix="summary",
            title="Clear Analysis B",
        )

        with self._auth_user():
            initial_response = self.client.get("/api/pcap/alerts?limit=10")

        self.assertEqual(initial_response.status_code, 200)
        initial_payload = initial_response.get_json()
        alert_ids = [
            int(item["id"])
            for item in (initial_payload.get("alerts") or [])
            if str(item.get("job_id") or "").startswith("clear-job-")
        ]
        self.assertEqual(len(alert_ids), 2)

        with self._auth_user():
            clear_response = self.client.post(
                "/api/pcap/alerts/dismiss-visible",
                json={"alert_ids": alert_ids},
            )

        self.assertEqual(clear_response.status_code, 200)
        self.assertIn("application/json", clear_response.content_type)
        clear_payload = clear_response.get_json()
        self.assertEqual(clear_payload.get("ok"), True)
        self.assertEqual(int(clear_payload.get("dismissed_count") or 0), 2)
        self.assertEqual(clear_payload.get("message"), "Visible alerts cleared.")

        with self._auth_user():
            hidden_response = self.client.get("/api/pcap/alerts?limit=10")

        self.assertEqual(hidden_response.status_code, 200)
        hidden_payload = hidden_response.get_json()
        self.assertEqual(
            [
                item
                for item in (hidden_payload.get("alerts") or [])
                if str(item.get("job_id") or "").startswith("clear-job-")
            ],
            [],
        )

        with self._auth_user():
            dismissed_response = self.client.get(
                "/api/pcap/alerts?limit=10&include_dismissed=true"
            )

        self.assertEqual(dismissed_response.status_code, 200)
        dismissed_payload = dismissed_response.get_json()
        dismissed_job_ids = {
            str(item.get("job_id") or "") for item in dismissed_payload.get("alerts") or []
        }
        self.assertIn("clear-job-a", dismissed_job_ids)
        self.assertIn("clear-job-b", dismissed_job_ids)

    def test_clear_visible_accepts_dismiss_all_visible_and_empty_feed(self):
        with self._auth_user():
            empty_response = self.client.post(
                "/api/pcap/alerts/clear",
                json={"dismiss_all_visible": True},
            )

        self.assertEqual(empty_response.status_code, 200)
        payload = empty_response.get_json()
        self.assertEqual(payload.get("ok"), True)
        self.assertEqual(int(payload.get("dismissed_count")), 0)
        self.assertEqual(payload.get("message"), "Visible alerts cleared.")

    def test_clear_alerts_error_responses_are_json(self):
        missing_auth_response = self.client.post(
            "/api/pcap/alerts/clear",
            json={"dismiss_all_visible": True},
        )
        self.assertEqual(missing_auth_response.status_code, 401)
        self.assertIn("application/json", missing_auth_response.content_type)
        self.assertEqual(missing_auth_response.get_json().get("error"), "Unauthorized")

        with self._auth_user():
            invalid_body_response = self.client.post(
                "/api/pcap/alerts/clear",
                json=[],
            )
            skipped_response = self.client.post(
                "/api/pcap/alerts/clear",
                json={"alert_ids": [999999]},
            )

        self.assertEqual(invalid_body_response.status_code, 400)
        self.assertIn("application/json", invalid_body_response.content_type)
        self.assertEqual(invalid_body_response.get_json().get("ok"), False)

        self.assertEqual(skipped_response.status_code, 200)
        self.assertIn("application/json", skipped_response.content_type)
        skipped_payload = skipped_response.get_json()
        self.assertEqual(skipped_payload.get("ok"), True)
        self.assertEqual(int(skipped_payload.get("dismissed_count") or 0), 0)
        self.assertGreaterEqual(int(skipped_payload.get("skipped_count") or 0), 1)

    def test_clear_all_visible_dismisses_current_user_database_rows(self):
        base_time = datetime(2026, 4, 7, 12, 0, tzinfo=UTC)
        for index in range(10):
            self._create_pcap_alert_record(
                job_id=f"bulk-clear-job-{index}",
                event_at=base_time + timedelta(minutes=index),
                created_at=base_time + timedelta(minutes=index),
                alert_key_suffix="summary",
                title=f"Bulk Clear Analysis {index}",
            )

        with self._auth_user():
            initial_response = self.client.get("/api/pcap/alerts?limit=10")
            clear_response = self.client.post(
                "/api/pcap/alerts/clear",
                json={"dismiss_all_visible": True},
            )
            hidden_response = self.client.get("/api/pcap/alerts?limit=10")

        self.assertEqual(initial_response.status_code, 200)
        self.assertEqual(int(initial_response.get_json().get("count") or 0), 10)
        self.assertEqual(clear_response.status_code, 200)
        clear_payload = clear_response.get_json()
        self.assertEqual(clear_payload.get("ok"), True)
        self.assertGreater(int(clear_payload.get("dismissed_count") or 0), 0)
        self.assertEqual(int(hidden_response.get_json().get("count") or 0), 0)

    def test_clear_alert_ids_skips_synthetic_and_invalid_without_403(self):
        base_time = datetime(2026, 4, 7, 12, 0, tzinfo=UTC)
        self._create_pcap_alert_record(
            job_id="mixed-clear-job",
            event_at=base_time,
            created_at=base_time,
            alert_key_suffix="summary",
            title="Mixed Clear Analysis",
        )

        with self._auth_user():
            initial_response = self.client.get("/api/pcap/alerts?limit=10")

        alert = next(
            item
            for item in (initial_response.get_json().get("alerts") or [])
            if str(item.get("job_id") or "") == "mixed-clear-job"
        )

        with self._auth_user():
            clear_response = self.client.post(
                "/api/pcap/alerts/clear",
                json={"alert_ids": [int(alert["id"]), "synthetic-alert", 999999]},
            )
            hidden_response = self.client.get("/api/pcap/alerts?limit=10")

        self.assertEqual(clear_response.status_code, 200)
        clear_payload = clear_response.get_json()
        self.assertEqual(clear_payload.get("ok"), True)
        self.assertEqual(int(clear_payload.get("dismissed_count") or 0), 1)
        self.assertGreaterEqual(int(clear_payload.get("skipped_count") or 0), 2)
        self.assertEqual(
            [
                item
                for item in (hidden_response.get_json().get("alerts") or [])
                if str(item.get("job_id") or "") == "mixed-clear-job"
            ],
            [],
        )

    def test_clear_alert_ids_does_not_clear_another_users_alert(self):
        other_user = backend_app.User(
            email=f"pcap-alert-other-{uuid.uuid4().hex[:12]}@example.com",
            password_hash=generate_password_hash("Sentinel!12345"),
            full_name="Other Regression User",
            is_email_verified=True,
            is_two_factor_enabled=False,
            two_factor_secret=None,
        )
        with backend_app.app.app_context():
            backend_app.db.session.add(other_user)
            backend_app.db.session.commit()
            other_user_id = int(other_user.id)
            other_alert = backend_app.PcapAlertRecord(
                user_id=other_user_id,
                job_id="other-user-clear-job",
                alert_key=f"other-user-clear-job:{uuid.uuid4().hex}",
                source_type="pcap_job_summary",
                type="analysis_result",
                title="Other User Analysis",
                message="Must remain visible for the owning user only.",
                severity="medium",
                status="new",
                event_at=datetime(2026, 4, 7, 12, 0, tzinfo=UTC),
                metadata_json=json.dumps(
                    {"owner_scope": f"email:{other_user.email.lower()}"}
                ),
            )
            backend_app.db.session.add(other_alert)
            backend_app.db.session.commit()
            other_alert_id = int(other_alert.id)

        try:
            with self._auth_user():
                clear_response = self.client.post(
                    "/api/pcap/alerts/clear",
                    json={"alert_ids": [other_alert_id]},
                )

            self.assertEqual(clear_response.status_code, 200)
            clear_payload = clear_response.get_json()
            self.assertEqual(clear_payload.get("ok"), True)
            self.assertEqual(int(clear_payload.get("dismissed_count") or 0), 0)

            with backend_app.app.app_context():
                row = backend_app.PcapAlertRecord.query.get(other_alert_id)
                self.assertIsNotNone(row)
                self.assertIsNone(row.dismissed_at)
        finally:
            with backend_app.app.app_context():
                backend_app.PcapAlertRecord.query.filter_by(user_id=other_user_id).delete()
                backend_app.User.query.filter_by(id=other_user_id).delete()
                backend_app.db.session.commit()

    def test_backfill_does_not_resurrect_dismissed_alert(self):
        base_time = datetime(2026, 4, 7, 12, 0, tzinfo=UTC)
        job = backend_app.jobs.create(
            upload_path=str(ATTACK_PCAP),
            owner_user_id=self.user_id,
            owner_user_scope=f"email:{self.user.email.lower()}",
            analysis_key=f"dismissed-backfill-{uuid.uuid4().hex}",
        )
        self.created_job_ids.append(job.job_id)
        report_path = Path(backend_app.JOBS_FOLDER) / job.job_id / "report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report = _fake_benign_report(job_id=job.job_id)
        report["meta"]["generated_at"] = base_time.isoformat()
        report_path.write_text(json.dumps(report), encoding="utf-8")
        backend_app.jobs.update(
            job.job_id,
            status="done",
            started_at=(base_time - timedelta(minutes=1)).isoformat(),
            finished_at=base_time.isoformat(),
            progress=100,
            message="Completed",
            report_path=str(report_path),
        )

        with self._auth_user():
            first_response = self.client.get("/api/pcap/alerts?limit=10")

        self.assertEqual(first_response.status_code, 200)
        first_payload = first_response.get_json()
        matching_alerts = [
            item
            for item in (first_payload.get("alerts") or [])
            if str(item.get("job_id") or "") == job.job_id
        ]
        self.assertEqual(len(matching_alerts), 1)
        alert_id = int(matching_alerts[0]["id"])

        with self._auth_user():
            dismiss_response = self.client.post(
                "/api/pcap/alerts/clear",
                json={"alert_ids": [alert_id]},
            )
            second_response = self.client.get("/api/pcap/alerts?limit=10")
            third_response = self.client.get("/api/pcap/alerts?limit=10")

        self.assertEqual(dismiss_response.status_code, 200)
        self.assertEqual(dismiss_response.get_json().get("message"), "Alert dismissed.")
        self.assertEqual(second_response.status_code, 200)
        self.assertEqual(third_response.status_code, 200)

        for response in (second_response, third_response):
            payload = response.get_json()
            self.assertEqual(
                [
                    item
                    for item in (payload.get("alerts") or [])
                    if str(item.get("job_id") or "") == job.job_id
                ],
                [],
            )

        with backend_app.app.app_context():
            rows = backend_app.PcapAlertRecord.query.filter_by(
                user_id=self.user_id,
                job_id=job.job_id,
            ).all()
        self.assertEqual(len(rows), 1)
        self.assertIsNotNone(rows[0].dismissed_at)

    def test_alerts_and_jobs_reject_records_from_different_account_scope_even_if_user_id_matches(self):
        legacy_job = backend_app.jobs.create(
            upload_path=str(ATTACK_PCAP),
            owner_user_id=self.user_id,
            owner_user_scope="email:legacy-owner@example.com",
            analysis_key=f"legacy-scope-{uuid.uuid4().hex}",
        )
        self.created_job_ids.append(legacy_job.job_id)
        backend_app.jobs.update(
            legacy_job.job_id,
            status="done",
            started_at=legacy_job.created_at,
            finished_at=legacy_job.created_at,
            progress=100,
            message="Completed",
        )

        with backend_app.app.app_context():
            backend_app.db.session.add(
                backend_app.PcapAlertRecord(
                    user_id=self.user_id,
                    job_id=legacy_job.job_id,
                    alert_key=f"{legacy_job.job_id}:summary",
                    source_type="pcap_job_summary",
                    type="analysis_result",
                    title="Leaked Legacy Alert",
                    message="This row should not appear for a different account scope.",
                    severity="medium",
                    status="new",
                    risk_label="Low Risk (Isolated Event)",
                    threats_count=1,
                    flows_analyzed=10,
                    top_pattern="legacy-pattern",
                    filename="legacy.pcap",
                    event_at=datetime(2026, 4, 7, 12, 0, tzinfo=UTC),
                    created_at=datetime(2026, 4, 7, 12, 0, tzinfo=UTC),
                    metadata_json=json.dumps(
                        {"owner_scope": "email:legacy-owner@example.com"}
                    ),
                )
            )
            backend_app.db.session.commit()

        reused_id_new_account = types.SimpleNamespace(
            id=self.user_id,
            email="brand-new-user@example.com",
        )
        with patch.object(
            backend_app,
            "require_full_auth_user",
            return_value=(reused_id_new_account, None),
        ):
            alerts_response = self.client.get("/api/pcap/alerts?limit=10")
            jobs_response = self.client.get("/jobs?limit=10")
            job_response = self.client.get(f"/job/{legacy_job.job_id}")

        self.assertEqual(alerts_response.status_code, 200)
        alerts_payload = alerts_response.get_json()
        self.assertEqual(int(alerts_payload.get("count") or 0), 0)
        self.assertEqual(alerts_payload.get("alerts") or [], [])

        self.assertEqual(jobs_response.status_code, 200)
        jobs_payload = jobs_response.get_json()
        self.assertEqual(int(jobs_payload.get("count") or 0), 0)
        self.assertEqual(jobs_payload.get("jobs") or [], [])

        self.assertEqual(job_response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
