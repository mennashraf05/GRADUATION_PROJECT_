import sys
import unittest
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from werkzeug.security import generate_password_hash


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as backend_app
from gamification.definitions import compute_level_details
from gamification.models import (
    GamificationEvent,
    UserBadge,
    UserChallenge,
    UserGamificationProfile,
    UserAlertReviewState,
    InvestigationNote,
    GamificationDailyStat,
)
from gamification.service import (
    critical_reduction_points,
    score_improvement_points,
)


class GamificationServiceTests(unittest.TestCase):
    def setUp(self):
        self.app_context = backend_app.app.app_context()
        self.app_context.push()
        self.service = backend_app.gamification_service
        self.service.ensure_schema()
        self.user = backend_app.User(
            email=f"gamification-{uuid.uuid4().hex[:12]}@example.com",
            password_hash=generate_password_hash("Sentinel!12345"),
            full_name="Gamification Test User",
            is_email_verified=True,
            is_two_factor_enabled=False,
            two_factor_secret=None,
        )
        backend_app.db.session.add(self.user)
        backend_app.db.session.commit()
        self.user_id = int(self.user.id)

    def tearDown(self):
        try:
            InvestigationNote.query.filter_by(user_id=self.user_id).delete()
            UserAlertReviewState.query.filter_by(user_id=self.user_id).delete()
            GamificationDailyStat.query.filter_by(user_id=self.user_id).delete()
            UserChallenge.query.filter_by(user_id=self.user_id).delete()
            UserBadge.query.filter_by(user_id=self.user_id).delete()
            GamificationEvent.query.filter_by(user_id=self.user_id).delete()
            UserGamificationProfile.query.filter_by(user_id=self.user_id).delete()
            backend_app.User.query.filter_by(id=self.user_id).delete()
            backend_app.db.session.commit()
        finally:
            backend_app.db.session.remove()
            self.app_context.pop()

    def _insert_raw_event(
        self,
        *,
        event_type: str,
        event_key: str,
        points_awarded: int,
        job_id: str | None = None,
        alert_id: str | None = None,
        metadata_json: str = "{}",
        created_at: datetime | None = None,
    ) -> None:
        backend_app.db.session.add(
            GamificationEvent(
                user_id=self.user_id,
                event_type=event_type,
                event_key=event_key,
                job_id=job_id,
                alert_id=alert_id,
                points_awarded=points_awarded,
                metadata_json=metadata_json,
                created_at=created_at or datetime.now(UTC),
            )
        )
        backend_app.db.session.commit()

    def test_duplicate_event_does_not_double_award_points(self):
        with backend_app.app.app_context():
            first = self.service.record_upload(self.user_id, "job-upload-1", "hash-1")
            second = self.service.record_upload(self.user_id, "job-upload-2", "hash-1")
            profile = UserGamificationProfile.query.filter_by(user_id=self.user_id).first()

            self.assertTrue(first["accepted"])
            self.assertFalse(second["accepted"])
            self.assertEqual(second["reason"], "duplicate_event")
            self.assertEqual(int(profile.total_points), 5)

    def test_same_alert_reviewed_twice_gives_points_only_once(self):
        with backend_app.app.app_context():
            first = self.service.record_ui_event(
                self.user_id,
                "alert_reviewed",
                {"job_id": "job-a", "alert_id": "alert-1"},
            )
            second = self.service.record_ui_event(
                self.user_id,
                "alert_reviewed",
                {"job_id": "job-a", "alert_id": "alert-1"},
            )
            profile = UserGamificationProfile.query.filter_by(user_id=self.user_id).first()

            self.assertTrue(first["accepted"])
            self.assertFalse(second["accepted"])
            self.assertEqual(int(profile.total_reviewed_alerts), 1)

    def test_same_report_opened_twice_for_same_job_gives_points_only_once(self):
        with backend_app.app.app_context():
            first = self.service.record_ui_event(
                self.user_id,
                "report_opened",
                {"job_id": "job-report-1"},
            )
            second = self.service.record_ui_event(
                self.user_id,
                "report_opened",
                {"job_id": "job-report-1"},
            )
            profile = UserGamificationProfile.query.filter_by(user_id=self.user_id).first()

            self.assertTrue(first["accepted"])
            self.assertFalse(second["accepted"])
            self.assertEqual(int(profile.total_points), 10)

    def test_report_download_and_frontend_access_do_not_double_award(self):
        with backend_app.app.app_context():
            first = self.service.record_download_event(
                self.user_id,
                "job-report-download",
                "report",
            )
            second = self.service.process_event(
                self.user_id,
                "report_accessed",
                {
                    "job_id": "job-report-download",
                    "access_method": "download_success",
                },
            )
            profile = UserGamificationProfile.query.filter_by(user_id=self.user_id).first()
            history = self.service.get_history_payload(self.user_id, limit=10)["history"]

            self.assertTrue(first["accepted"])
            self.assertFalse(second["accepted"])
            self.assertEqual(second["reason"], "duplicate_event")
            self.assertEqual(int(profile.total_points), 10)
            self.assertEqual(
                len([item for item in history if item["event_type"] == "report_accessed"]),
                1,
            )

    def test_evidence_download_and_frontend_access_do_not_double_award(self):
        with backend_app.app.app_context():
            first = self.service.record_download_event(
                self.user_id,
                "job-evidence-download",
                "evidence",
                evidence_key="bundle",
            )
            second = self.service.process_event(
                self.user_id,
                "evidence_accessed",
                {
                    "job_id": "job-evidence-download",
                    "evidence_key": "bundle",
                    "evidence_context": "bundle",
                    "access_method": "download_success",
                },
            )
            profile = UserGamificationProfile.query.filter_by(user_id=self.user_id).first()
            history = self.service.get_history_payload(self.user_id, limit=10)["history"]

            self.assertTrue(first["accepted"])
            self.assertFalse(second["accepted"])
            self.assertEqual(second["reason"], "duplicate_event")
            self.assertEqual(int(profile.total_points), 2)
            self.assertEqual(
                len([item for item in history if item["event_type"] == "evidence_accessed"]),
                1,
            )

    def test_level_calculation_is_correct(self):
        self.assertEqual(compute_level_details(0)["current_level_name"], "Beginner Analyst")
        self.assertEqual(compute_level_details(149)["current_level"], 2)
        self.assertEqual(compute_level_details(300)["current_level_name"], "Threat Hunter")
        self.assertEqual(compute_level_details(1250)["current_level"], 7)

    def test_history_payload_serializes_naive_timestamps_as_utc(self):
        event_time = datetime(2026, 4, 14, 17, 3, 14)
        with backend_app.app.app_context():
            backend_app.db.session.add(
                GamificationEvent(
                    user_id=self.user_id,
                    event_type="report_opened",
                    event_key=f"report_opened:user{self.user_id}:job-timezone",
                    job_id="job-timezone",
                    points_awarded=2,
                    metadata_json="{}",
                    created_at=event_time,
                )
            )
            backend_app.db.session.commit()

            payload = self.service.get_history_payload(self.user_id, limit=1)

            self.assertEqual(payload["history"][0]["created_at"], "2026-04-14T17:03:14+00:00")

    def test_score_improvement_reward_calculation_is_correct(self):
        self.assertEqual(score_improvement_points(70, 72), 5)
        self.assertEqual(score_improvement_points(70, 75), 10)
        self.assertEqual(score_improvement_points(70, 82), 15)
        self.assertEqual(score_improvement_points(70, 70), 0)

    def test_critical_reduction_reward_calculation_is_correct(self):
        self.assertEqual(critical_reduction_points(8, 5), 8)
        self.assertEqual(critical_reduction_points(8, 3), 15)
        self.assertEqual(critical_reduction_points(8, 0), 20)
        self.assertEqual(critical_reduction_points(0, 0), 0)

    def test_streak_increments_on_consecutive_days_and_resets(self):
        with backend_app.app.app_context():
            day_one = datetime(2026, 4, 10, 9, 0, tzinfo=UTC)
            day_two = day_one + timedelta(days=1)
            day_four = day_one + timedelta(days=3)

            self.service.process_event(
                self.user_id,
                "report_opened",
                {"job_id": "job-day-1", "occurred_at": day_one},
            )
            self.service.process_event(
                self.user_id,
                "report_opened",
                {"job_id": "job-day-2", "occurred_at": day_two},
            )
            self.service.process_event(
                self.user_id,
                "report_opened",
                {"job_id": "job-day-4", "occurred_at": day_four},
            )

            profile = UserGamificationProfile.query.filter_by(user_id=self.user_id).first()
            self.assertEqual(int(profile.current_streak), 1)
            self.assertEqual(int(profile.longest_streak), 2)

    def test_badge_unlock_happens_exactly_once(self):
        with backend_app.app.app_context():
            self.service.record_ui_event(
                self.user_id,
                "report_opened",
                {"job_id": "job-badge-1"},
            )
            self.service.record_ui_event(
                self.user_id,
                "report_opened",
                {"job_id": "job-badge-2"},
            )

            badge_rows = UserBadge.query.filter_by(
                user_id=self.user_id,
                badge_code="report_explorer",
            ).all()
            self.assertEqual(len(badge_rows), 1)

    def test_report_badge_unlocks_from_download_access(self):
        with backend_app.app.app_context():
            self.service.record_download_event(
                self.user_id,
                "job-report-badge",
                "report",
            )
            badge_rows = UserBadge.query.filter_by(
                user_id=self.user_id,
                badge_code="report_explorer",
            ).all()

            self.assertEqual(len(badge_rows), 1)

    def test_evidence_badge_unlocks_from_download_access(self):
        with backend_app.app.app_context():
            self.service.record_download_event(
                self.user_id,
                "job-evidence-badge",
                "evidence",
                evidence_key="bundle",
            )
            badge_rows = UserBadge.query.filter_by(
                user_id=self.user_id,
                badge_code="evidence_explorer",
            ).all()

            self.assertEqual(len(badge_rows), 1)

    def test_challenge_progress_updates_and_completes_correctly(self):
        with backend_app.app.app_context():
            current_day = datetime(2026, 4, 12, 11, 0, tzinfo=UTC)
            self.service.record_ui_event(
                self.user_id,
                "alert_reviewed",
                {"job_id": "job-challenge", "alert_id": "alert-1", "occurred_at": current_day},
            )
            self.service.record_ui_event(
                self.user_id,
                "alert_reviewed",
                {"job_id": "job-challenge", "alert_id": "alert-2", "occurred_at": current_day},
            )
            self.service.record_ui_event(
                self.user_id,
                "alert_reviewed",
                {"job_id": "job-challenge", "alert_id": "alert-3", "occurred_at": current_day},
            )

            challenge = UserChallenge.query.filter_by(
                user_id=self.user_id,
                challenge_code="review_three_alerts",
            ).first()
            completion_events = GamificationEvent.query.filter_by(
                user_id=self.user_id,
                event_type="challenge_completed",
            ).all()

            self.assertIsNotNone(challenge)
            self.assertEqual(challenge.status, "completed")
            self.assertEqual(int(challenge.current_value), 3)
            self.assertEqual(len(completion_events), 1)

    def test_report_challenge_completes_on_download_access(self):
        with backend_app.app.app_context():
            self.service.record_download_event(
                self.user_id,
                "job-report-challenge",
                "report",
            )

            challenge = UserChallenge.query.filter_by(
                user_id=self.user_id,
                challenge_code="open_one_report",
            ).first()

            self.assertIsNotNone(challenge)
            self.assertEqual(challenge.title, "Access 1 report")
            self.assertEqual(challenge.status, "completed")
            self.assertEqual(int(challenge.current_value), 1)

    def test_evidence_challenge_completes_on_unique_accesses(self):
        with backend_app.app.app_context():
            self.service.record_download_event(
                self.user_id,
                "job-evidence-challenge",
                "evidence",
                evidence_key="bundle",
            )
            self.service.process_event(
                self.user_id,
                "evidence_accessed",
                {
                    "job_id": "job-evidence-challenge",
                    "alert_id": "alert-1",
                    "evidence_key": "dns",
                    "evidence_context": "dns",
                    "access_method": "in_app_view",
                },
            )

            challenge = UserChallenge.query.filter_by(
                user_id=self.user_id,
                challenge_code="open_two_evidence_items",
            ).first()

            self.assertIsNotNone(challenge)
            self.assertEqual(challenge.title, "Access evidence twice")
            self.assertEqual(challenge.status, "completed")
            self.assertEqual(int(challenge.current_value), 2)

    def test_badge_progress_is_clamped_for_unlocked_one_time_badges(self):
        with backend_app.app.app_context():
            self.service.process_event(
                self.user_id,
                "report_accessed",
                {"job_id": "job-clamp-1", "access_method": "in_app_view"},
            )
            self.service.process_event(
                self.user_id,
                "report_accessed",
                {"job_id": "job-clamp-2", "access_method": "download_success"},
            )

            payload = self.service.get_badges_payload(self.user_id)
            report_badge = next(
                item
                for item in payload["unlocked"]
                if item["badge_code"] == "report_explorer"
            )

            self.assertEqual(report_badge["progress_current"], 1)
            self.assertEqual(report_badge["progress_target"], 1)

    def test_legacy_access_rows_are_deduped_in_profile_and_history(self):
        with backend_app.app.app_context():
            created_at = datetime(2026, 4, 14, 9, 0, tzinfo=UTC)
            self._insert_raw_event(
                event_type="report_opened",
                event_key=f"report_opened:user{self.user_id}:job-legacy",
                job_id="job-legacy",
                points_awarded=2,
                created_at=created_at,
            )
            self._insert_raw_event(
                event_type="report_downloaded",
                event_key=f"report_downloaded:user{self.user_id}:job-legacy",
                job_id="job-legacy",
                points_awarded=2,
                created_at=created_at + timedelta(minutes=1),
            )

            profile = self.service.get_profile_payload(self.user_id)
            history = self.service.get_history_payload(self.user_id, limit=10)["history"]
            access_history = [
                item for item in history if item["event_type"] == "report_accessed"
            ]

            self.assertEqual(profile["total_points"], 2)
            self.assertEqual(len(access_history), 1)
            self.assertIn("accessing an analysis report", access_history[0]["human_readable_reason"])


if __name__ == "__main__":
    unittest.main()
