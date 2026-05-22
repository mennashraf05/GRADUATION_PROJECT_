from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, inspect
from sqlalchemy.exc import IntegrityError

from extensions import db
from gamification.definitions import (
    ACCESS_EVENT_QUERY_TYPES,
    ACCESS_EVENT_TYPES,
    BADGE_DEFINITIONS,
    CHALLENGE_DEFINITIONS,
    DAILY_CHALLENGE_DEFINITIONS,
    EVENT_TYPES,
    HISTORY_REASON_TEMPLATES,
    LEVELS,
    MEANINGFUL_ACTIVITY_EVENT_TYPES,
    POINTS,
    WEEKLY_CHALLENGE_DEFINITIONS,
    canonical_event_type,
    compute_level_details,
)
from gamification.helpers import (
    activity_date,
    build_event_key,
    compact_message,
    current_daily_window,
    current_weekly_window,
    ensure_utc,
    extract_report_metrics,
    parse_metadata,
    safe_float,
    safe_int,
    safe_str,
    serialize_datetime,
    serialize_metadata,
    utc_now,
)
from gamification.models import (
    GamificationDailyStat,
    GamificationEvent,
    InvestigationNote,
    UserAlertReviewState,
    UserBadge,
    UserChallenge,
    UserGamificationProfile,
)


_schema_lock = threading.Lock()
_schema_initialized = False


def _parse_identity_timestamp(value: Any) -> datetime | None:
    raw = safe_str(value)
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def ensure_gamification_schema_initialized() -> None:
    global _schema_initialized
    if _schema_initialized:
        return

    with _schema_lock:
        if _schema_initialized:
            return

        db.create_all()
        inspector = inspect(db.engine)
        required_tables = {
            GamificationEvent.__tablename__,
            UserGamificationProfile.__tablename__,
            UserBadge.__tablename__,
            UserChallenge.__tablename__,
            GamificationDailyStat.__tablename__,
            UserAlertReviewState.__tablename__,
            InvestigationNote.__tablename__,
        }
        existing_tables = set(inspector.get_table_names())
        missing = required_tables.difference(existing_tables)
        if missing:
            raise RuntimeError(
                f"Gamification schema initialization failed for tables: {sorted(missing)}"
            )

        _schema_initialized = True


def score_improvement_points(previous_score: float | None, current_score: float | None) -> int:
    if previous_score is None or current_score is None:
        return 0
    if current_score <= previous_score:
        return 0

    delta = current_score - previous_score
    if delta >= 10:
        return 15
    if delta >= 5:
        return 10
    if delta >= 1:
        return 5
    return 0


def critical_reduction_points(previous_count: int | None, current_count: int | None) -> int:
    if previous_count is None or current_count is None:
        return 0
    if previous_count <= 0 or current_count >= previous_count:
        return 0

    reduction_ratio = (previous_count - current_count) / previous_count
    if current_count == 0:
        return 20
    if reduction_ratio >= 0.5:
        return 15
    if reduction_ratio >= 0.25:
        return 8
    return 0


@dataclass
class PreparedEvent:
    accepted: bool
    reason: str | None
    event_key: str | None
    points: int
    metadata: dict[str, Any]
    job_id: str | None = None
    alert_id: str | None = None
    file_hash: str | None = None
    event_type: str | None = None
    history_message: str | None = None
    force_record: bool = False


class GamificationService:
    def ensure_schema(self) -> None:
        ensure_gamification_schema_initialized()

    def ensure_profile(self, user_id: int) -> UserGamificationProfile:
        self.ensure_schema()
        profile = UserGamificationProfile.query.filter_by(user_id=int(user_id)).first()
        if profile is not None:
            return profile

        level = compute_level_details(0)
        profile = UserGamificationProfile(
            user_id=int(user_id),
            total_points=0,
            current_level=int(level["current_level"]),
            current_level_name=str(level["current_level_name"]),
            current_streak=0,
            longest_streak=0,
            total_scans=0,
            total_reviewed_alerts=0,
            total_badges=0,
        )
        db.session.add(profile)
        db.session.flush()
        return profile

    def ensure_current_challenges_for_user(
        self, user_id: int, now: datetime | None = None
    ) -> dict[str, list[UserChallenge]]:
        current = ensure_utc(now) or utc_now()
        self.ensure_profile(int(user_id))

        (
            UserChallenge.query.filter(
                UserChallenge.user_id == int(user_id),
                UserChallenge.status == "active",
                UserChallenge.expires_at <= current,
            ).update(
                {
                    UserChallenge.status: "expired",
                    UserChallenge.updated_at: current,
                },
                synchronize_session=False,
            )
        )

        daily_start, daily_end = current_daily_window(current)
        weekly_start, weekly_end = current_weekly_window(current)

        daily = self._ensure_challenge_window(
            int(user_id),
            DAILY_CHALLENGE_DEFINITIONS,
            daily_start,
            daily_end,
            current,
        )
        weekly = self._ensure_challenge_window(
            int(user_id),
            WEEKLY_CHALLENGE_DEFINITIONS,
            weekly_start,
            weekly_end,
            current,
        )
        db.session.flush()
        return {"daily": daily, "weekly": weekly}

    def _ensure_challenge_window(
        self,
        user_id: int,
        definitions: dict[str, dict[str, Any]],
        starts_at,
        expires_at,
        now,
    ) -> list[UserChallenge]:
        existing = (
            UserChallenge.query.filter_by(user_id=user_id)
            .filter(
                UserChallenge.starts_at == starts_at,
                UserChallenge.expires_at == expires_at,
            )
            .all()
        )
        by_code = {challenge.challenge_code: challenge for challenge in existing}

        for code, definition in definitions.items():
            if code in by_code:
                challenge = by_code[code]
                challenge.title = definition["title"]
                challenge.description = definition["description"]
                challenge.target_value = int(definition["target_value"])
                challenge.reward_points = int(definition["reward_points"])
                challenge.updated_at = now
                continue
            challenge = UserChallenge(
                user_id=user_id,
                challenge_code=definition["challenge_code"],
                challenge_type=definition["challenge_type"],
                title=definition["title"],
                description=definition["description"],
                target_value=int(definition["target_value"]),
                current_value=0,
                reward_points=int(definition["reward_points"]),
                status="active",
                starts_at=starts_at,
                expires_at=expires_at,
                created_at=now,
                updated_at=now,
            )
            db.session.add(challenge)
            by_code[code] = challenge

        return sorted(
            by_code.values(),
            key=lambda item: (item.challenge_type, item.challenge_code),
        )

    def _build_evidence_resource_key(
        self,
        alert_id: str | None,
        evidence_key: str | None = None,
        evidence_context: str | None = None,
    ) -> str:
        base_key = safe_str(evidence_key) or safe_str(evidence_context) or "bundle"
        normalized_alert_id = safe_str(alert_id)
        if normalized_alert_id and base_key != "bundle":
            return build_event_key("alert", normalized_alert_id, base_key)
        return base_key

    def _logical_access_key(
        self,
        canonical_type: str,
        *,
        job_id: str | None,
        alert_id: str | None = None,
        evidence_key: str | None = None,
        evidence_context: str | None = None,
    ) -> str | None:
        normalized_job_id = safe_str(job_id)
        if not normalized_job_id:
            return None

        if canonical_type == "report_accessed":
            return build_event_key(canonical_type, normalized_job_id)

        if canonical_type != "evidence_accessed":
            return None

        resource_key = self._build_evidence_resource_key(
            alert_id,
            evidence_key=evidence_key,
            evidence_context=evidence_context,
        )
        return build_event_key(canonical_type, normalized_job_id, resource_key)

    def _logical_access_key_from_event(
        self,
        event: GamificationEvent,
        *,
        canonical_type: str | None = None,
    ) -> str | None:
        normalized_type = canonical_type or canonical_event_type(event.event_type)
        if normalized_type not in ACCESS_EVENT_TYPES:
            return None

        metadata = parse_metadata(event.metadata_json)
        evidence_resource_key = safe_str(metadata.get("evidence_resource_key"))
        evidence_key = safe_str(metadata.get("evidence_key"))
        evidence_context = safe_str(metadata.get("evidence_context"))

        if normalized_type == "evidence_accessed" and evidence_resource_key:
            return build_event_key(
                normalized_type,
                safe_str(event.job_id),
                evidence_resource_key,
            )

        return self._logical_access_key(
            normalized_type,
            job_id=event.job_id,
            alert_id=event.alert_id,
            evidence_key=evidence_key,
            evidence_context=evidence_context,
        )

    def _access_events_for_user(
        self,
        user_id: int,
        canonical_type: str,
        *,
        job_id: str | None = None,
    ) -> list[GamificationEvent]:
        query_types = ACCESS_EVENT_QUERY_TYPES.get(canonical_type, {canonical_type})
        query = GamificationEvent.query.filter(
            GamificationEvent.user_id == int(user_id),
            GamificationEvent.event_type.in_(sorted(query_types)),
        )
        normalized_job_id = safe_str(job_id)
        if normalized_job_id:
            query = query.filter(GamificationEvent.job_id == normalized_job_id)
        return query.all()

    def _count_unique_accesses_for_job(
        self,
        user_id: int,
        canonical_type: str,
        job_id: str | None = None,
    ) -> int:
        events = self._access_events_for_user(
            int(user_id),
            canonical_type,
            job_id=job_id,
        )
        keys = {
            key
            for event in events
            if (key := self._logical_access_key_from_event(event, canonical_type=canonical_type))
        }
        return len(keys)

    def _has_existing_access(
        self,
        user_id: int,
        canonical_type: str,
        *,
        job_id: str | None,
        alert_id: str | None = None,
        evidence_key: str | None = None,
        evidence_context: str | None = None,
    ) -> bool:
        logical_key = self._logical_access_key(
            canonical_type,
            job_id=job_id,
            alert_id=alert_id,
            evidence_key=evidence_key,
            evidence_context=evidence_context,
        )
        if not logical_key:
            return False

        events = self._access_events_for_user(
            int(user_id),
            canonical_type,
            job_id=job_id,
        )
        for event in events:
            if (
                self._logical_access_key_from_event(event, canonical_type=canonical_type)
                == logical_key
            ):
                return True
        return False

    def _compute_streak_values(self, user_id: int) -> tuple[int, int]:
        stats = (
            GamificationDailyStat.query.filter_by(user_id=int(user_id))
            .order_by(GamificationDailyStat.activity_date.asc())
            .all()
        )
        meaningful_days = [
            item.activity_date
            for item in stats
            if (
                int(item.scans_completed or 0)
                + int(item.alerts_reviewed or 0)
                + int(item.reports_opened or 0)
                + int(item.notes_added or 0)
            )
            > 0
        ]
        if not meaningful_days:
            return 0, 0

        longest = 1
        current_run = 1
        latest_run = 1
        previous_day = meaningful_days[0]
        for day in meaningful_days[1:]:
            if day == previous_day + timedelta(days=1):
                current_run += 1
            else:
                current_run = 1
            longest = max(longest, current_run)
            latest_run = current_run
            previous_day = day

        return latest_run, longest

    def _recalculate_profile_rollups(
        self,
        user_id: int,
        profile: UserGamificationProfile | None = None,
    ) -> UserGamificationProfile:
        profile = profile or self.ensure_profile(int(user_id))
        events = (
            GamificationEvent.query.filter_by(user_id=int(user_id))
            .order_by(GamificationEvent.created_at.asc(), GamificationEvent.id.asc())
            .all()
        )

        unique_access_keys: set[str] = set()
        total_points = 0
        total_scans = 0
        total_reviewed_alerts = 0
        last_activity_at = None

        for event in events:
            normalized_type = canonical_event_type(event.event_type)
            event_created_at = ensure_utc(event.created_at)
            if event_created_at and (
                last_activity_at is None or event_created_at > last_activity_at
            ):
                last_activity_at = event_created_at

            if normalized_type in ACCESS_EVENT_TYPES:
                logical_key = self._logical_access_key_from_event(
                    event,
                    canonical_type=normalized_type,
                )
                if not logical_key or logical_key in unique_access_keys:
                    continue
                unique_access_keys.add(logical_key)
                total_points += int(POINTS[normalized_type])
                continue

            total_points += int(event.points_awarded or 0)
            if normalized_type in {"analysis_completed", "identity_scan_completed"}:
                total_scans += 1
            elif normalized_type == "alert_reviewed":
                total_reviewed_alerts += 1

        total_badges = UserBadge.query.filter_by(user_id=int(user_id)).count()
        current_streak, longest_streak = self._compute_streak_values(int(user_id))
        level_details = compute_level_details(total_points)

        profile.total_points = total_points
        profile.current_level = int(level_details["current_level"] or 1)
        profile.current_level_name = str(level_details["current_level_name"] or "Beginner Analyst")
        profile.current_streak = int(current_streak or 0)
        profile.longest_streak = int(longest_streak or 0)
        profile.last_activity_at = last_activity_at
        profile.total_scans = total_scans
        profile.total_reviewed_alerts = total_reviewed_alerts
        profile.total_badges = total_badges
        profile.updated_at = utc_now()
        db.session.flush()
        return profile

    def get_profile_payload(self, user_id: int) -> dict[str, Any]:
        self.backfill_identity_scan_completions(int(user_id))
        self.ensure_current_challenges_for_user(int(user_id))
        profile = self.ensure_profile(int(user_id))
        self._recalculate_profile_rollups(int(user_id), profile)
        db.session.commit()
        level_details = compute_level_details(profile.total_points)
        last_badge = (
            UserBadge.query.filter_by(user_id=int(user_id))
            .order_by(UserBadge.awarded_at.desc(), UserBadge.id.desc())
            .first()
        )

        return {
            "total_points": int(profile.total_points or 0),
            "current_level": int(level_details["current_level"]),
            "current_level_name": str(level_details["current_level_name"]),
            "next_level": level_details["next_level"],
            "next_level_name": level_details["next_level_name"],
            "points_to_next_level": int(level_details["points_to_next_level"] or 0),
            "level_progress_percent": float(level_details["level_progress_percent"] or 0.0),
            "current_streak": int(profile.current_streak or 0),
            "longest_streak": int(profile.longest_streak or 0),
            "total_scans": int(profile.total_scans or 0),
            "total_reviewed_alerts": int(profile.total_reviewed_alerts or 0),
            "total_badges": int(profile.total_badges or 0),
            "last_activity_at": serialize_datetime(profile.last_activity_at),
            "last_badge": None
            if last_badge is None
            else {
                "badge_code": last_badge.badge_code,
                "badge_title": last_badge.badge_title,
                "awarded_at": serialize_datetime(last_badge.awarded_at),
            },
        }

    def get_badges_payload(self, user_id: int) -> dict[str, Any]:
        self.backfill_identity_scan_completions(int(user_id))
        self.ensure_current_challenges_for_user(int(user_id))
        self._recalculate_profile_rollups(int(user_id))
        db.session.commit()
        unlocked_rows = UserBadge.query.filter_by(user_id=int(user_id)).all()
        unlocked_by_code = {badge.badge_code: badge for badge in unlocked_rows}
        progress = self._badge_progress(int(user_id))

        unlocked = []
        locked = []
        for badge_code, definition in BADGE_DEFINITIONS.items():
            progress_current = progress.get(badge_code, {}).get("current", 0)
            progress_target = progress.get(badge_code, {}).get(
                "target", definition.get("progress_target", 1)
            )
            normalized_target = max(int(progress_target or 0), 0)
            normalized_current = max(int(progress_current or 0), 0)
            if normalized_target > 0:
                normalized_current = min(normalized_current, normalized_target)
            item = {
                "badge_code": definition["badge_code"],
                "badge_title": definition["badge_title"],
                "badge_description": definition["badge_description"],
                "rarity": definition["rarity"],
                "unlocked": badge_code in unlocked_by_code,
                "awarded_at": serialize_datetime(
                    unlocked_by_code[badge_code].awarded_at
                )
                if badge_code in unlocked_by_code
                else None,
                "progress_current": normalized_current,
                "progress_target": normalized_target,
            }
            if badge_code in unlocked_by_code:
                unlocked.append(item)
            else:
                locked.append(item)

        unlocked.sort(key=lambda item: item["awarded_at"] or "", reverse=True)
        locked.sort(key=lambda item: (item["rarity"], item["badge_title"]))
        return {"unlocked": unlocked, "locked": locked}

    def get_challenges_payload(self, user_id: int) -> dict[str, Any]:
        self.backfill_identity_scan_completions(int(user_id))
        windows = self.ensure_current_challenges_for_user(int(user_id))
        db.session.commit()
        return {
            "daily": self._serialize_challenges(windows["daily"]),
            "weekly": self._serialize_challenges(windows["weekly"]),
        }

    def get_history_payload(self, user_id: int, limit: int = 15) -> dict[str, Any]:
        self.backfill_identity_scan_completions(int(user_id))
        limit_value = max(1, min(int(limit or 15), 50))
        events = (
            GamificationEvent.query.filter(
                GamificationEvent.user_id == int(user_id),
                GamificationEvent.points_awarded > 0,
            )
            .order_by(GamificationEvent.created_at.desc(), GamificationEvent.id.desc())
            .limit(min(max(limit_value * 8, 50), 250))
            .all()
        )
        history: list[dict[str, Any]] = []
        seen_access_keys: set[str] = set()
        for event in events:
            normalized_type = canonical_event_type(event.event_type)
            if normalized_type in ACCESS_EVENT_TYPES:
                logical_key = self._logical_access_key_from_event(
                    event,
                    canonical_type=normalized_type,
                )
                if logical_key and logical_key in seen_access_keys:
                    continue
                if logical_key:
                    seen_access_keys.add(logical_key)
            history.append(self._serialize_history_item(event))
            if len(history) >= limit_value:
                break
        return {
            "history": history,
            "count": len(history),
            "limit": limit_value,
        }

    def get_overview_payload(self, user_id: int) -> dict[str, Any]:
        return {
            "profile": self.get_profile_payload(int(user_id)),
            "badges": self.get_badges_payload(int(user_id)),
            "challenges": self.get_challenges_payload(int(user_id)),
            "history": self.get_history_payload(int(user_id), limit=8)["history"],
        }

    def get_alert_context(self, user_id: int, job_id: str, alert_id: str) -> dict[str, Any]:
        self.ensure_schema()
        review_state = UserAlertReviewState.query.filter_by(
            user_id=int(user_id),
            job_id=safe_str(job_id),
            alert_id=safe_str(alert_id),
        ).first()
        notes = (
            InvestigationNote.query.filter_by(
                user_id=int(user_id),
                job_id=safe_str(job_id),
                alert_id=safe_str(alert_id),
            )
            .order_by(InvestigationNote.created_at.desc(), InvestigationNote.id.desc())
            .all()
        )
        return {
            "review": None
            if review_state is None
            else {
                "review_status": review_state.review_status,
                "disposition": review_state.disposition,
                "first_viewed_at": serialize_datetime(review_state.first_viewed_at),
                "reviewed_at": serialize_datetime(review_state.reviewed_at),
                "last_viewed_at": serialize_datetime(review_state.last_viewed_at),
            },
            "notes": [
                {
                    "id": int(note.id),
                    "note_body": note.note_body,
                    "created_at": serialize_datetime(note.created_at),
                }
                for note in notes
            ],
        }

    def record_ui_event(
        self,
        user_id: int,
        event_type: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = dict(context or {})
        event_name = safe_str(event_type)
        current = ensure_utc(payload.get("occurred_at")) or utc_now()
        payload["occurred_at"] = current

        if event_name == "alert_viewed":
            self._touch_alert_state(
                int(user_id),
                safe_str(payload.get("job_id")),
                safe_str(payload.get("alert_id")),
                viewed_at=current,
            )
            db.session.commit()
        elif event_name == "alert_reviewed":
            self._touch_alert_state(
                int(user_id),
                safe_str(payload.get("job_id")),
                safe_str(payload.get("alert_id")),
                reviewed_at=current,
            )
            db.session.commit()
        elif event_name in {"alert_marked_true_positive", "alert_marked_false_positive"}:
            disposition = (
                "true_positive"
                if event_name == "alert_marked_true_positive"
                else "false_positive"
            )
            self._touch_alert_state(
                int(user_id),
                safe_str(payload.get("job_id")),
                safe_str(payload.get("alert_id")),
                reviewed_at=current,
                disposition=disposition,
            )
            db.session.commit()
        elif event_name == "investigation_note_added":
            note = self._create_note(
                int(user_id),
                safe_str(payload.get("job_id")),
                safe_str(payload.get("alert_id")),
                safe_str(payload.get("note_body")),
                current,
            )
            payload["note_id"] = int(note.id)
            payload["note_preview"] = compact_message(note.note_body, 120)
            db.session.commit()

        result = self.process_event(int(user_id), event_name, payload)
        if event_name in {
            "alert_viewed",
            "alert_reviewed",
            "alert_marked_true_positive",
            "alert_marked_false_positive",
            "investigation_note_added",
        }:
            result["alert_context"] = self.get_alert_context(
                int(user_id),
                safe_str(payload.get("job_id")),
                safe_str(payload.get("alert_id")),
            )
        return result

    def record_download_event(
        self,
        user_id: int,
        job_id: str,
        export_type: str,
        evidence_key: str | None = None,
    ) -> dict[str, Any]:
        event_type = "report_accessed" if export_type == "report" else "evidence_accessed"
        payload = {
            "job_id": safe_str(job_id),
            "evidence_key": evidence_key or "bundle",
            "evidence_context": evidence_key or "bundle",
            "access_method": "download_response",
        }
        return self.process_event(int(user_id), event_type, payload)

    def record_upload(
        self,
        user_id: int,
        job_id: str,
        file_hash: str | None,
        upload_name: str | None = None,
    ) -> dict[str, Any]:
        return self.process_event(
            int(user_id),
            "pcap_uploaded",
            {
                "job_id": safe_str(job_id),
                "file_hash": safe_str(file_hash) or None,
                "upload_name": safe_str(upload_name),
            },
        )

    def record_analysis_completion(
        self,
        user_id: int,
        job_id: str,
        file_hash: str | None,
        report: dict[str, Any] | None,
        upload_name: str | None = None,
    ) -> dict[str, Any]:
        metrics = extract_report_metrics(report)
        base_context = {
            "job_id": safe_str(job_id),
            "file_hash": safe_str(file_hash) or None,
            "upload_name": safe_str(upload_name),
            "report_metrics": metrics,
        }
        analysis_result = self.process_event(int(user_id), "analysis_completed", base_context)
        if not analysis_result.get("accepted"):
            return {"analysis_completed": analysis_result}

        previous = self.get_previous_completed_analysis_for_user(
            int(user_id),
            exclude_job_id=safe_str(job_id),
        )

        results: dict[str, Any] = {"analysis_completed": analysis_result}

        current_score = self._metric_float(metrics, "security_score")
        previous_score = self._event_metric_float(previous, "security_score")
        score_points = score_improvement_points(previous_score, current_score)
        if score_points > 0 and current_score is not None and previous_score is not None:
            results["security_score_improved"] = self.process_event(
                int(user_id),
                "security_score_improved",
                {
                    **base_context,
                    "score_points_override": score_points,
                    "score_delta": round(current_score - previous_score, 2),
                    "previous_score": previous_score,
                    "current_score": current_score,
                },
            )

        current_critical = self._metric_int(metrics, "critical_alert_count")
        previous_critical = self._event_metric_int(previous, "critical_alert_count")
        reduction_points = critical_reduction_points(previous_critical, current_critical)
        if reduction_points > 0:
            reduction_ratio = 0.0
            if previous_critical and previous_critical > 0:
                reduction_ratio = round(
                    ((previous_critical - current_critical) / previous_critical) * 100,
                    2,
                )
            results["critical_alerts_reduced"] = self.process_event(
                int(user_id),
                "critical_alerts_reduced",
                {
                    **base_context,
                    "critical_reduction_points_override": reduction_points,
                    "critical_reduction_ratio": reduction_ratio,
                    "previous_critical_count": previous_critical,
                    "current_critical_count": current_critical,
                },
            )

        if current_critical == 0:
            results["safe_scan_completed"] = self.process_event(
                int(user_id),
                "safe_scan_completed",
                base_context,
            )

        if current_critical == 0 and self._metric_int(metrics, "high_alert_count") == 0:
            results["clean_scan_completed"] = self.process_event(
                int(user_id),
                "clean_scan_completed",
                base_context,
            )

        return results

    def record_analysis_failure(
        self,
        user_id: int,
        job_id: str,
        file_hash: str | None,
        error_text: str | None,
    ) -> dict[str, Any]:
        return self.process_event(
            int(user_id),
            "analysis_failed",
            {
                "job_id": safe_str(job_id),
                "file_hash": safe_str(file_hash) or None,
                "error": compact_message(safe_str(error_text), 280),
            },
        )

    def record_identity_scan_completion(
        self,
        user_id: int,
        scan_id: int,
        risk_level: str | None = None,
        risk_score: int | None = None,
        total_findings: int | None = None,
        target_label: str | None = None,
        occurred_at: Any | None = None,
    ) -> dict[str, Any]:
        return self.process_event(
            int(user_id),
            "identity_scan_completed",
            {
                "identity_scan_id": int(scan_id),
                "risk_level": safe_str(risk_level) or "Low",
                "risk_score": safe_int(risk_score, 0),
                "total_findings": safe_int(total_findings, 0),
                "target_label": safe_str(target_label),
                "occurred_at": occurred_at,
            },
        )

    def backfill_identity_scan_completions(self, user_id: int, limit: int = 250) -> int:
        try:
            from services.identity_web_scraper.database import get_connection as get_identity_connection
        except Exception:
            return 0

        try:
            with get_identity_connection() as conn:
                rows = conn.execute(
                    """
                    SELECT id, email, username, domain, risk_level, risk_score, total_findings,
                           COALESCE(completed_at, created_at) AS occurred_at
                    FROM identity_scans
                    WHERE user_id=? AND status='completed'
                    ORDER BY id ASC
                    LIMIT ?
                    """,
                    (int(user_id), max(1, min(int(limit or 250), 500))),
                ).fetchall()
        except Exception:
            return 0

        accepted = 0
        for row in rows:
            scan_id = safe_int(row["id"], 0)
            if scan_id <= 0:
                continue
            target_label = " / ".join(
                value
                for value in [
                    safe_str(row["email"]),
                    safe_str(row["username"]),
                    safe_str(row["domain"]),
                ]
                if value
            )
            result = self.record_identity_scan_completion(
                int(user_id),
                scan_id,
                risk_level=safe_str(row["risk_level"]) or "Low",
                risk_score=safe_int(row["risk_score"], 0),
                total_findings=safe_int(row["total_findings"], 0),
                target_label=target_label,
                occurred_at=_parse_identity_timestamp(row["occurred_at"]),
            )
            if result.get("accepted"):
                accepted += 1
        return accepted

    def get_previous_completed_analysis_for_user(
        self,
        user_id: int,
        *,
        exclude_job_id: str | None = None,
    ) -> dict[str, Any] | None:
        query = GamificationEvent.query.filter_by(
            user_id=int(user_id),
            event_type="analysis_completed",
        ).order_by(GamificationEvent.created_at.desc(), GamificationEvent.id.desc())

        if exclude_job_id:
            query = query.filter(GamificationEvent.job_id != safe_str(exclude_job_id))

        event = query.first()
        if event is None:
            return None
        metadata = parse_metadata(event.metadata_json)
        return {
            "event": event,
            "metrics": metadata.get("metrics", {})
            if isinstance(metadata.get("metrics"), dict)
            else {},
        }

    def process_event(
        self,
        user_id: int,
        event_type: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.ensure_schema()
        current = ensure_utc((context or {}).get("occurred_at")) or utc_now()
        payload = dict(context or {})
        payload["occurred_at"] = current
        requested_event = safe_str(event_type)
        normalized_event = canonical_event_type(requested_event)
        payload["source_event_type"] = requested_event or normalized_event

        if requested_event not in EVENT_TYPES and normalized_event not in EVENT_TYPES:
            return {
                "accepted": False,
                "reason": "unsupported_event_type",
                "points_gained": 0,
            }

        prepared = self._prepare_event(int(user_id), normalized_event, payload)
        if not prepared.accepted and not prepared.force_record:
            return {
                "accepted": False,
                "reason": prepared.reason or "ineligible_event",
                "points_gained": 0,
            }

        profile = self.ensure_profile(int(user_id))
        self._recalculate_profile_rollups(int(user_id), profile)
        self.ensure_current_challenges_for_user(int(user_id), current)
        today_stat = self._ensure_daily_stat(int(user_id), current)
        had_meaningful_before = self._has_meaningful_activity(today_stat)
        old_level = int(profile.current_level or 1)

        created_events: list[GamificationEvent] = []
        total_points_gained = 0
        streak_updated = False

        try:
            base_event = self._create_event_row(int(user_id), prepared, current)
            if base_event is None:
                db.session.rollback()
                return {
                    "accepted": False,
                    "reason": "duplicate_event",
                    "points_gained": 0,
                }

            created_events.append(base_event)
            total_points_gained += int(base_event.points_awarded or 0)
            self._apply_event_effects(profile, today_stat, base_event, current)

            if (
                normalized_event in MEANINGFUL_ACTIVITY_EVENT_TYPES
                and prepared.accepted
                and not had_meaningful_before
            ):
                streak_events, streak_points, streak_updated = self._handle_streak(
                    int(user_id),
                    profile,
                    today_stat,
                    current,
                )
                created_events.extend(streak_events)
                total_points_gained += streak_points

            if normalized_event == "analysis_completed" and int(profile.total_scans or 0) == 1:
                first_scan_prepared = self._prepare_event(
                    int(user_id),
                    "first_scan_completed",
                    {"job_id": payload.get("job_id"), "occurred_at": current},
                )
                first_scan_event = self._create_event_row(
                    int(user_id), first_scan_prepared, current
                )
                if first_scan_event is not None:
                    created_events.append(first_scan_event)

            challenge_events, challenge_points = self._update_challenges_for_event(
                int(user_id),
                profile,
                today_stat,
                normalized_event,
                current,
            )
            created_events.extend(challenge_events)
            total_points_gained += challenge_points

            level_events = self._handle_level_change(profile, old_level, current)
            created_events.extend(level_events)

            badges_unlocked = self._evaluate_badges_for_user(
                int(user_id),
                profile,
                created_events[-1] if created_events else None,
            )

            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return {
                "accepted": False,
                "reason": "duplicate_event",
                "points_gained": 0,
            }
        except Exception:
            db.session.rollback()
            raise

        level_details = compute_level_details(profile.total_points)
        primary_history_message = (
            prepared.history_message
            if prepared.history_message
            else self._history_message_for_event(base_event)
            if base_event is not None
            else None
        )
        level_ups = []
        for item in created_events:
            if item.event_type != "level_up":
                continue
            metadata = parse_metadata(item.metadata_json)
            level_ups.append(
                {
                    "level": safe_int(metadata.get("new_level"), 0),
                    "level_name": safe_str(metadata.get("new_level_name")),
                }
            )

        return {
            "accepted": True,
            "points_gained": int(total_points_gained),
            "total_points": int(profile.total_points or 0),
            "current_level": int(level_details["current_level"]),
            "current_level_name": str(level_details["current_level_name"]),
            "level_progress_percent": float(level_details["level_progress_percent"] or 0.0),
            "badges_unlocked": badges_unlocked,
            "level_ups": level_ups,
            "streak_updated": bool(streak_updated),
            "current_streak": int(profile.current_streak or 0),
            "history_message": primary_history_message,
            "reward_breakdown": [
                {
                    "event_type": item.event_type,
                    "points_awarded": int(item.points_awarded or 0),
                    "created_at": serialize_datetime(item.created_at),
                    "message": self._history_message_for_event(item),
                }
                for item in created_events
                if int(item.points_awarded or 0) > 0
            ],
        }

    def _prepare_event(
        self,
        user_id: int,
        event_type: str,
        context: dict[str, Any],
    ) -> PreparedEvent:
        job_id = safe_str(context.get("job_id")) or None
        alert_id = safe_str(context.get("alert_id")) or None
        file_hash = safe_str(context.get("file_hash")) or None
        evidence_key = safe_str(context.get("evidence_key")) or None
        now = ensure_utc(context.get("occurred_at")) or utc_now()
        metrics = context.get("report_metrics")
        metrics = metrics if isinstance(metrics, dict) else {}

        metadata: dict[str, Any] = {
            "job_id": job_id,
            "alert_id": alert_id,
            "file_hash": file_hash,
        }
        if metrics:
            metadata["metrics"] = metrics

        if event_type == "pcap_uploaded":
            key_source = file_hash or job_id
            if not key_source:
                return PreparedEvent(False, "missing_context", None, 0, metadata, event_type=event_type)
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", key_source),
                points=int(POINTS[event_type]),
                metadata=metadata,
                job_id=job_id,
                file_hash=file_hash,
                event_type=event_type,
            )

        if event_type == "analysis_completed":
            key_source = file_hash or job_id
            if not key_source or not job_id:
                return PreparedEvent(False, "missing_context", None, 0, metadata, event_type=event_type)
            metadata["upload_name"] = safe_str(context.get("upload_name")) or None
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", key_source),
                points=int(POINTS[event_type]),
                metadata=metadata,
                job_id=job_id,
                file_hash=file_hash,
                event_type=event_type,
            )

        if event_type == "identity_scan_completed":
            scan_id = safe_int(context.get("identity_scan_id"), 0)
            if scan_id <= 0:
                return PreparedEvent(False, "missing_context", None, 0, metadata, event_type=event_type)
            metadata.update(
                {
                    "identity_scan_id": scan_id,
                    "risk_level": safe_str(context.get("risk_level")) or "Low",
                    "risk_score": safe_int(context.get("risk_score"), 0),
                    "total_findings": safe_int(context.get("total_findings"), 0),
                    "target_label": safe_str(context.get("target_label")),
                }
            )
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", scan_id),
                points=int(POINTS[event_type]),
                metadata=metadata,
                job_id=f"identity-scan-{scan_id}",
                event_type=event_type,
            )

        if event_type == "analysis_failed":
            key_source = job_id or file_hash
            if not key_source:
                return PreparedEvent(False, "missing_context", None, 0, metadata, event_type=event_type)
            metadata["error"] = safe_str(context.get("error"))
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", key_source),
                points=0,
                metadata=metadata,
                job_id=job_id,
                file_hash=file_hash,
                event_type=event_type,
                force_record=True,
            )

        if event_type == "report_accessed":
            if not job_id:
                return PreparedEvent(False, "missing_context", None, 0, metadata, event_type=event_type)
            if self._has_existing_access(
                int(user_id),
                event_type,
                job_id=job_id,
            ):
                return PreparedEvent(False, "duplicate_event", None, 0, metadata, event_type=event_type)
            metadata["access_method"] = safe_str(context.get("access_method")) or "access"
            metadata["source_event_type"] = safe_str(context.get("source_event_type")) or event_type
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", job_id),
                points=int(POINTS[event_type]),
                metadata=metadata,
                job_id=job_id,
                event_type=event_type,
            )

        if event_type == "alert_viewed":
            if not job_id or not alert_id:
                return PreparedEvent(False, "missing_context", None, 0, metadata, event_type=event_type)
            current_count = self._count_events_for_job(int(user_id), event_type, job_id)
            existing = self._event_exists(
                build_event_key(event_type, f"user{user_id}", job_id, alert_id)
            )
            if current_count >= 10 and not existing:
                return PreparedEvent(False, "job_cap_reached", None, 0, metadata, event_type=event_type)
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", job_id, alert_id),
                points=int(POINTS[event_type]),
                metadata=metadata,
                job_id=job_id,
                alert_id=alert_id,
                event_type=event_type,
            )

        if event_type == "evidence_accessed":
            if not job_id:
                return PreparedEvent(False, "missing_context", None, 0, metadata, event_type=event_type)
            evidence_context = evidence_key or safe_str(context.get("evidence_context")) or None
            resource_key = self._build_evidence_resource_key(
                alert_id,
                evidence_key=evidence_key,
                evidence_context=evidence_context,
            )
            if not resource_key:
                return PreparedEvent(False, "missing_evidence_context", None, 0, metadata, event_type=event_type)
            if self._has_existing_access(
                int(user_id),
                event_type,
                job_id=job_id,
                alert_id=alert_id,
                evidence_key=evidence_key,
                evidence_context=evidence_context,
            ):
                return PreparedEvent(False, "duplicate_event", None, 0, metadata, event_type=event_type)
            current_count = self._count_unique_accesses_for_job(int(user_id), event_type, job_id)
            if current_count >= 5:
                return PreparedEvent(False, "job_cap_reached", None, 0, metadata, event_type=event_type)
            metadata["access_method"] = safe_str(context.get("access_method")) or "access"
            metadata["evidence_key"] = evidence_context or evidence_key or "bundle"
            metadata["evidence_context"] = evidence_context or evidence_key or "bundle"
            metadata["evidence_resource_key"] = resource_key
            metadata["source_event_type"] = safe_str(context.get("source_event_type")) or event_type
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", job_id, resource_key),
                points=int(POINTS[event_type]),
                metadata=metadata,
                job_id=job_id,
                alert_id=alert_id,
                event_type=event_type,
            )

        if event_type in {
            "alert_reviewed",
            "investigation_note_added",
            "alert_marked_true_positive",
            "alert_marked_false_positive",
        }:
            if not job_id or not alert_id:
                return PreparedEvent(False, "missing_context", None, 0, metadata, event_type=event_type)

            if event_type == "investigation_note_added":
                note_body = safe_str(context.get("note_body"))
                if not note_body:
                    return PreparedEvent(False, "missing_note_body", None, 0, metadata, event_type=event_type)
                metadata["note_preview"] = safe_str(context.get("note_preview")) or compact_message(note_body, 120)
                key = build_event_key(event_type, f"user{user_id}", job_id, alert_id)
            elif event_type in {"alert_marked_true_positive", "alert_marked_false_positive"}:
                classification_exists = (
                    GamificationEvent.query.filter(
                        GamificationEvent.user_id == int(user_id),
                        GamificationEvent.alert_id == alert_id,
                        GamificationEvent.event_type.in_(
                            ["alert_marked_true_positive", "alert_marked_false_positive"]
                        ),
                    ).count()
                )
                if classification_exists > 0:
                    return PreparedEvent(False, "already_classified", None, 0, metadata, event_type=event_type)
                key = build_event_key("alert_classified", f"user{user_id}", job_id, alert_id)
            else:
                key = build_event_key(event_type, f"user{user_id}", job_id, alert_id)

            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=key,
                points=int(POINTS[event_type]),
                metadata=metadata,
                job_id=job_id,
                alert_id=alert_id,
                event_type=event_type,
            )

        if event_type == "security_score_improved":
            if not job_id:
                return PreparedEvent(False, "missing_context", None, 0, metadata, event_type=event_type)
            points = safe_int(context.get("score_points_override"), 0)
            if points <= 0:
                return PreparedEvent(False, "no_improvement", None, 0, metadata, event_type=event_type)
            metadata.update(
                {
                    "previous_score": safe_float(context.get("previous_score"), 0.0),
                    "current_score": safe_float(context.get("current_score"), 0.0),
                    "score_delta": safe_float(context.get("score_delta"), 0.0),
                }
            )
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", job_id),
                points=points,
                metadata=metadata,
                job_id=job_id,
                file_hash=file_hash,
                event_type=event_type,
            )

        if event_type == "critical_alerts_reduced":
            if not job_id:
                return PreparedEvent(False, "missing_context", None, 0, metadata, event_type=event_type)
            points = safe_int(context.get("critical_reduction_points_override"), 0)
            if points <= 0:
                return PreparedEvent(False, "no_reduction", None, 0, metadata, event_type=event_type)
            metadata.update(
                {
                    "previous_critical_count": safe_int(context.get("previous_critical_count"), 0),
                    "current_critical_count": safe_int(context.get("current_critical_count"), 0),
                    "critical_reduction_ratio": safe_float(context.get("critical_reduction_ratio"), 0.0),
                }
            )
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", job_id),
                points=points,
                metadata=metadata,
                job_id=job_id,
                file_hash=file_hash,
                event_type=event_type,
            )

        if event_type == "safe_scan_completed":
            if not job_id:
                return PreparedEvent(False, "missing_context", None, 0, metadata, event_type=event_type)
            if self._metric_int(metrics, "critical_alert_count") != 0:
                return PreparedEvent(False, "not_safe_scan", None, 0, metadata, event_type=event_type)
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", job_id),
                points=int(POINTS[event_type]),
                metadata=metadata,
                job_id=job_id,
                file_hash=file_hash,
                event_type=event_type,
            )

        if event_type == "clean_scan_completed":
            if not job_id:
                return PreparedEvent(False, "missing_context", None, 0, metadata, event_type=event_type)
            if self._metric_int(metrics, "critical_alert_count") != 0 or self._metric_int(
                metrics, "high_alert_count"
            ) != 0:
                return PreparedEvent(False, "not_clean_scan", None, 0, metadata, event_type=event_type)
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", job_id),
                points=int(POINTS[event_type]),
                metadata=metadata,
                job_id=job_id,
                file_hash=file_hash,
                event_type=event_type,
            )

        if event_type == "daily_streak_extended":
            day_key = safe_str(context.get("activity_date")) or activity_date(now).isoformat()
            metadata["activity_date"] = day_key
            metadata["streak_value"] = safe_int(context.get("streak_value"), 0)
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", day_key),
                points=int(POINTS[event_type]),
                metadata=metadata,
                event_type=event_type,
                force_record=True,
            )

        if event_type == "weekly_goal_completed":
            week_key = safe_str(context.get("week_key"))
            metadata["week_key"] = week_key
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", week_key),
                points=int(POINTS[event_type]),
                metadata=metadata,
                event_type=event_type,
                force_record=True,
            )

        if event_type == "challenge_completed":
            challenge_code = safe_str(context.get("challenge_code"))
            window_key = safe_str(context.get("window_key"))
            metadata.update(
                {
                    "challenge_code": challenge_code,
                    "challenge_title": safe_str(context.get("challenge_title")),
                    "challenge_type": safe_str(context.get("challenge_type")),
                }
            )
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", challenge_code, window_key),
                points=safe_int(context.get("reward_points"), 0),
                metadata=metadata,
                event_type=event_type,
                force_record=True,
            )

        if event_type == "level_up":
            new_level = safe_int(context.get("new_level"), 0)
            metadata["new_level"] = new_level
            metadata["new_level_name"] = safe_str(context.get("new_level_name"))
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}", new_level),
                points=0,
                metadata=metadata,
                event_type=event_type,
                force_record=True,
            )

        if event_type == "first_scan_completed":
            return PreparedEvent(
                accepted=True,
                reason=None,
                event_key=build_event_key(event_type, f"user{user_id}"),
                points=0,
                metadata=metadata,
                event_type=event_type,
                force_record=True,
            )

        return PreparedEvent(False, "unsupported_event_type", None, 0, metadata, event_type=event_type)

    def _create_event_row(
        self,
        user_id: int,
        prepared: PreparedEvent,
        current,
    ) -> GamificationEvent | None:
        if not prepared.event_key or not prepared.event_type:
            return None

        existing = GamificationEvent.query.filter_by(event_key=prepared.event_key).first()
        if existing is not None:
            return None

        event = GamificationEvent(
            user_id=int(user_id),
            event_type=prepared.event_type,
            event_key=prepared.event_key,
            job_id=prepared.job_id,
            alert_id=prepared.alert_id,
            file_hash=prepared.file_hash,
            points_awarded=int(prepared.points or 0),
            metadata_json=serialize_metadata(prepared.metadata),
            created_at=current,
        )
        db.session.add(event)
        db.session.flush()
        return event

    def _apply_event_effects(
        self,
        profile: UserGamificationProfile,
        today_stat: GamificationDailyStat,
        event: GamificationEvent,
        current,
    ) -> None:
        points = int(event.points_awarded or 0)
        if points > 0:
            profile.total_points = int(profile.total_points or 0) + points
            today_stat.points_earned = int(today_stat.points_earned or 0) + points

        if event.event_type in {"analysis_completed", "identity_scan_completed"}:
            profile.total_scans = int(profile.total_scans or 0) + 1
            today_stat.scans_completed = int(today_stat.scans_completed or 0) + 1
        elif event.event_type == "alert_reviewed":
            profile.total_reviewed_alerts = int(profile.total_reviewed_alerts or 0) + 1
            today_stat.alerts_reviewed = int(today_stat.alerts_reviewed or 0) + 1
        elif event.event_type == "report_accessed":
            today_stat.reports_opened = int(today_stat.reports_opened or 0) + 1
        elif event.event_type == "evidence_accessed":
            today_stat.evidence_opened = int(today_stat.evidence_opened or 0) + 1
        elif event.event_type == "investigation_note_added":
            today_stat.notes_added = int(today_stat.notes_added or 0) + 1

        profile.last_activity_at = current
        level = compute_level_details(int(profile.total_points or 0))
        profile.current_level = int(level["current_level"])
        profile.current_level_name = str(level["current_level_name"])
        profile.updated_at = current
        today_stat.updated_at = current

    def _ensure_daily_stat(self, user_id: int, current) -> GamificationDailyStat:
        day = activity_date(current)
        stat = GamificationDailyStat.query.filter_by(
            user_id=int(user_id),
            activity_date=day,
        ).first()
        if stat is not None:
            return stat

        stat = GamificationDailyStat(
            user_id=int(user_id),
            activity_date=day,
            points_earned=0,
            scans_completed=0,
            alerts_reviewed=0,
            reports_opened=0,
            evidence_opened=0,
            notes_added=0,
            created_at=current,
            updated_at=current,
        )
        db.session.add(stat)
        db.session.flush()
        return stat

    def _has_meaningful_activity(self, stat: GamificationDailyStat) -> bool:
        meaningful = (
            int(stat.scans_completed or 0)
            + int(stat.alerts_reviewed or 0)
            + int(stat.reports_opened or 0)
            + int(stat.notes_added or 0)
        )
        return meaningful > 0

    def _handle_streak(
        self,
        user_id: int,
        profile: UserGamificationProfile,
        today_stat: GamificationDailyStat,
        current,
    ) -> tuple[list[GamificationEvent], int, bool]:
        day = activity_date(current)
        previous_day = day - timedelta(days=1)

        previous_meaningful_day = (
            db.session.query(func.max(GamificationDailyStat.activity_date))
            .filter(
                GamificationDailyStat.user_id == int(user_id),
                GamificationDailyStat.activity_date < day,
                (
                    GamificationDailyStat.scans_completed
                    + GamificationDailyStat.alerts_reviewed
                    + GamificationDailyStat.reports_opened
                    + GamificationDailyStat.notes_added
                )
                > 0,
            )
            .scalar()
        )

        if previous_meaningful_day == previous_day:
            profile.current_streak = int(profile.current_streak or 0) + 1
        else:
            profile.current_streak = 1

        profile.longest_streak = max(
            int(profile.longest_streak or 0),
            int(profile.current_streak or 0),
        )

        prepared = self._prepare_event(
            int(user_id),
            "daily_streak_extended",
            {
                "activity_date": day.isoformat(),
                "streak_value": int(profile.current_streak or 0),
                "occurred_at": current,
            },
        )
        event = self._create_event_row(int(user_id), prepared, current)
        if event is None:
            return [], 0, False

        self._apply_event_effects(profile, today_stat, event, current)
        return [event], int(event.points_awarded or 0), True

    def _update_challenges_for_event(
        self,
        user_id: int,
        profile: UserGamificationProfile,
        today_stat: GamificationDailyStat,
        event_type: str,
        current,
    ) -> tuple[list[GamificationEvent], int]:
        created_events: list[GamificationEvent] = []
        total_points = 0
        self.ensure_current_challenges_for_user(int(user_id), current)
        active_challenges = (
            UserChallenge.query.filter_by(user_id=int(user_id), status="active")
            .filter(UserChallenge.starts_at <= current, UserChallenge.expires_at > current)
            .all()
        )

        weekly_start, weekly_end = current_weekly_window(current)
        weekly_completed_now = False

        for challenge in active_challenges:
            definition = CHALLENGE_DEFINITIONS.get(challenge.challenge_code, {})
            tracked_event_types = definition.get("tracked_event_types", set())
            if event_type not in tracked_event_types:
                continue

            challenge.current_value = min(
                int(challenge.target_value or 0),
                int(challenge.current_value or 0) + 1,
            )
            challenge.updated_at = current
            if challenge.current_value < int(challenge.target_value or 0):
                continue

            challenge.status = "completed"
            challenge.completed_at = current
            prepared = self._prepare_event(
                int(user_id),
                "challenge_completed",
                {
                    "challenge_code": challenge.challenge_code,
                    "challenge_title": challenge.title,
                    "challenge_type": challenge.challenge_type,
                    "reward_points": int(challenge.reward_points or 0),
                    "window_key": challenge.starts_at.date().isoformat(),
                    "occurred_at": current,
                },
            )
            event = self._create_event_row(int(user_id), prepared, current)
            if event is None:
                continue
            self._apply_event_effects(profile, today_stat, event, current)
            created_events.append(event)
            total_points += int(event.points_awarded or 0)
            if challenge.challenge_type == "weekly":
                weekly_completed_now = True

        if weekly_completed_now:
            current_weekly = (
                UserChallenge.query.filter_by(
                    user_id=int(user_id),
                    challenge_type="weekly",
                    starts_at=weekly_start,
                    expires_at=weekly_end,
                ).all()
            )
            if current_weekly and all(item.status == "completed" for item in current_weekly):
                prepared = self._prepare_event(
                    int(user_id),
                    "weekly_goal_completed",
                    {
                        "week_key": weekly_start.date().isoformat(),
                        "occurred_at": current,
                    },
                )
                event = self._create_event_row(int(user_id), prepared, current)
                if event is not None:
                    self._apply_event_effects(profile, today_stat, event, current)
                    created_events.append(event)
                    total_points += int(event.points_awarded or 0)

        return created_events, total_points

    def _handle_level_change(
        self,
        profile: UserGamificationProfile,
        old_level: int,
        current,
    ) -> list[GamificationEvent]:
        created_events: list[GamificationEvent] = []
        new_details = compute_level_details(int(profile.total_points or 0))
        new_level = int(new_details["current_level"])
        if new_level <= int(old_level or 1):
            return created_events

        for level_value in range(int(old_level or 1) + 1, new_level + 1):
            level_definition = next(level for level in LEVELS if level.level == level_value)
            prepared = self._prepare_event(
                int(profile.user_id),
                "level_up",
                {
                    "new_level": level_value,
                    "new_level_name": level_definition.name,
                    "occurred_at": current,
                },
            )
            event = self._create_event_row(int(profile.user_id), prepared, current)
            if event is not None:
                created_events.append(event)

        profile.current_level = new_level
        profile.current_level_name = str(new_details["current_level_name"])
        return created_events

    def _evaluate_badges_for_user(
        self,
        user_id: int,
        profile: UserGamificationProfile,
        source_event: GamificationEvent | None,
    ) -> list[dict[str, Any]]:
        progress = self._badge_progress(int(user_id), profile=profile)
        existing = {
            row.badge_code
            for row in UserBadge.query.filter_by(user_id=int(user_id)).all()
        }
        unlocked: list[dict[str, Any]] = []

        for badge_code, definition in BADGE_DEFINITIONS.items():
            if badge_code in existing:
                continue

            progress_item = progress.get(badge_code, {})
            current_value = int(progress_item.get("current", 0))
            target_value = int(
                progress_item.get("target", definition.get("progress_target", 1))
            )
            if current_value < target_value:
                continue

            badge = UserBadge(
                user_id=int(user_id),
                badge_code=definition["badge_code"],
                badge_title=definition["badge_title"],
                badge_description=definition["badge_description"],
                rarity=definition["rarity"],
                awarded_at=utc_now(),
                source_event_id=source_event.id if source_event is not None else None,
            )
            db.session.add(badge)
            existing.add(badge_code)
            profile.total_badges = int(profile.total_badges or 0) + 1
            unlocked.append(
                {
                    "badge_code": badge.badge_code,
                    "badge_title": badge.badge_title,
                    "badge_description": badge.badge_description,
                    "rarity": badge.rarity,
                    "awarded_at": serialize_datetime(badge.awarded_at),
                }
            )

        return unlocked

    def _badge_progress(
        self,
        user_id: int,
        *,
        profile: UserGamificationProfile | None = None,
    ) -> dict[str, dict[str, int]]:
        profile = profile or self.ensure_profile(int(user_id))
        profile = self._recalculate_profile_rollups(int(user_id), profile)

        event_counts = defaultdict(int)
        counts = (
            db.session.query(
                GamificationEvent.event_type,
                func.count(GamificationEvent.id),
            )
            .filter(GamificationEvent.user_id == int(user_id))
            .group_by(GamificationEvent.event_type)
            .all()
        )
        for event_type, count in counts:
            normalized_type = canonical_event_type(str(event_type))
            if normalized_type in ACCESS_EVENT_TYPES:
                continue
            event_counts[normalized_type] += int(count or 0)

        event_counts["report_accessed"] = self._count_unique_accesses_for_job(
            int(user_id),
            "report_accessed",
        )
        event_counts["evidence_accessed"] = self._count_unique_accesses_for_job(
            int(user_id),
            "evidence_accessed",
        )

        completed_analysis_events = (
            GamificationEvent.query.filter_by(
                user_id=int(user_id),
                event_type="analysis_completed",
            )
            .order_by(GamificationEvent.created_at.asc(), GamificationEvent.id.asc())
            .all()
        )
        safe_streak = 0
        best_safe_streak = 0
        score_85_count = 0
        for event in completed_analysis_events:
            metrics = parse_metadata(event.metadata_json).get("metrics", {})
            if not isinstance(metrics, dict):
                metrics = {}
            if safe_int(metrics.get("critical_alert_count"), 0) == 0:
                safe_streak += 1
                best_safe_streak = max(best_safe_streak, safe_streak)
            else:
                safe_streak = 0
            if safe_float(metrics.get("security_score"), -1.0) >= 85:
                score_85_count += 1

        total_scan_events = int(profile.total_scans or 0)
        if total_scan_events <= 0:
            total_scan_events = event_counts["analysis_completed"] + event_counts["identity_scan_completed"]

        weekly_completed_count = UserChallenge.query.filter_by(
            user_id=int(user_id),
            challenge_type="weekly",
            status="completed",
        ).count()

        return {
            "first_scan": {"current": total_scan_events, "target": 1},
            "report_explorer": {"current": event_counts["report_accessed"], "target": 1},
            "evidence_explorer": {"current": event_counts["evidence_accessed"], "target": 1},
            "alert_reviewer": {"current": int(profile.total_reviewed_alerts or 0), "target": 10},
            "investigator": {"current": int(profile.total_reviewed_alerts or 0), "target": 25},
            "risk_reducer": {"current": event_counts["security_score_improved"], "target": 1},
            "critical_cleaner": {"current": event_counts["safe_scan_completed"], "target": 1},
            "safe_streak": {"current": best_safe_streak, "target": 3},
            "daily_defender": {"current": int(profile.current_streak or 0), "target": 3},
            "weekly_analyst": {
                "current": max(event_counts["weekly_goal_completed"], weekly_completed_count),
                "target": 1,
            },
            "security_champion": {"current": score_85_count, "target": 3},
            "elite_guardian": {"current": int(profile.current_level or 1), "target": 7},
        }

    def _serialize_challenges(self, challenges: list[UserChallenge]) -> list[dict[str, Any]]:
        serialized = []
        for challenge in challenges:
            target_value = max(int(challenge.target_value or 0), 0)
            current_value = max(int(challenge.current_value or 0), 0)
            if target_value > 0:
                current_value = min(current_value, target_value)
            serialized.append(
                {
                    "challenge_code": challenge.challenge_code,
                    "challenge_type": challenge.challenge_type,
                    "title": challenge.title,
                    "description": challenge.description,
                    "target_value": target_value,
                    "current_value": current_value,
                    "reward_points": int(challenge.reward_points or 0),
                    "status": challenge.status,
                    "starts_at": serialize_datetime(challenge.starts_at),
                    "expires_at": serialize_datetime(challenge.expires_at),
                    "completed_at": serialize_datetime(challenge.completed_at),
                }
            )
        serialized.sort(key=lambda item: item["challenge_code"])
        return serialized

    def _serialize_history_item(self, event: GamificationEvent) -> dict[str, Any]:
        normalized_type = canonical_event_type(event.event_type)
        return {
            "event_type": normalized_type,
            "points_awarded": int(event.points_awarded or 0),
            "created_at": serialize_datetime(event.created_at),
            "human_readable_reason": self._history_message_for_event(event),
            "job_id": event.job_id,
            "alert_id": event.alert_id,
        }

    def _history_message_for_event(self, event: GamificationEvent) -> str:
        metadata = parse_metadata(event.metadata_json)
        normalized_type = canonical_event_type(event.event_type)
        template = HISTORY_REASON_TEMPLATES.get(
            normalized_type,
            "You earned +{points} points.",
        )

        if normalized_type == "challenge_completed":
            title = safe_str(metadata.get("challenge_title"))
            if title:
                return f"You earned +{int(event.points_awarded or 0)} points for completing '{title}'."

        if normalized_type == "weekly_goal_completed":
            return "You earned +15 points for completing all weekly goals."

        if normalized_type == "security_score_improved":
            delta = safe_float(metadata.get("score_delta"), 0.0)
            if delta > 0:
                return (
                    f"You earned +{int(event.points_awarded or 0)} points for improving "
                    f"your security score by {round(delta, 1)}."
                )

        if normalized_type == "critical_alerts_reduced":
            reduction = safe_float(metadata.get("critical_reduction_ratio"), 0.0)
            if reduction > 0:
                return (
                    f"You earned +{int(event.points_awarded or 0)} points for reducing "
                    f"critical alerts by {round(reduction, 1)}%."
                )

        if normalized_type == "investigation_note_added":
            preview = safe_str(metadata.get("note_preview"))
            if preview:
                return (
                    f"You earned +{int(event.points_awarded or 0)} points for adding a note: "
                    f"{preview}"
                )

        return template.format(points=int(event.points_awarded or 0))

    def _event_exists(self, event_key: str) -> bool:
        return (
            GamificationEvent.query.filter_by(event_key=event_key)
            .with_entities(GamificationEvent.id)
            .first()
            is not None
        )

    def _count_events_for_job(self, user_id: int, event_type: str, job_id: str) -> int:
        return (
            GamificationEvent.query.filter_by(
                user_id=int(user_id),
                event_type=event_type,
                job_id=safe_str(job_id),
            ).count()
        )

    def _touch_alert_state(
        self,
        user_id: int,
        job_id: str,
        alert_id: str,
        *,
        viewed_at=None,
        reviewed_at=None,
        disposition: str | None = None,
    ) -> UserAlertReviewState:
        if not job_id or not alert_id:
            raise ValueError("job_id and alert_id are required")
        current = ensure_utc(viewed_at or reviewed_at) or utc_now()
        state = UserAlertReviewState.query.filter_by(
            user_id=int(user_id),
            job_id=job_id,
            alert_id=alert_id,
        ).first()
        if state is None:
            state = UserAlertReviewState(
                user_id=int(user_id),
                job_id=job_id,
                alert_id=alert_id,
                review_status="new",
                created_at=current,
                updated_at=current,
            )
            db.session.add(state)

        if viewed_at:
            state.last_viewed_at = current
            if state.first_viewed_at is None:
                state.first_viewed_at = current
        if reviewed_at:
            state.review_status = "reviewed"
            state.reviewed_at = current
            if state.first_viewed_at is None:
                state.first_viewed_at = current
            state.last_viewed_at = current
        if disposition:
            state.disposition = disposition
            state.review_status = "reviewed"
            state.reviewed_at = current
        state.updated_at = current
        db.session.flush()
        return state

    def _create_note(
        self,
        user_id: int,
        job_id: str,
        alert_id: str,
        note_body: str,
        current,
    ) -> InvestigationNote:
        if not job_id or not alert_id:
            raise ValueError("job_id and alert_id are required")
        trimmed = safe_str(note_body)
        if not trimmed:
            raise ValueError("note_body is required")
        if len(trimmed) > 2000:
            raise ValueError("note_body must be 2000 characters or fewer")

        note = InvestigationNote(
            user_id=int(user_id),
            job_id=job_id,
            alert_id=alert_id,
            note_body=trimmed,
            created_at=current,
        )
        db.session.add(note)
        db.session.flush()
        return note

    def _metric_int(self, metrics: dict[str, Any], key: str) -> int:
        return safe_int(metrics.get(key), 0)

    def _metric_float(self, metrics: dict[str, Any], key: str) -> float | None:
        value = safe_float(metrics.get(key), -1.0)
        return None if value < 0 else value

    def _event_metric_int(self, previous: dict[str, Any] | None, key: str) -> int | None:
        if not previous:
            return None
        metrics = previous.get("metrics")
        if not isinstance(metrics, dict):
            return None
        return safe_int(metrics.get(key), 0)

    def _event_metric_float(self, previous: dict[str, Any] | None, key: str) -> float | None:
        if not previous:
            return None
        metrics = previous.get("metrics")
        if not isinstance(metrics, dict):
            return None
        return self._metric_float(metrics, key)
