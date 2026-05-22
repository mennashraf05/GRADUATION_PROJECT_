from __future__ import annotations

from datetime import UTC, datetime, date

from sqlalchemy import UniqueConstraint

from extensions import db


def utc_now() -> datetime:
    return datetime.now(UTC)


class GamificationEvent(db.Model):
    __tablename__ = "gamification_event"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    event_key = db.Column(db.String(255), nullable=False, unique=True, index=True)
    job_id = db.Column(db.String(80), nullable=True, index=True)
    alert_id = db.Column(db.String(255), nullable=True, index=True)
    file_hash = db.Column(db.String(128), nullable=True, index=True)
    points_awarded = db.Column(db.Integer, nullable=False, default=0)
    metadata_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now, index=True)


class UserGamificationProfile(db.Model):
    __tablename__ = "user_gamification_profile"

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    total_points = db.Column(db.Integer, nullable=False, default=0)
    current_level = db.Column(db.Integer, nullable=False, default=1)
    current_level_name = db.Column(db.String(80), nullable=False, default="Beginner Analyst")
    current_streak = db.Column(db.Integer, nullable=False, default=0)
    longest_streak = db.Column(db.Integer, nullable=False, default=0)
    last_activity_at = db.Column(db.DateTime, nullable=True, index=True)
    total_scans = db.Column(db.Integer, nullable=False, default=0)
    total_reviewed_alerts = db.Column(db.Integer, nullable=False, default=0)
    total_badges = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)


class UserBadge(db.Model):
    __tablename__ = "user_badge"
    __table_args__ = (UniqueConstraint("user_id", "badge_code", name="uq_user_badge_code"),)

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    badge_code = db.Column(db.String(80), nullable=False, index=True)
    badge_title = db.Column(db.String(120), nullable=False)
    badge_description = db.Column(db.String(255), nullable=False)
    rarity = db.Column(db.String(32), nullable=False)
    awarded_at = db.Column(db.DateTime, nullable=False, default=utc_now, index=True)
    source_event_id = db.Column(
        db.Integer,
        db.ForeignKey("gamification_event.id"),
        nullable=True,
        index=True,
    )


class UserChallenge(db.Model):
    __tablename__ = "user_challenge"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "challenge_code",
            "challenge_type",
            "starts_at",
            "expires_at",
            name="uq_user_challenge_window",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    challenge_code = db.Column(db.String(80), nullable=False, index=True)
    challenge_type = db.Column(db.String(16), nullable=False, index=True)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    target_value = db.Column(db.Integer, nullable=False, default=0)
    current_value = db.Column(db.Integer, nullable=False, default=0)
    reward_points = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(16), nullable=False, default="active", index=True)
    starts_at = db.Column(db.DateTime, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)


class GamificationDailyStat(db.Model):
    __tablename__ = "gamification_daily_stat"
    __table_args__ = (
        UniqueConstraint("user_id", "activity_date", name="uq_gamification_daily_stat"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    activity_date = db.Column(db.Date, nullable=False, index=True)
    points_earned = db.Column(db.Integer, nullable=False, default=0)
    scans_completed = db.Column(db.Integer, nullable=False, default=0)
    alerts_reviewed = db.Column(db.Integer, nullable=False, default=0)
    reports_opened = db.Column(db.Integer, nullable=False, default=0)
    evidence_opened = db.Column(db.Integer, nullable=False, default=0)
    notes_added = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)


class UserAlertReviewState(db.Model):
    __tablename__ = "user_alert_review_state"
    __table_args__ = (
        UniqueConstraint("user_id", "job_id", "alert_id", name="uq_user_alert_review_state"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    job_id = db.Column(db.String(80), nullable=False, index=True)
    alert_id = db.Column(db.String(255), nullable=False, index=True)
    review_status = db.Column(db.String(20), nullable=False, default="new")
    disposition = db.Column(db.String(32), nullable=True)
    first_viewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    last_viewed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)


class InvestigationNote(db.Model):
    __tablename__ = "investigation_note"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    job_id = db.Column(db.String(80), nullable=False, index=True)
    alert_id = db.Column(db.String(255), nullable=False, index=True)
    note_body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now, index=True)


def activity_date_utc(value: datetime | None = None) -> date:
    current = value or utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC).date()
