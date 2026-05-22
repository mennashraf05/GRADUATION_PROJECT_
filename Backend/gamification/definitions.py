from __future__ import annotations

from dataclasses import dataclass


LEGACY_EVENT_ALIASES = {
    "report_opened": "report_accessed",
    "report_downloaded": "report_accessed",
    "evidence_opened": "evidence_accessed",
    "evidence_downloaded": "evidence_accessed",
}

ACCESS_EVENT_TYPES = {
    "report_accessed",
    "evidence_accessed",
}

ACCESS_EVENT_QUERY_TYPES = {
    "report_accessed": {"report_accessed", "report_opened", "report_downloaded"},
    "evidence_accessed": {"evidence_accessed", "evidence_opened", "evidence_downloaded"},
}

EVENT_TYPES = {
    "pcap_uploaded",
    "analysis_completed",
    "identity_scan_completed",
    "analysis_failed",
    "report_accessed",
    "report_opened",
    "alert_viewed",
    "evidence_accessed",
    "evidence_opened",
    "report_downloaded",
    "evidence_downloaded",
    "alert_reviewed",
    "investigation_note_added",
    "alert_marked_true_positive",
    "alert_marked_false_positive",
    "security_score_improved",
    "critical_alerts_reduced",
    "safe_scan_completed",
    "clean_scan_completed",
    "daily_streak_extended",
    "weekly_goal_completed",
    "challenge_completed",
    "level_up",
    "first_scan_completed",
}

UI_EVENT_TYPES = {
    "report_accessed",
    "report_opened",
    "alert_viewed",
    "evidence_accessed",
    "evidence_opened",
    "alert_reviewed",
    "investigation_note_added",
    "alert_marked_true_positive",
    "alert_marked_false_positive",
}

MEANINGFUL_ACTIVITY_EVENT_TYPES = {
    "analysis_completed",
    "identity_scan_completed",
    "report_accessed",
    "alert_reviewed",
    "investigation_note_added",
}

POINTS = {
    "pcap_uploaded": 5,
    "analysis_completed": 5,
    "identity_scan_completed": 5,
    "analysis_failed": 0,
    "report_accessed": 2,
    "report_opened": 2,
    "alert_viewed": 1,
    "evidence_accessed": 2,
    "evidence_opened": 2,
    "report_downloaded": 2,
    "evidence_downloaded": 2,
    "alert_reviewed": 3,
    "investigation_note_added": 4,
    "alert_marked_true_positive": 2,
    "alert_marked_false_positive": 2,
    "safe_scan_completed": 12,
    "clean_scan_completed": 20,
    "daily_streak_extended": 3,
    "weekly_goal_completed": 15,
    "level_up": 0,
    "first_scan_completed": 0,
}

HISTORY_REASON_TEMPLATES = {
    "pcap_uploaded": "You earned +{points} points for submitting a new PCAP.",
    "analysis_completed": "You earned +{points} points for completing a unique analysis.",
    "identity_scan_completed": "You earned +{points} points for completing an Identity scan.",
    "analysis_failed": "The analysis failed. No points were awarded.",
    "report_accessed": "You earned +{points} points for accessing an analysis report.",
    "report_opened": "You earned +{points} points for accessing an analysis report.",
    "alert_viewed": "You earned +{points} points for viewing an alert.",
    "evidence_accessed": "You earned +{points} points for accessing evidence context.",
    "evidence_opened": "You earned +{points} points for accessing evidence context.",
    "report_downloaded": "You earned +{points} points for accessing an analysis report.",
    "evidence_downloaded": "You earned +{points} points for accessing evidence context.",
    "alert_reviewed": "You earned +{points} points for reviewing an alert.",
    "investigation_note_added": "You earned +{points} points for adding an investigation note.",
    "alert_marked_true_positive": "You earned +{points} points for marking an alert as a true positive.",
    "alert_marked_false_positive": "You earned +{points} points for marking an alert as a false positive.",
    "security_score_improved": "You earned +{points} points for improving your security score.",
    "critical_alerts_reduced": "You earned +{points} points for reducing critical alerts.",
    "safe_scan_completed": "You earned +{points} points for completing a scan with zero critical alerts.",
    "clean_scan_completed": "You earned +{points} points for completing a fully clean scan.",
    "daily_streak_extended": "You earned +{points} points for extending your daily streak.",
    "weekly_goal_completed": "You earned +{points} points for completing your weekly goal.",
    "challenge_completed": "You earned +{points} points for completing a challenge.",
    "level_up": "Level up unlocked.",
    "first_scan_completed": "You completed your first eligible scan.",
}


@dataclass(frozen=True)
class LevelDefinition:
    level: int
    name: str
    min_points: int
    max_points: int | None


LEVELS: tuple[LevelDefinition, ...] = (
    LevelDefinition(1, "Beginner Analyst", 0, 49),
    LevelDefinition(2, "Threat Observer", 50, 149),
    LevelDefinition(3, "Security Reviewer", 150, 299),
    LevelDefinition(4, "Threat Hunter", 300, 499),
    LevelDefinition(5, "Security Champion", 500, 799),
    LevelDefinition(6, "Defense Strategist", 800, 1199),
    LevelDefinition(7, "Elite Guardian", 1200, None),
)


def compute_level_details(total_points: int) -> dict[str, float | int | str | None]:
    points = max(int(total_points or 0), 0)
    current = LEVELS[0]
    next_level = None

    for index, level in enumerate(LEVELS):
        if points >= level.min_points and (
            level.max_points is None or points <= level.max_points
        ):
            current = level
            next_level = LEVELS[index + 1] if index + 1 < len(LEVELS) else None
            break

    if next_level is None:
        progress = 100.0
        points_to_next = 0
    else:
        span = max(next_level.min_points - current.min_points, 1)
        progress = round(((points - current.min_points) / span) * 100, 1)
        progress = max(0.0, min(progress, 100.0))
        points_to_next = max(next_level.min_points - points, 0)

    return {
        "current_level": current.level,
        "current_level_name": current.name,
        "next_level": next_level.level if next_level else None,
        "next_level_name": next_level.name if next_level else None,
        "points_to_next_level": points_to_next,
        "level_progress_percent": progress,
    }


BADGE_DEFINITIONS = {
    "first_scan": {
        "badge_code": "first_scan",
        "badge_title": "First Scan",
        "badge_description": "Completed your first PCAP analysis",
        "rarity": "common",
        "progress_target": 1,
    },
    "report_explorer": {
        "badge_code": "report_explorer",
        "badge_title": "Report Explorer",
        "badge_description": "Accessed your first analysis report",
        "rarity": "common",
        "progress_target": 1,
    },
    "evidence_explorer": {
        "badge_code": "evidence_explorer",
        "badge_title": "Evidence Explorer",
        "badge_description": "Accessed evidence for the first time",
        "rarity": "common",
        "progress_target": 1,
    },
    "alert_reviewer": {
        "badge_code": "alert_reviewer",
        "badge_title": "Alert Reviewer",
        "badge_description": "Reviewed 10 alerts",
        "rarity": "common",
        "progress_target": 10,
    },
    "investigator": {
        "badge_code": "investigator",
        "badge_title": "Investigator",
        "badge_description": "Reviewed 25 alerts",
        "rarity": "rare",
        "progress_target": 25,
    },
    "risk_reducer": {
        "badge_code": "risk_reducer",
        "badge_title": "Risk Reducer",
        "badge_description": "Improved your security score for the first time",
        "rarity": "rare",
        "progress_target": 1,
    },
    "critical_cleaner": {
        "badge_code": "critical_cleaner",
        "badge_title": "Critical Cleaner",
        "badge_description": "Completed an analysis with zero critical alerts",
        "rarity": "rare",
        "progress_target": 1,
    },
    "safe_streak": {
        "badge_code": "safe_streak",
        "badge_title": "Safe Streak",
        "badge_description": "Completed 3 eligible analyses in a row with zero critical alerts",
        "rarity": "epic",
        "progress_target": 3,
    },
    "daily_defender": {
        "badge_code": "daily_defender",
        "badge_title": "Daily Defender",
        "badge_description": "Maintained a 3-day active streak",
        "rarity": "rare",
        "progress_target": 3,
    },
    "weekly_analyst": {
        "badge_code": "weekly_analyst",
        "badge_title": "Weekly Analyst",
        "badge_description": "Completed your weekly challenge",
        "rarity": "rare",
        "progress_target": 1,
    },
    "security_champion": {
        "badge_code": "security_champion",
        "badge_title": "Security Champion",
        "badge_description": "Achieved a security score of at least 85 in 3 completed analyses",
        "rarity": "legendary",
        "progress_target": 3,
    },
    "elite_guardian": {
        "badge_code": "elite_guardian",
        "badge_title": "Elite Guardian",
        "badge_description": "Reached Level 7",
        "rarity": "legendary",
        "progress_target": 7,
    },
}

DAILY_CHALLENGE_DEFINITIONS = {
    "open_one_report": {
        "challenge_code": "open_one_report",
        "challenge_type": "daily",
        "title": "Access 1 report",
        "description": "Access one analysis report today.",
        "target_value": 1,
        "reward_points": 5,
        "tracked_event_types": {"report_accessed"},
    },
    "review_three_alerts": {
        "challenge_code": "review_three_alerts",
        "challenge_type": "daily",
        "title": "Review 3 alerts",
        "description": "Review three alerts today.",
        "target_value": 3,
        "reward_points": 8,
        "tracked_event_types": {"alert_reviewed"},
    },
    "open_two_evidence_items": {
        "challenge_code": "open_two_evidence_items",
        "challenge_type": "daily",
        "title": "Access evidence twice",
        "description": "Access two evidence items today.",
        "target_value": 2,
        "reward_points": 6,
        "tracked_event_types": {"evidence_accessed"},
    },
}

WEEKLY_CHALLENGE_DEFINITIONS = {
    "complete_three_scans": {
        "challenge_code": "complete_three_scans",
        "challenge_type": "weekly",
        "title": "Complete 3 analyses this week",
        "description": "Finish three eligible analyses or Identity scans this week.",
        "target_value": 3,
        "reward_points": 15,
        "tracked_event_types": {"analysis_completed", "identity_scan_completed"},
    },
    "improve_score_once": {
        "challenge_code": "improve_score_once",
        "challenge_type": "weekly",
        "title": "Improve security score once this week",
        "description": "Improve your security score at least once this week.",
        "target_value": 1,
        "reward_points": 15,
        "tracked_event_types": {"security_score_improved"},
    },
    "review_ten_alerts": {
        "challenge_code": "review_ten_alerts",
        "challenge_type": "weekly",
        "title": "Review 10 alerts this week",
        "description": "Review ten alerts this week.",
        "target_value": 10,
        "reward_points": 18,
        "tracked_event_types": {"alert_reviewed"},
    },
}

CHALLENGE_DEFINITIONS = {
    **DAILY_CHALLENGE_DEFINITIONS,
    **WEEKLY_CHALLENGE_DEFINITIONS,
}


def canonical_event_type(event_type: str | None) -> str:
    normalized = str(event_type or "").strip().lower()
    return LEGACY_EVENT_ALIASES.get(normalized, normalized)
