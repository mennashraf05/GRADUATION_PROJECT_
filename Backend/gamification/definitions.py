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
    "phishing_scan_completed",
    "phishing_safe_scan_completed",
    "phishing_risky_url_detected",
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
    "vault_file_uploaded",
    "vault_file_downloaded",
    "vault_integrity_verified",
    "vault_offline_enabled",
    "vault_offline_disabled",
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
    "phishing_scan_completed",
    "phishing_safe_scan_completed",
    "phishing_risky_url_detected",
    "report_accessed",
    "alert_reviewed",
    "investigation_note_added",
    "vault_file_uploaded",
    "vault_file_downloaded",
    "vault_integrity_verified",
    "vault_offline_enabled",
    "vault_offline_disabled",
}

POINTS = {
    "pcap_uploaded": 5,
    "analysis_completed": 5,
    "identity_scan_completed": 5,
    "phishing_scan_completed": 5,
    "phishing_safe_scan_completed": 5,
    "phishing_risky_url_detected": 8,
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
    "vault_file_uploaded": 5,
    "vault_file_downloaded": 2,
    "vault_integrity_verified": 4,
    "vault_offline_enabled": 1,
    "vault_offline_disabled": 2,
}

HISTORY_REASON_TEMPLATES = {
    "pcap_uploaded": "You earned +{points} points for submitting a new PCAP.",
    "analysis_completed": "You earned +{points} points for completing a unique analysis.",
    "identity_scan_completed": "You earned +{points} points for completing an Identity scan.",
    "phishing_scan_completed": "Phishing: Check 1 URL today. You earned +{points} points.",
    "phishing_safe_scan_completed": "Phishing: Safe URL scan completed. You earned +{points} points.",
    "phishing_risky_url_detected": "Phishing: Risky URL detected. You earned +{points} points.",
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
    "vault_file_uploaded": "You earned +{points} points for uploading an encrypted vault file.",
    "vault_file_downloaded": "You earned +{points} points for downloading your encrypted vault file.",
    "vault_integrity_verified": "You earned +{points} points for verifying encrypted file integrity.",
    "vault_offline_enabled": "You earned +{points} point for enabling offline vault access.",
    "vault_offline_disabled": "You earned +{points} points for disabling offline vault access.",
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
    "vault_first_upload": {
        "badge_code": "vault_first_upload",
        "badge_title": "First Secure Upload",
        "badge_description": "Uploaded your first encrypted vault file",
        "rarity": "common",
        "progress_target": 1,
    },
    "vault_integrity_checker": {
        "badge_code": "vault_integrity_checker",
        "badge_title": "Integrity Checker",
        "badge_description": "Verified encrypted file integrity for the first time",
        "rarity": "common",
        "progress_target": 1,
    },
    "vault_keeper": {
        "badge_code": "vault_keeper",
        "badge_title": "Vault Keeper",
        "badge_description": "Uploaded 10 encrypted vault files",
        "rarity": "rare",
        "progress_target": 10,
    },
    "vault_safe_access": {
        "badge_code": "vault_safe_access",
        "badge_title": "Safe Vault Access",
        "badge_description": "Downloaded 5 encrypted vault files successfully",
        "rarity": "rare",
        "progress_target": 5,
    },
    "vault_guardian": {
        "badge_code": "vault_guardian",
        "badge_title": "Vault Guardian",
        "badge_description": "Completed 10 vault integrity checks",
        "rarity": "epic",
        "progress_target": 10,
    },
    "vault_offline_ready": {
        "badge_code": "vault_offline_ready",
        "badge_title": "Offline Ready",
        "badge_description": "Enabled offline access for an encrypted vault file",
        "rarity": "common",
        "progress_target": 1,
    },
    "vault_offline_manager": {
        "badge_code": "vault_offline_manager",
        "badge_title": "Offline Access Manager",
        "badge_description": "Disabled offline access after enabling it",
        "rarity": "rare",
        "progress_target": 1,
    },
    "phishing_first_url_scan": {
        "badge_code": "phishing_first_url_scan",
        "badge_title": "First URL Scan",
        "badge_description": "Completed your first phishing URL scan.",
        "rarity": "common",
        "progress_target": 1,
    },
    "phishing_safe_link_checker": {
        "badge_code": "phishing_safe_link_checker",
        "badge_title": "Safe Link Checker",
        "badge_description": "Completed a safe phishing scan result.",
        "rarity": "common",
        "progress_target": 1,
    },
    "phishing_hunter": {
        "badge_code": "phishing_hunter",
        "badge_title": "Phishing Hunter",
        "badge_description": "Detected your first suspicious or dangerous URL.",
        "rarity": "rare",
        "progress_target": 1,
    },
    "weekly_phishing_analyst": {
        "badge_code": "weekly_phishing_analyst",
        "badge_title": "Weekly Phishing Analyst",
        "badge_description": "Completed three phishing scans in one week.",
        "rarity": "rare",
        "progress_target": 3,
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
    "vault_upload_one_file": {
        "challenge_code": "vault_upload_one_file",
        "challenge_type": "daily",
        "title": "Upload 1 encrypted file",
        "description": "Upload one file to the encrypted vault today.",
        "target_value": 1,
        "reward_points": 5,
        "tracked_event_types": {"vault_file_uploaded"},
    },
    "vault_verify_one_file": {
        "challenge_code": "vault_verify_one_file",
        "challenge_type": "daily",
        "title": "Verify 1 vault file",
        "description": "Verify encrypted file integrity today.",
        "target_value": 1,
        "reward_points": 6,
        "tracked_event_types": {"vault_integrity_verified"},
    },
    "vault_enable_offline_once": {
        "challenge_code": "vault_enable_offline_once",
        "challenge_type": "daily",
        "title": "Enable offline access once",
        "description": "Enable offline access for one encrypted vault file today.",
        "target_value": 1,
        "reward_points": 3,
        "tracked_event_types": {"vault_offline_enabled"},
    },
    "phishing_check_one_url": {
        "challenge_code": "phishing_check_one_url",
        "challenge_type": "daily",
        "title": "Check 1 URL today",
        "description": "Run one phishing URL scan today.",
        "target_value": 1,
        "reward_points": 5,
        "tracked_event_types": {"phishing_scan_completed"},
    },
    "phishing_identify_one_risky_url": {
        "challenge_code": "phishing_identify_one_risky_url",
        "challenge_type": "daily",
        "title": "Identify 1 risky URL today",
        "description": "Detect one suspicious or dangerous URL today.",
        "target_value": 1,
        "reward_points": 8,
        "tracked_event_types": {"phishing_risky_url_detected"},
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
    "vault_upload_three_files": {
        "challenge_code": "vault_upload_three_files",
        "challenge_type": "weekly",
        "title": "Upload 3 encrypted files this week",
        "description": "Upload three files to the encrypted vault this week.",
        "target_value": 3,
        "reward_points": 15,
        "tracked_event_types": {"vault_file_uploaded"},
    },
    "vault_verify_three_files": {
        "challenge_code": "vault_verify_three_files",
        "challenge_type": "weekly",
        "title": "Verify 3 vault files this week",
        "description": "Verify integrity for three encrypted vault files this week.",
        "target_value": 3,
        "reward_points": 18,
        "tracked_event_types": {"vault_integrity_verified"},
    },
    "vault_manage_offline_access": {
        "challenge_code": "vault_manage_offline_access",
        "challenge_type": "weekly",
        "title": "Manage offline vault access",
        "description": "Disable offline access for one encrypted vault file this week.",
        "target_value": 1,
        "reward_points": 8,
        "tracked_event_types": {"vault_offline_disabled"},
    },
    "phishing_complete_three_scans": {
        "challenge_code": "phishing_complete_three_scans",
        "challenge_type": "weekly",
        "title": "Complete 3 phishing scans this week",
        "description": "Run three phishing URL scans this week.",
        "target_value": 3,
        "reward_points": 15,
        "tracked_event_types": {"phishing_scan_completed"},
    },
    "phishing_detect_two_risky_urls": {
        "challenge_code": "phishing_detect_two_risky_urls",
        "challenge_type": "weekly",
        "title": "Detect 2 risky phishing URLs this week",
        "description": "Find two suspicious or dangerous URLs this week.",
        "target_value": 2,
        "reward_points": 18,
        "tracked_event_types": {"phishing_risky_url_detected"},
    },
}

CHALLENGE_DEFINITIONS = {
    **DAILY_CHALLENGE_DEFINITIONS,
    **WEEKLY_CHALLENGE_DEFINITIONS,
}


def canonical_event_type(event_type: str | None) -> str:
    normalized = str(event_type or "").strip().lower()
    return LEGACY_EVENT_ALIASES.get(normalized, normalized)
