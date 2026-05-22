import json
import logging
import shutil
import threading
import time
from dataclasses import dataclass, asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable, Optional


ACTIVE_JOB_STATUSES = {"queued", "running"}
TERMINAL_JOB_STATUSES = {"done", "error"}
DIRECT_FILE_SUFFIXES = {".pcap", ".pcapng", ".csv", ".zip", ".tmp", ".temp", ".part"}
EXPORT_BUNDLE_NAME = "evidence_bundle.zip"

_scheduler_lock = threading.Lock()
_scheduler_started = False


@dataclass
class CleanupSummary:
    files_deleted: int = 0
    folders_deleted: int = 0
    jobs_deleted: int = 0
    errors_count: int = 0
    skipped_active: int = 0
    skipped_recent: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _parse_iso_datetime(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _age_reference_for_job(state: dict, fallback_path: Path) -> datetime:
    for key in ("finished_at", "created_at"):
        dt = _parse_iso_datetime(state.get(key))
        if dt is not None:
            return dt
    return datetime.fromtimestamp(fallback_path.stat().st_mtime, tz=UTC)


def _normalized_job_status(value) -> str:
    status = str(value or "").strip().lower()
    if status == "failed":
        return "error"
    return status


def _is_path_within_base(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except Exception:
        return False


def _safe_load_job_state(state_path: Path, logger) -> Optional[dict]:
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        logger.exception("cleanup error reading state file %s", state_path)
    return None


def _delete_file(path: Path, summary: CleanupSummary, logger) -> bool:
    try:
        if not path.exists():
            logger.info("cleanup skipped missing path %s", path)
            return False
        path.unlink()
        summary.files_deleted += 1
        logger.info("cleanup deleted file %s", path)
        return True
    except Exception:
        summary.errors_count += 1
        logger.exception("cleanup error deleting file %s", path)
        return False


def _delete_folder(path: Path, summary: CleanupSummary, logger) -> bool:
    try:
        if not path.exists():
            logger.info("cleanup skipped missing path %s", path)
            return False
        shutil.rmtree(path)
        summary.folders_deleted += 1
        logger.info("cleanup deleted folder %s", path)
        return True
    except Exception:
        summary.errors_count += 1
        logger.exception("cleanup error deleting folder %s", path)
        return False


def _collect_active_job_protections(jobs_folder: Path, base_run_folder: Path, logger):
    protected_files: set[Path] = set()
    protected_dirs: set[Path] = set()

    for state_path in jobs_folder.glob("*/state.json"):
        state = _safe_load_job_state(state_path, logger)
        if not state:
            continue

        status = _normalized_job_status(state.get("status"))
        if status not in ACTIVE_JOB_STATUSES:
            continue

        protected_dirs.add(state_path.parent.resolve())
        logger.info(
            "cleanup skipped active job %s with status=%s",
            state.get("job_id") or state_path.parent.name,
            status,
        )

        for key in ("upload_path", "packet_csv_path", "report_path"):
            raw_path = state.get(key)
            if not raw_path:
                continue
            path = Path(str(raw_path))
            if _is_path_within_base(path, base_run_folder):
                protected_files.add(path.resolve())

        evidence_dir = state.get("evidence_dir")
        if evidence_dir:
            path = Path(str(evidence_dir))
            if _is_path_within_base(path, base_run_folder):
                protected_dirs.add(path.resolve())

    return protected_files, protected_dirs


def should_delete_job_folder(state: dict, state_path: Path, cutoff_time: datetime) -> bool:
    status = _normalized_job_status(state.get("status"))
    if status not in TERMINAL_JOB_STATUSES:
        return False
    return _age_reference_for_job(state, state_path) < cutoff_time


def _is_older_than(path: Path, cutoff_time: datetime) -> bool:
    try:
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    except FileNotFoundError:
        return False
    return modified < cutoff_time


def clean_stale_artifacts(
    base_run_folder: Path,
    jobs_folder: Path,
    artifact_retention_hours: int,
    protected_files: set[Path],
    protected_dirs: set[Path],
    summary: CleanupSummary,
    logger,
) -> None:
    cutoff_time = _now_utc() - timedelta(hours=artifact_retention_hours)

    for entry in base_run_folder.iterdir():
        try:
            resolved_entry = entry.resolve()
        except Exception:
            summary.errors_count += 1
            logger.exception("cleanup error resolving path %s", entry)
            continue

        if resolved_entry == jobs_folder.resolve():
            continue
        if entry.is_symlink():
            logger.info("cleanup skipped symlink %s", entry)
            continue
        if resolved_entry in protected_files or resolved_entry in protected_dirs:
            summary.skipped_active += 1
            continue
        if not _is_path_within_base(resolved_entry, base_run_folder):
            logger.warning("cleanup skipped unsafe path outside base folder: %s", entry)
            continue
        if not _is_older_than(entry, cutoff_time):
            summary.skipped_recent += 1
            continue

        if entry.is_dir():
            _delete_folder(entry, summary, logger)
            continue

        suffix = entry.suffix.lower()
        if suffix in DIRECT_FILE_SUFFIXES or entry.name.endswith("_packets.csv"):
            _delete_file(entry, summary, logger)


def clean_stale_job_exports(
    jobs_folder: Path,
    artifact_retention_hours: int,
    protected_dirs: set[Path],
    summary: CleanupSummary,
    logger,
) -> None:
    cutoff_time = _now_utc() - timedelta(hours=artifact_retention_hours)

    for job_dir in jobs_folder.iterdir():
        if not job_dir.is_dir():
            continue
        if job_dir.resolve() in protected_dirs:
            continue
        bundle_path = job_dir / EXPORT_BUNDLE_NAME
        if bundle_path.exists() and _is_older_than(bundle_path, cutoff_time):
            _delete_file(bundle_path, summary, logger)


def clean_stale_job_folders(
    jobs_folder: Path,
    job_retention_hours: int,
    protected_dirs: set[Path],
    summary: CleanupSummary,
    logger,
    forget_job_fn: Optional[Callable[[str], None]] = None,
) -> None:
    cutoff_time = _now_utc() - timedelta(hours=job_retention_hours)

    for state_path in jobs_folder.glob("*/state.json"):
        job_dir = state_path.parent
        if job_dir.resolve() in protected_dirs:
            summary.skipped_active += 1
            continue

        state = _safe_load_job_state(state_path, logger)
        if not state:
            summary.errors_count += 1
            continue

        status = _normalized_job_status(state.get("status"))
        if status in ACTIVE_JOB_STATUSES:
            summary.skipped_active += 1
            logger.info(
                "cleanup skipped active job folder %s status=%s",
                state.get("job_id") or job_dir.name,
                status,
            )
            continue
        if status not in TERMINAL_JOB_STATUSES:
            logger.info(
                "cleanup skipped job folder %s due to non-terminal status=%s",
                state.get("job_id") or job_dir.name,
                status or "unknown",
            )
            continue
        if not should_delete_job_folder(state, state_path, cutoff_time):
            summary.skipped_recent += 1
            continue

        job_id = str(state.get("job_id") or job_dir.name)
        deleted = _delete_folder(job_dir, summary, logger)
        if not deleted:
            continue

        summary.jobs_deleted += 1
        if forget_job_fn is not None:
            try:
                forget_job_fn(job_id)
            except Exception:
                summary.errors_count += 1
                logger.exception("cleanup error forgetting job %s", job_id)


def run_cleanup_pass(
    *,
    base_run_folder: str,
    jobs_folder: str,
    artifact_retention_hours: int = 72,
    job_retention_hours: int = 168,
    forget_job_fn: Optional[Callable[[str], None]] = None,
    logger=None,
) -> dict:
    logger = logger or logging.getLogger(__name__)
    summary = CleanupSummary()

    try:
        base_path = Path(base_run_folder).resolve()
        jobs_path = Path(jobs_folder).resolve()
        if not base_path.exists():
            logger.info("cleanup skipped: base run folder missing %s", base_path)
            return summary.as_dict()
        if not jobs_path.exists():
            logger.info("cleanup skipped: jobs folder missing %s", jobs_path)
            return summary.as_dict()

        logger.info(
            "cleanup started artifact_retention_hours=%s job_retention_hours=%s",
            artifact_retention_hours,
            job_retention_hours,
        )
        protected_files, protected_dirs = _collect_active_job_protections(
            jobs_path, base_path, logger
        )
        clean_stale_job_exports(
            jobs_path,
            artifact_retention_hours,
            protected_dirs,
            summary,
            logger,
        )
        clean_stale_artifacts(
            base_path,
            jobs_path,
            artifact_retention_hours,
            protected_files,
            protected_dirs,
            summary,
            logger,
        )
        clean_stale_job_folders(
            jobs_path,
            job_retention_hours,
            protected_dirs,
            summary,
            logger,
            forget_job_fn=forget_job_fn,
        )
        logger.info("cleanup completed %s", summary.as_dict())
    except Exception:
        summary.errors_count += 1
        logger.exception("cleanup pass failed")

    return summary.as_dict()


def start_cleanup_scheduler(
    *,
    base_run_folder: str,
    jobs_folder: str,
    artifact_retention_hours: int = 72,
    job_retention_hours: int = 168,
    cleanup_interval_minutes: int = 60,
    forget_job_fn: Optional[Callable[[str], None]] = None,
    logger=None,
) -> bool:
    logger = logger or logging.getLogger(__name__)
    interval_seconds = max(60, int(cleanup_interval_minutes) * 60)

    def _loop():
        run_cleanup_pass(
            base_run_folder=base_run_folder,
            jobs_folder=jobs_folder,
            artifact_retention_hours=artifact_retention_hours,
            job_retention_hours=job_retention_hours,
            forget_job_fn=forget_job_fn,
            logger=logger,
        )
        while True:
            time.sleep(interval_seconds)
            run_cleanup_pass(
                base_run_folder=base_run_folder,
                jobs_folder=jobs_folder,
                artifact_retention_hours=artifact_retention_hours,
                job_retention_hours=job_retention_hours,
                forget_job_fn=forget_job_fn,
                logger=logger,
            )

    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return False
        thread = threading.Thread(
            target=_loop,
            name="pcap-artifact-cleanup",
            daemon=True,
        )
        thread.start()
        _scheduler_started = True
        logger.info(
            "cleanup scheduler started interval_minutes=%s artifact_retention_hours=%s job_retention_hours=%s",
            cleanup_interval_minutes,
            artifact_retention_hours,
            job_retention_hours,
        )
        return True
