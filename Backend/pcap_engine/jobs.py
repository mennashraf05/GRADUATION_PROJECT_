# backend/pcap_engine/jobs.py
import json
import logging
import math
import os
import threading
import tempfile
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Callable
from concurrent.futures import ThreadPoolExecutor
import traceback


def _sanitize_for_json(obj: Any) -> Any:
    """Recursively replace NaN/Inf with None for valid JSON (JS JSON.parse rejects NaN)."""
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        return None if (math.isnan(obj) or math.isinf(obj)) else obj
    if hasattr(obj, "item") and callable(getattr(obj, "item")):
        try:
            return _sanitize_for_json(obj.item())
        except (ValueError, TypeError):
            return None
    if isinstance(obj, dict):
        return {str(k): _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_for_json(x) for x in obj]
    if isinstance(obj, str):
        return obj
    return obj


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_job_status(status: Any) -> str:
    value = str(status or "").strip().lower()
    if value == "failed":
        return "error"
    if value in {"cancelling", "cancellation_requested"}:
        return "cancelled"
    return value or "queued"


class JobCancelled(RuntimeError):
    """Raised by a worker when the user cancels a queued/running job."""


@dataclass
class JobState:
    job_id: str
    status: str  # queued | running | done | error | cancelled
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    progress: int = 0  # 0..100
    message: str = ""
    owner_user_id: Optional[int] = None
    owner_user_scope: Optional[str] = None
    owner_client_id: Optional[str] = None
    upload_path: Optional[str] = None
    packet_csv_path: Optional[str] = None
    report_path: Optional[str] = None
    evidence_dir: Optional[str] = None
    error: Optional[str] = None
    analysis_key: Optional[str] = None
    file_hash: Optional[str] = None
    artifact_protection: Optional[Dict[str, Any]] = None
    zeek_requested: bool = False
    zeek_status: Optional[str] = None
    zeek_error: Optional[str] = None
    zeek_required_files_found: Optional[list[str]] = None
    zeek_log_count: int = 0
    cancellation_requested: bool = False
    cancelled_at: Optional[str] = None
    cancel_reason: Optional[str] = None


class JobRegistry:
    """
    In-memory registry + persists each job state to disk as JSON.
    This is production-like enough for graduation project without Redis/Celery.
    """

    def __init__(self, base_dir: str, max_workers: int = 2):
        self.base = Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._jobs: Dict[str, JobState] = {}
        self._pool = ThreadPoolExecutor(max_workers=max_workers)

    def _job_dir(self, job_id: str) -> Path:
        d = self.base / job_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _disk_state_path(self, job_id: str) -> Path:
        return self.base / job_id / "state.json"

    def _state_path(self, job_id: str) -> Path:
        return self._job_dir(job_id) / "state.json"

    def _write_state(self, st: JobState) -> None:
        p = self._state_path(st.job_id)
        st.status = _normalize_job_status(st.status)
        payload = asdict(st)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=str(p.parent),
                prefix="state-",
                suffix=".tmp",
                delete=False,
            ) as f:
                json.dump(payload, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
                temp_path = Path(f.name)
            os.replace(temp_path, p)
        finally:
            if temp_path is not None and temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass

    def _load_state_from_disk(self, job_id: str) -> Optional[JobState]:
        p = self._disk_state_path(job_id)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            data["status"] = _normalize_job_status(data.get("status"))
            st = JobState(**data)
        except Exception:
            logging.exception("jobs.get failed to load state from disk | job_id=%s", job_id)
            return None
        with self._lock:
            self._jobs[job_id] = st
        return st

    def create(
        self,
        upload_path: str,
        owner_user_id: Optional[int] = None,
        owner_user_scope: Optional[str] = None,
        owner_client_id: Optional[str] = None,
        analysis_key: Optional[str] = None,
    ) -> JobState:
        job_id = str(uuid.uuid4())
        st = JobState(
            job_id=job_id,
            status="queued",
            created_at=utc_now_iso(),
            owner_user_id=owner_user_id,
            owner_user_scope=owner_user_scope,
            owner_client_id=owner_client_id,
            upload_path=upload_path,
            progress=0,
            message="Queued",
            analysis_key=analysis_key,
        )
        with self._lock:
            self._jobs[job_id] = st
            self._write_state(st)
        return st

    def create_or_reuse_active(
        self,
        upload_path: str,
        *,
        owner_user_id: Optional[int] = None,
        owner_user_scope: Optional[str] = None,
        owner_client_id: Optional[str] = None,
        analysis_key: Optional[str] = None,
    ) -> tuple[JobState, bool]:
        with self._lock:
            if analysis_key:
                for st in self._jobs.values():
                    if st.status not in {"queued", "running"}:
                        continue
                    if getattr(st, "analysis_key", None) != analysis_key:
                        continue
                    if owner_user_id is not None:
                        if getattr(st, "owner_user_id", None) != owner_user_id:
                            continue
                        if (
                            owner_user_scope
                            and getattr(st, "owner_user_scope", None)
                            != owner_user_scope
                        ):
                            continue
                    elif owner_client_id:
                        if getattr(st, "owner_client_id", None) != owner_client_id:
                            continue
                    return st, False

                for state_path in self.base.glob("*/state.json"):
                    try:
                        data = json.loads(state_path.read_text(encoding="utf-8"))
                        data["status"] = _normalize_job_status(data.get("status"))
                        st = JobState(**data)
                    except Exception:
                        continue
                    self._jobs[st.job_id] = st
                    if st.status not in {"queued", "running"}:
                        continue
                    if getattr(st, "analysis_key", None) != analysis_key:
                        continue
                    if owner_user_id is not None:
                        if getattr(st, "owner_user_id", None) != owner_user_id:
                            continue
                        if (
                            owner_user_scope
                            and getattr(st, "owner_user_scope", None)
                            != owner_user_scope
                        ):
                            continue
                    elif owner_client_id:
                        if getattr(st, "owner_client_id", None) != owner_client_id:
                            continue
                    return st, False

            job_id = str(uuid.uuid4())
            st = JobState(
                job_id=job_id,
                status="queued",
                created_at=utc_now_iso(),
                owner_user_id=owner_user_id,
                owner_user_scope=owner_user_scope,
                owner_client_id=owner_client_id,
                upload_path=upload_path,
                progress=0,
                message="Queued",
                analysis_key=analysis_key,
            )
            self._jobs[job_id] = st
            self._write_state(st)
            return st, True

    def get(self, job_id: str) -> Optional[JobState]:
        with self._lock:
            st = self._jobs.get(job_id)
        if st:
            return st

        # allow reading old jobs from disk even after restart
        return self._load_state_from_disk(job_id)

    def update(self, job_id: str, **kwargs) -> None:
        st = None
        with self._lock:
            st = self._jobs.get(job_id)
        if st is None:
            st = self._load_state_from_disk(job_id)
        if st is None:
            return
        with self._lock:
            st = self._jobs.get(job_id) or st
            for k, v in kwargs.items():
                setattr(st, k, v)
            st.status = _normalize_job_status(st.status)
            self._jobs[job_id] = st
            self._write_state(st)

    def request_cancel(self, job_id: str, reason: str = "user_requested") -> Optional[JobState]:
        st = None
        with self._lock:
            st = self._jobs.get(job_id)
        if st is None:
            st = self._load_state_from_disk(job_id)
        if st is None:
            return None

        with self._lock:
            st = self._jobs.get(job_id) or st
            st.cancellation_requested = True
            st.cancel_reason = str(reason or "user_requested")
            st.cancelled_at = st.cancelled_at or utc_now_iso()
            st.finished_at = st.finished_at or st.cancelled_at
            st.status = "cancelled"
            st.message = "Analysis cancelled by user."
            st.error = None
            self._jobs[job_id] = st
            self._write_state(st)
            return st

    def is_cancel_requested(self, job_id: str) -> bool:
        st = self.get(job_id)
        if st is None:
            return False
        return bool(getattr(st, "cancellation_requested", False)) or st.status == "cancelled"

    def forget(self, job_id: str) -> None:
        with self._lock:
            self._jobs.pop(job_id, None)

    def list_recent(self, limit: int = 50) -> list[JobState]:
        seen: Dict[str, JobState] = {}

        for state_path in self.base.glob("*/state.json"):
            try:
                data = json.loads(state_path.read_text(encoding="utf-8"))
                data["status"] = _normalize_job_status(data.get("status"))
                st = JobState(**data)
                seen[st.job_id] = st
            except Exception:
                continue

        with self._lock:
            for job_id, st in self._jobs.items():
                seen[job_id] = st
            self._jobs.update(seen)

        def _sort_key(st: JobState) -> str:
            return st.started_at or st.finished_at or st.created_at or ""

        items = sorted(seen.values(), key=_sort_key, reverse=True)
        if limit and limit > 0:
            return items[:limit]
        return items

    def submit(
        self,
        job_id: str,
        fn: Callable[[], Dict[str, Any]],
        on_success: Optional[Callable[[JobState, Dict[str, Any]], None]] = None,
        on_error: Optional[Callable[[JobState, str], None]] = None,
        on_terminal: Optional[Callable[[JobState], None]] = None,
    ) -> None:
        """
        Run fn() in background. fn() must return a report dict.
        We'll store report.json and update status.
        """

        def runner():
            st_before_start = self.get(job_id)
            if st_before_start is not None and (
                getattr(st_before_start, "cancellation_requested", False)
                or st_before_start.status == "cancelled"
            ):
                self.update(
                    job_id,
                    status="cancelled",
                    finished_at=utc_now_iso(),
                    message="Analysis cancelled by user.",
                    error=None,
                    cancellation_requested=True,
                    cancelled_at=getattr(st_before_start, "cancelled_at", None) or utc_now_iso(),
                    cancel_reason=getattr(st_before_start, "cancel_reason", None) or "user_requested",
                )
                st = self.get(job_id)
                if on_terminal and st is not None:
                    try:
                        on_terminal(st)
                    except Exception:
                        logging.exception("jobs.submit on_terminal callback failed")
                return

            self.update(
                job_id,
                status="running",
                started_at=utc_now_iso(),
                message="Running",
                progress=5,
            )

            try:
                report = fn()

                st_after_run = self.get(job_id)
                if st_after_run is not None and (
                    getattr(st_after_run, "cancellation_requested", False)
                    or st_after_run.status == "cancelled"
                ):
                    raise JobCancelled("Analysis cancelled by user.")

                job_dir = self._job_dir(job_id)
                report_path = job_dir / "report.json"
                report_clean = _sanitize_for_json(report)
                report_path.write_text(
                    json.dumps(report_clean, indent=2, allow_nan=False),
                    encoding="utf-8",
                )

                self.update(
                    job_id,
                    status="done",
                    finished_at=utc_now_iso(),
                    progress=100,
                    message="Completed",
                    report_path=str(report_path),
                    error=None,
                )
                st = self.get(job_id)
                if on_terminal and st is not None:
                    try:
                        on_terminal(st)
                    except Exception:
                        logging.exception("jobs.submit on_terminal callback failed")
                    st = self.get(job_id) or st
                if on_success and st is not None:
                    try:
                        on_success(st, report_clean)
                    except Exception:
                        logging.exception("jobs.submit on_success callback failed")
            except JobCancelled:
                st_cancelled = self.get(job_id)
                self.update(
                    job_id,
                    status="cancelled",
                    finished_at=getattr(st_cancelled, "finished_at", None) or utc_now_iso(),
                    progress=getattr(st_cancelled, "progress", 0) if st_cancelled else 0,
                    message="Analysis cancelled by user.",
                    error=None,
                    cancellation_requested=True,
                    cancelled_at=getattr(st_cancelled, "cancelled_at", None) or utc_now_iso(),
                    cancel_reason=getattr(st_cancelled, "cancel_reason", None) or "user_requested",
                )
                st = self.get(job_id)
                if on_terminal and st is not None:
                    try:
                        on_terminal(st)
                    except Exception:
                        logging.exception("jobs.submit on_terminal callback failed")
            except Exception:
                err_text = traceback.format_exc()
                self.update(
                    job_id,
                    status="error",
                    finished_at=utc_now_iso(),
                    progress=100,
                    message="Failed",
                    error=err_text,
                )
                st = self.get(job_id)
                if on_terminal and st is not None:
                    try:
                        on_terminal(st)
                    except Exception:
                        logging.exception("jobs.submit on_terminal callback failed")
                    st = self.get(job_id) or st
                if on_error and st is not None:
                    try:
                        on_error(st, err_text)
                    except Exception:
                        logging.exception("jobs.submit on_error callback failed")

        self._pool.submit(runner)
