import logging
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

DEFAULT_ZEEK_PATH = "/usr/local/zeek/bin/zeek"
LOGGER = logging.getLogger(__name__)
WINDOWS_ABS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")


def prepare_zeek_run_folder(output_base: str) -> Path:
    run_id = str(uuid.uuid4())
    run_folder = Path(output_base) / run_id
    run_folder.mkdir(parents=True, exist_ok=True)
    return run_folder


def _windows_to_wsl_path(path_value: str, *, label: str) -> str:
    raw_path = str(path_value or "").strip()
    if not WINDOWS_ABS_PATH_RE.match(raw_path):
        LOGGER.error(
            "Invalid non-Windows path passed to Zeek | label=%s | path=%s",
            label,
            raw_path,
        )
        raise ValueError(
            f"Zeek requires a Windows absolute path for {label}: {raw_path!r}"
        )

    normalized = raw_path.replace("\\", "/")
    drive = normalized[0].lower()
    return f"/mnt/{drive}{normalized[2:]}"


def _is_linux_absolute_path(path_value: str) -> bool:
    return str(path_value or "").startswith("/")


def _resolve_linux_zeek_bin() -> str:
    configured = str(os.getenv("ZEEK_BIN") or "").strip()
    if configured:
        return configured
    discovered = shutil.which("zeek")
    if discovered:
        return discovered
    if Path(DEFAULT_ZEEK_PATH).exists():
        return DEFAULT_ZEEK_PATH
    return "zeek"


def _build_zeek_command(pcap_path: str, run_folder: Path):
    raw_pcap_path = str(pcap_path or "").strip()
    raw_run_folder = str(run_folder)

    if WINDOWS_ABS_PATH_RE.match(raw_pcap_path):
        wsl_path = _windows_to_wsl_path(raw_pcap_path, label="pcap_path")
        wsl_output = _windows_to_wsl_path(raw_run_folder, label="run_folder")
        return (
            [
                "wsl",
                "bash",
                "-lc",
                f'cd "{wsl_output}" && {DEFAULT_ZEEK_PATH} -C -r "{wsl_path}" LogAscii::use_json=T',
            ],
            None,
            "wsl",
        )

    if _is_linux_absolute_path(raw_pcap_path):
        linux_cwd = raw_run_folder.replace("\\", "/")
        return (
            [
                _resolve_linux_zeek_bin(),
                "-C",
                "-r",
                raw_pcap_path,
                "LogAscii::use_json=T",
            ],
            linux_cwd,
            "linux",
        )

    LOGGER.error("Invalid path passed to Zeek | pcap_path=%s", raw_pcap_path)
    raise ValueError(
        f"Zeek requires a Windows or Linux absolute path for pcap_path: {raw_pcap_path!r}"
    )


def run_zeek(
    pcap_path: str,
    output_base: str,
    run_folder: str | None = None,
    process_callback=None,
):
    run_folder = Path(run_folder) if run_folder else prepare_zeek_run_folder(output_base)
    run_folder.mkdir(parents=True, exist_ok=True)
    LOGGER.info("Starting Zeek run | pcap=%s | run_folder=%s", pcap_path, run_folder)

    command, cwd, mode = _build_zeek_command(pcap_path, run_folder)

    pcap_size_mb = Path(pcap_path).stat().st_size / (1024 * 1024)
    timeout_s = int(
        min(3600, max(300, pcap_size_mb * 2))
    )  # 2 sec per MB, min 5m, max 1h

    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process_callback is not None:
        process_callback(process)
    try:
        stdout_text, stderr_text = process.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            stdout_text, stderr_text = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout_text, stderr_text = process.communicate()
        raise TimeoutError(f"Zeek timed out after {timeout_s} seconds")
    finally:
        if process_callback is not None:
            process_callback(None)

    if process.returncode != 0:
        stderr_text = (stderr_text or "").strip()
        stdout_text = (stdout_text or "").strip()
        detail = stderr_text or stdout_text or f"exit code {process.returncode}"
        LOGGER.error(
            "Zeek failed | returncode=%s | stdout=%s | stderr=%s",
            process.returncode,
            stdout_text,
            stderr_text,
        )
        raise Exception(f"Zeek failed (code {process.returncode}): {detail}")

    log_count = len(list(run_folder.glob("*.log")))
    LOGGER.info(
        "Zeek run completed | mode=%s | run_folder=%s | log_files=%s",
        mode,
        run_folder,
        log_count,
    )

    return run_folder
