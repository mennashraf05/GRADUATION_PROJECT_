import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import zlib
from pathlib import Path


LOGGER = logging.getLogger(__name__)
WINDOWS_ABS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/].+")


def _env_positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


TSHARK_TIMEOUT = _env_positive_int("TSHARK_TIMEOUT", 1800)
TSHARK_PACKET_LIMIT = _env_positive_int("TSHARK_PACKET_LIMIT", 0) or None
TSHARK_READ_FILTER = str(os.getenv("TSHARK_READ_FILTER", "") or "").strip() or None
TSHARK_CHUNK_THRESHOLD_BYTES = _env_positive_int(
    "TSHARK_CHUNK_THRESHOLD_BYTES", 4 * 1024 * 1024 * 1024
)
TSHARK_SPLIT_PACKETS_PER_FILE = _env_positive_int(
    "TSHARK_SPLIT_PACKETS_PER_FILE", 100000
)
TSHARK_MIN_SPLIT_PACKETS_PER_FILE = _env_positive_int(
    "TSHARK_MIN_SPLIT_PACKETS_PER_FILE", 25000
)

TSHARK_FIELD_ARGS = [
    "-T",
    "fields",
    "-E",
    "separator=,",
    "-E",
    "quote=d",
    "-E",
    "occurrence=f",
    "-e",
    "frame.time_epoch",
    "-e",
    "ip.src",
    "-e",
    "ip.dst",
    "-e",
    "ipv6.src",
    "-e",
    "ipv6.dst",
    "-e",
    "tcp.srcport",
    "-e",
    "tcp.dstport",
    "-e",
    "udp.srcport",
    "-e",
    "udp.dstport",
    "-e",
    "ip.proto",
    "-e",
    "frame.len",
    "-e",
    "tcp.flags",
    "-e",
    "arp.src.proto_ipv4",
    "-e",
    "arp.dst.proto_ipv4",
    "-e",
    "arp.opcode",
    "-e",
    "eth.src",
    "-e",
    "arp.src.hw_mac",
]
MEMORY_PRESSURE_SIGNALS = (
    "cannot allocate memory",
    "not enough memory",
    "out of memory",
    "memoryerror",
    "std::bad_alloc",
    "failed to allocate",
)


class TsharkExportError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        memory_pressure: bool = False,
        stderr_text: str = "",
        returncode: int | None = None,
        stdout_preview: str = "",
        output_size: int = 0,
    ) -> None:
        super().__init__(message)
        self.memory_pressure = bool(memory_pressure)
        self.stderr_text = str(stderr_text or "")
        self.returncode = returncode
        self.stdout_preview = str(stdout_preview or "")
        self.output_size = max(int(output_size or 0), 0)


def _format_size(size_bytes: int) -> str:
    value = float(max(size_bytes, 0))
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    while value >= 1024.0 and unit_index < len(units) - 1:
        value /= 1024.0
        unit_index += 1
    precision = 0 if unit_index == 0 else 2
    return f"{value:.{precision}f} {units[unit_index]}"


def _find_tshark_windows() -> str | None:
    """Find native tshark.exe on Windows before falling back to WSL."""
    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    tshark_in_path = shutil.which("tshark")
    if tshark_in_path and os.path.isfile(tshark_in_path):
        return tshark_in_path
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def _find_editcap_windows() -> str | None:
    candidates = [
        r"C:\Program Files\Wireshark\editcap.exe",
        r"C:\Program Files (x86)\Wireshark\editcap.exe",
    ]
    editcap_in_path = shutil.which("editcap")
    if editcap_in_path and os.path.isfile(editcap_in_path):
        return editcap_in_path
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def win_to_wsl_path(win_path: str) -> str:
    text = str(win_path or "").strip()
    if not WINDOWS_ABS_PATH_RE.match(text):
        raise RuntimeError(f"WSL tshark fallback requires a Windows absolute path, got: {text!r}")
    p = text.replace("\\", "/")
    drive = p[0].lower()
    return f"/mnt/{drive}{p[2:]}"


def _build_tshark_args(executable: str, input_path: str) -> list[str]:
    args = [executable, "-n", "-r", input_path, *TSHARK_FIELD_ARGS]
    if TSHARK_READ_FILTER:
        args.extend(["-Y", TSHARK_READ_FILTER])
    if TSHARK_PACKET_LIMIT:
        args.extend(["-c", str(TSHARK_PACKET_LIMIT)])
    return args


def _build_editcap_split_args(
    executable: str,
    input_path: str,
    output_prefix: str,
    *,
    packets_per_file: int,
) -> list[str]:
    return [
        executable,
        "-F",
        "pcapng",
        "-c",
        str(max(int(packets_per_file), 1)),
        input_path,
        output_prefix,
    ]


def _remove_partial_output(out_csv: Path) -> None:
    if not out_csv.exists():
        return
    for attempt in range(3):
        try:
            out_csv.unlink()
            LOGGER.warning("Removed partial tshark output | out_csv=%s", out_csv)
            return
        except FileNotFoundError:
            return
        except OSError:
            if attempt == 2:
                LOGGER.exception("Failed to remove partial tshark output | out_csv=%s", out_csv)
                return
            time.sleep(0.25 * (attempt + 1))


def _read_output_tail(path: Path, *, max_bytes: int = 4096) -> str:
    if not path.exists() or not path.is_file():
        return ""
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            if size <= 0:
                return ""
            handle.seek(max(size - max_bytes, 0), os.SEEK_SET)
            data = handle.read(max_bytes)
    except OSError:
        return ""

    return data.decode("utf-8", errors="replace").strip()


def _build_chunk_artifact_stem(path: Path, *, depth: int) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.stem or "chunk")
    suffix = format(zlib.crc32(str(path).encode("utf-8", errors="ignore")) & 0xFFFFFFFF, "08x")
    return f"{safe_name}-d{depth}-{suffix}"


def _friendly_tshark_error(stderr_text: str) -> str:
    clean = str(stderr_text or "").strip()
    if _is_memory_pressure_error(clean):
        return (
            "tshark export failed due to memory pressure; try a smaller PCAP, a "
            "narrower capture slice, or automatic chunked export for large captures"
        )
    return f"tshark export failed: {clean or 'unknown tshark error'}"


def _is_memory_pressure_error(stderr_text: str) -> bool:
    lowered = str(stderr_text or "").strip().lower()
    return any(signal in lowered for signal in MEMORY_PRESSURE_SIGNALS)


def _run_export_process(
    *,
    args: list[str],
    out_csv: Path,
    timeout_s: int,
    mode_label: str,
    pcap_path: Path,
    executable_path: str,
    append: bool = False,
    process_callback=None,
) -> str:
    start = time.monotonic()
    stderr_text = ""
    process = None
    timed_out = False
    output_mode = "a" if append else "w"
    with out_csv.open(output_mode, encoding="utf-8", newline="") as out_handle:
        process = subprocess.Popen(
            args,
            stdout=out_handle,
            stderr=subprocess.PIPE,
            text=True,
        )
        if process_callback is not None:
            process_callback(process)
        try:
            _, stderr_text = process.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            elapsed = time.monotonic() - start
            LOGGER.error(
                "tshark export timed out | mode=%s | pcap=%s | out_csv=%s | tshark=%s | timeout_s=%s | elapsed_s=%.2f",
                mode_label,
                pcap_path,
                out_csv,
                executable_path,
                timeout_s,
                elapsed,
            )
            process.terminate()
            try:
                _, stderr_text = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                _, stderr_text = process.communicate()
        finally:
            if process_callback is not None:
                process_callback(None)

    if timed_out:
        output_size = out_csv.stat().st_size if out_csv.exists() else 0
        stdout_preview = _read_output_tail(out_csv)
        _remove_partial_output(out_csv)
        raise TsharkExportError(
            f"tshark export timed out after {timeout_s} seconds; file may be too large or disk I/O may be slow",
            stdout_preview=stdout_preview,
            output_size=output_size,
        )

    elapsed = time.monotonic() - start
    if process is None or process.returncode != 0:
        stderr_clean = (stderr_text or "").strip()
        output_size = out_csv.stat().st_size if out_csv.exists() else 0
        stdout_preview = _read_output_tail(out_csv)
        _remove_partial_output(out_csv)
        LOGGER.error(
            "tshark export failed | mode=%s | pcap=%s | out_csv=%s | tshark=%s | returncode=%s | elapsed_s=%.2f | output_size=%s | stderr=%s | stdout_tail=%s",
            mode_label,
            pcap_path,
            out_csv,
            executable_path,
            None if process is None else process.returncode,
            elapsed,
            _format_size(output_size),
            stderr_clean,
            stdout_preview,
        )
        raise TsharkExportError(
            _friendly_tshark_error(stderr_clean),
            memory_pressure=_is_memory_pressure_error(stderr_clean),
            stderr_text=stderr_clean,
            returncode=None if process is None else process.returncode,
            stdout_preview=stdout_preview,
            output_size=output_size,
        )

    output_size = out_csv.stat().st_size if out_csv.exists() else 0
    LOGGER.info(
        "tshark export completed | mode=%s | pcap=%s | out_csv=%s | tshark=%s | timeout_s=%s | elapsed_s=%.2f | output_size=%s",
        mode_label,
        pcap_path,
        out_csv,
        executable_path,
        timeout_s,
        elapsed,
        _format_size(output_size),
    )
    return str(out_csv)


def _append_csv_contents(src_csv: Path, dest_csv: Path) -> None:
    if not src_csv.exists():
        raise TsharkExportError(f"Expected chunk CSV output was not created: {src_csv}")

    with src_csv.open("rb") as source_handle, dest_csv.open("ab") as dest_handle:
        shutil.copyfileobj(source_handle, dest_handle, length=1024 * 1024)

    LOGGER.info(
        "Appended tshark chunk output | chunk_csv=%s | final_csv=%s | chunk_output_size=%s",
        src_csv,
        dest_csv,
        _format_size(src_csv.stat().st_size),
    )


def _should_resplit_chunk(exc: TsharkExportError, packets_per_file: int) -> bool:
    if packets_per_file <= max(int(TSHARK_MIN_SPLIT_PACKETS_PER_FILE), 1):
        return False

    if exc.memory_pressure:
        return True

    if exc.returncode in {2, 3221226505}:
        return True

    if not exc.stderr_text and exc.output_size > 0:
        return True

    return False


def _next_split_packet_count(current_packets_per_file: int) -> int:
    return max(
        max(int(TSHARK_MIN_SPLIT_PACKETS_PER_FILE), 1),
        int(current_packets_per_file) // 2,
    )


def _split_pcap_with_editcap(
    *,
    editcap_path: str,
    pcap_path: Path,
    split_dir: Path,
    packets_per_file: int,
    timeout_s: int,
    process_callback=None,
) -> list[Path]:
    output_prefix = split_dir / "chunk.pcapng"
    args = _build_editcap_split_args(
        editcap_path,
        str(pcap_path),
        str(output_prefix),
        packets_per_file=packets_per_file,
    )
    start = time.monotonic()
    process = subprocess.Popen(
        args,
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
        raise TsharkExportError(
            f"editcap split timed out after {timeout_s} seconds",
            stderr_text=str(stderr_text or "").strip(),
            returncode=process.returncode,
        )
    finally:
        if process_callback is not None:
            process_callback(None)
    elapsed = time.monotonic() - start
    stderr_clean = str(stderr_text or "").strip()
    if process.returncode != 0:
        stdout_clean = str(stdout_text or "").strip()
        LOGGER.error(
            "editcap split failed | pcap=%s | editcap=%s | returncode=%s | elapsed_s=%.2f | stderr=%s",
            pcap_path,
            editcap_path,
            process.returncode,
            elapsed,
            stderr_clean,
        )
        raise TsharkExportError(
            f"editcap split failed: {stderr_clean or stdout_clean or 'unknown editcap error'}",
            memory_pressure=_is_memory_pressure_error(stderr_clean),
            stderr_text=stderr_clean,
            returncode=process.returncode,
        )

    chunk_files = sorted(path for path in split_dir.iterdir() if path.is_file())
    if not chunk_files:
        raise TsharkExportError("editcap split produced no chunk files")

    LOGGER.info(
        "editcap split completed | pcap=%s | chunks=%s | packets_per_chunk=%s | elapsed_s=%.2f",
        pcap_path,
        len(chunk_files),
        packets_per_file,
        elapsed,
    )
    return chunk_files


def _export_chunk_or_resplit(
    *,
    pcap_path: Path,
    final_csv: Path,
    csv_temp_dir: Path,
    split_temp_dir: Path,
    timeout_s: int,
    tshark_path: str,
    editcap_path: str,
    mode_label: str,
    packets_per_file: int,
    depth: int,
    process_callback=None,
) -> None:
    artifact_stem = _build_chunk_artifact_stem(pcap_path, depth=depth)
    chunk_csv = csv_temp_dir / f"{artifact_stem}.csv"

    try:
        _run_export_process(
            args=_build_tshark_args(tshark_path, str(pcap_path)),
            out_csv=chunk_csv,
            timeout_s=timeout_s,
            mode_label=f"{mode_label}-chunked",
            pcap_path=pcap_path,
            executable_path=tshark_path,
            append=False,
            process_callback=process_callback,
        )
        _append_csv_contents(chunk_csv, final_csv)
        return
    except TsharkExportError as exc:
        if _should_resplit_chunk(exc, packets_per_file):
            next_packets_per_file = _next_split_packet_count(packets_per_file)
            child_split_dir = split_temp_dir / f"{artifact_stem}-resplit-{next_packets_per_file}"
            child_split_dir.mkdir(parents=True, exist_ok=True)
            LOGGER.warning(
                "Retrying failed tshark chunk with smaller editcap split | chunk_file=%s | packets_per_chunk=%s | next_packets_per_chunk=%s | returncode=%s | stderr=%s",
                pcap_path,
                packets_per_file,
                next_packets_per_file,
                exc.returncode,
                exc.stderr_text,
            )
            child_chunks = _split_pcap_with_editcap(
                editcap_path=editcap_path,
                pcap_path=pcap_path,
                split_dir=child_split_dir,
                packets_per_file=next_packets_per_file,
                timeout_s=timeout_s,
                process_callback=process_callback,
            )
            for child_chunk in child_chunks:
                _export_chunk_or_resplit(
                    pcap_path=child_chunk,
                    final_csv=final_csv,
                    csv_temp_dir=csv_temp_dir,
                    split_temp_dir=split_temp_dir,
                    timeout_s=timeout_s,
                    tshark_path=tshark_path,
                    editcap_path=editcap_path,
                    mode_label=mode_label,
                    packets_per_file=next_packets_per_file,
                    depth=depth + 1,
                    process_callback=process_callback,
                )
            return

        raise TsharkExportError(
            f"{exc} | chunk={pcap_path.name}",
            memory_pressure=exc.memory_pressure,
            stderr_text=exc.stderr_text,
            returncode=exc.returncode,
            stdout_preview=exc.stdout_preview,
            output_size=exc.output_size,
        ) from exc
    finally:
        _remove_partial_output(chunk_csv)


def _run_chunked_export(
    *,
    pcap_path: Path,
    out_csv: Path,
    timeout_s: int,
    tshark_path: str,
    editcap_path: str,
    mode_label: str,
    process_callback=None,
) -> str:
    _remove_partial_output(out_csv)
    with tempfile.TemporaryDirectory(
        prefix=f"{out_csv.stem}-chunks-",
        dir=str(out_csv.parent),
    ) as temp_dir_name:
        temp_root = Path(temp_dir_name)
        split_dir = temp_root / "split"
        csv_temp_dir = temp_root / "csv"
        split_temp_dir = temp_root / "resplit"
        split_dir.mkdir(parents=True, exist_ok=True)
        csv_temp_dir.mkdir(parents=True, exist_ok=True)
        split_temp_dir.mkdir(parents=True, exist_ok=True)
        chunk_files = _split_pcap_with_editcap(
            editcap_path=editcap_path,
            pcap_path=pcap_path,
            split_dir=split_dir,
            packets_per_file=TSHARK_SPLIT_PACKETS_PER_FILE,
            timeout_s=timeout_s,
            process_callback=process_callback,
        )
        total_chunks = len(chunk_files)
        for index, chunk_file in enumerate(chunk_files, start=1):
            LOGGER.info(
                "tshark chunk export starting | chunk=%s/%s | chunk_file=%s | out_csv=%s",
                index,
                total_chunks,
                chunk_file,
                out_csv,
            )
            _export_chunk_or_resplit(
                pcap_path=chunk_file,
                final_csv=out_csv,
                csv_temp_dir=csv_temp_dir,
                split_temp_dir=split_temp_dir,
                timeout_s=timeout_s,
                tshark_path=tshark_path,
                editcap_path=editcap_path,
                mode_label=mode_label,
                packets_per_file=TSHARK_SPLIT_PACKETS_PER_FILE,
                depth=0,
                process_callback=process_callback,
            )
    return str(out_csv)


def run_tshark_export(pcap_path: str, out_csv_path: str, process_callback=None) -> str:
    """
    Export packet-level fields to CSV without changing the feature schema that
    CIC flow extraction expects. Native Windows tshark is preferred; WSL is a
    fallback only when necessary.
    """
    pcap = Path(pcap_path)
    out_csv = Path(out_csv_path)
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    if not pcap.exists():
        raise RuntimeError(f"PCAP file not found: {pcap}")

    pcap_size = pcap.stat().st_size
    timeout_s = TSHARK_TIMEOUT

    tshark_exe = _find_tshark_windows()
    editcap_exe = _find_editcap_windows() if tshark_exe else None
    if tshark_exe:
        mode_label = "native-windows"
        executable_path = tshark_exe
        if not Path(tshark_exe).exists():
            raise RuntimeError(f"Configured tshark executable not found: {tshark_exe}")
        args = _build_tshark_args(tshark_exe, str(pcap))
    else:
        wsl_exe = shutil.which("wsl")
        if not wsl_exe:
            raise RuntimeError(
                "tshark executable not found on Windows and WSL is unavailable"
            )
        mode_label = "wsl-fallback"
        executable_path = wsl_exe
        args = _build_tshark_args("tshark", win_to_wsl_path(str(pcap)))
        args = [wsl_exe, *args]

    LOGGER.info(
        "Starting tshark export | mode=%s | pcap=%s | pcap_size=%s | out_csv=%s | tshark=%s | timeout_s=%s | packet_limit=%s | read_filter=%s",
        mode_label,
        pcap,
        _format_size(pcap_size),
        out_csv,
        executable_path,
        timeout_s,
        TSHARK_PACKET_LIMIT if TSHARK_PACKET_LIMIT else "none",
        TSHARK_READ_FILTER if TSHARK_READ_FILTER else "none",
    )
    should_chunk_first = bool(
        tshark_exe
        and editcap_exe
        and pcap_size >= max(int(TSHARK_CHUNK_THRESHOLD_BYTES), 1)
    )
    if should_chunk_first:
        LOGGER.info(
            "Using chunked tshark export for large PCAP | pcap=%s | pcap_size=%s | threshold=%s | packets_per_chunk=%s",
            pcap,
            _format_size(pcap_size),
            _format_size(TSHARK_CHUNK_THRESHOLD_BYTES),
            TSHARK_SPLIT_PACKETS_PER_FILE,
        )
        return _run_chunked_export(
            pcap_path=pcap,
            out_csv=out_csv,
            timeout_s=timeout_s,
            tshark_path=tshark_exe,
            editcap_path=editcap_exe,
            mode_label=mode_label,
            process_callback=process_callback,
        )

    try:
        return _run_export_process(
            args=args,
            out_csv=out_csv,
            timeout_s=timeout_s,
            mode_label=mode_label,
            pcap_path=pcap,
            executable_path=executable_path,
            process_callback=process_callback,
        )
    except TsharkExportError as exc:
        if tshark_exe and editcap_exe and exc.memory_pressure:
            LOGGER.warning(
                "Retrying tshark export with chunked fallback after memory-pressure failure | pcap=%s | packets_per_chunk=%s",
                pcap,
                TSHARK_SPLIT_PACKETS_PER_FILE,
            )
            return _run_chunked_export(
                pcap_path=pcap,
                out_csv=out_csv,
                timeout_s=timeout_s,
                tshark_path=tshark_exe,
                editcap_path=editcap_exe,
                mode_label=mode_label,
                process_callback=process_callback,
            )
        raise
