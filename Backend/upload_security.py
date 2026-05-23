import os
from pathlib import PurePosixPath, PureWindowsPath


PCAP_PUBLIC_MESSAGE = "Invalid PCAP file. Please upload a valid .pcap or .pcapng file."
VAULT_PUBLIC_MESSAGE = "This file type is not allowed."

PCAP_ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
PCAP_CLASSIC_MAGIC = (
    bytes.fromhex("d4 c3 b2 a1"),
    bytes.fromhex("a1 b2 c3 d4"),
    bytes.fromhex("4d 3c b2 a1"),
    bytes.fromhex("a1 b2 3c 4d"),
)
PCAPNG_MAGIC = bytes.fromhex("0a 0d 0d 0a")
PCAP_MIN_HEADER_BYTES = 4

VAULT_DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".php", ".jsp", ".asp",
    ".aspx", ".jar", ".vbs", ".scr", ".msi", ".com", ".pif", ".hta",
    ".cpl", ".reg", ".lnk", ".env", ".key", ".pem", ".p12", ".pfx",
    ".sqlite", ".db", ".sql",
}

VAULT_DANGEROUS_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-dosexec",
    "application/x-ms-installer",
    "application/x-msi",
    "application/vnd.microsoft.portable-executable",
    "application/x-sh",
    "application/x-csh",
    "application/x-php",
}

VAULT_ARCHIVE_EXTENSIONS = {".zip", ".docx", ".xlsx", ".pptx"}
VAULT_TEXT_EXTENSIONS = {
    "", ".txt", ".csv", ".json", ".xml", ".yml", ".yaml", ".md", ".ini",
    ".cfg", ".toml", ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c",
    ".cpp", ".h", ".hpp", ".cs", ".go", ".rs", ".html", ".css", ".scss",
}

EXECUTABLE_HEADERS = (
    b"MZ",
    b"\x7fELF",
    b"\xca\xfe\xba\xbe",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
)


def _result(ok: bool, error_code: str | None = None, public_message: str | None = None, safe_reason: str | None = None) -> dict:
    return {
        "ok": ok,
        "error_code": error_code,
        "public_message": public_message,
        "safe_reason": safe_reason,
    }


def read_upload_header(file_storage, max_bytes: int = 16) -> bytes:
    stream = getattr(file_storage, "stream", None)
    if stream is None or not hasattr(stream, "read"):
        return b""

    original_pos = None
    try:
        if hasattr(stream, "tell"):
            original_pos = stream.tell()
        if hasattr(stream, "seek"):
            stream.seek(0)
        header = stream.read(max_bytes) or b""
        return header
    except (OSError, ValueError):
        return b""
    finally:
        if hasattr(stream, "seek"):
            try:
                stream.seek(0 if original_pos is None else original_pos)
            except (OSError, ValueError):
                try:
                    stream.seek(0)
                except (OSError, ValueError):
                    pass


def reset_upload_stream(file_storage) -> None:
    stream = getattr(file_storage, "stream", None)
    if stream is not None and hasattr(stream, "seek"):
        try:
            stream.seek(0)
        except (OSError, ValueError):
            pass


def _extension(filename: str) -> str:
    return os.path.splitext(filename or "")[1].lower()


def _upload_size(file_storage) -> int | None:
    content_length = getattr(file_storage, "content_length", None)
    if content_length not in (None, -1, "", 0):
        try:
            parsed_length = int(content_length)
            if parsed_length > 0:
                return parsed_length
        except (TypeError, ValueError):
            pass

    stream = getattr(file_storage, "stream", None)
    if stream is None or not hasattr(stream, "seek") or not hasattr(stream, "tell"):
        return None
    try:
        current_pos = stream.tell()
        stream.seek(0, os.SEEK_END)
        size = int(stream.tell())
        stream.seek(current_pos)
        return size
    except (OSError, ValueError):
        reset_upload_stream(file_storage)
        return None


def _has_path_traversal_or_separator(filename: str) -> bool:
    if not filename or "\x00" in filename:
        return True
    if filename != os.path.basename(filename):
        return True
    if PurePosixPath(filename).is_absolute() or PureWindowsPath(filename).is_absolute():
        return True
    parts = filename.replace("\\", "/").split("/")
    return any(part == ".." for part in parts)


def _starts_with_any(data: bytes, prefixes: tuple[bytes, ...]) -> bool:
    return any(data.startswith(prefix) for prefix in prefixes)


def _is_probably_text(data: bytes) -> bool:
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        try:
            data.decode("latin-1")
            return True
        except UnicodeDecodeError:
            return False


def validate_pcap_upload(file_storage, filename: str) -> dict:
    ext = _extension(filename)
    if ext not in PCAP_ALLOWED_EXTENSIONS:
        reset_upload_stream(file_storage)
        return _result(False, "invalid_file_type", PCAP_PUBLIC_MESSAGE, "invalid_extension")

    size = _upload_size(file_storage)
    if size == 0:
        reset_upload_stream(file_storage)
        return _result(False, "invalid_file_type", PCAP_PUBLIC_MESSAGE, "empty_file")
    if size is not None and size < PCAP_MIN_HEADER_BYTES:
        reset_upload_stream(file_storage)
        return _result(False, "invalid_file_type", PCAP_PUBLIC_MESSAGE, "file_too_small")

    header = read_upload_header(file_storage, 16)
    reset_upload_stream(file_storage)
    if not header:
        return _result(False, "invalid_file_type", PCAP_PUBLIC_MESSAGE, "empty_file")
    if len(header) < PCAP_MIN_HEADER_BYTES:
        return _result(False, "invalid_file_type", PCAP_PUBLIC_MESSAGE, "file_too_small")

    if header.startswith(PCAPNG_MAGIC) or _starts_with_any(header, PCAP_CLASSIC_MAGIC):
        return _result(True)
    return _result(False, "invalid_file_type", PCAP_PUBLIC_MESSAGE, "invalid_magic")


def validate_vault_upload(file_storage, filename: str, allowed_extensions: set[str] | None = None) -> dict:
    if _has_path_traversal_or_separator(filename):
        reset_upload_stream(file_storage)
        return _result(False, "invalid_file_type", VAULT_PUBLIC_MESSAGE, "invalid_filename")

    ext = _extension(filename)
    if ext in VAULT_DANGEROUS_EXTENSIONS:
        reset_upload_stream(file_storage)
        return _result(False, "invalid_file_type", VAULT_PUBLIC_MESSAGE, "invalid_extension")

    normalized_allowed = {
        item if item.startswith(".") else f".{item}"
        for item in (allowed_extensions or set())
    }
    if normalized_allowed and ext and ext not in normalized_allowed:
        reset_upload_stream(file_storage)
        return _result(False, "invalid_file_type", VAULT_PUBLIC_MESSAGE, "invalid_extension")

    content_type = (getattr(file_storage, "content_type", "") or "").split(";", 1)[0].strip().lower()
    if content_type in VAULT_DANGEROUS_MIME_TYPES:
        reset_upload_stream(file_storage)
        return _result(False, "invalid_file_type", VAULT_PUBLIC_MESSAGE, "invalid_mime")

    header = read_upload_header(file_storage, 16)
    reset_upload_stream(file_storage)
    if not header:
        return _result(False, "invalid_file_type", VAULT_PUBLIC_MESSAGE, "empty_file")

    if _starts_with_any(header, EXECUTABLE_HEADERS):
        return _result(False, "invalid_file_type", VAULT_PUBLIC_MESSAGE, "invalid_magic")
    if ext == ".pdf" and not header.startswith(b"%PDF"):
        return _result(False, "invalid_file_type", VAULT_PUBLIC_MESSAGE, "invalid_magic")
    if ext == ".png" and not header.startswith(b"\x89PNG\r\n\x1a\n"):
        return _result(False, "invalid_file_type", VAULT_PUBLIC_MESSAGE, "invalid_magic")
    if ext in {".jpg", ".jpeg"} and not header.startswith(b"\xff\xd8\xff"):
        return _result(False, "invalid_file_type", VAULT_PUBLIC_MESSAGE, "invalid_magic")
    if ext == ".gif" and not (header.startswith(b"GIF87a") or header.startswith(b"GIF89a")):
        return _result(False, "invalid_file_type", VAULT_PUBLIC_MESSAGE, "invalid_magic")
    if ext in VAULT_ARCHIVE_EXTENSIONS and not header.startswith(b"PK"):
        return _result(False, "invalid_file_type", VAULT_PUBLIC_MESSAGE, "invalid_magic")
    if ext in VAULT_TEXT_EXTENSIONS and not _is_probably_text(header):
        return _result(False, "invalid_file_type", VAULT_PUBLIC_MESSAGE, "invalid_magic")

    return _result(True)
