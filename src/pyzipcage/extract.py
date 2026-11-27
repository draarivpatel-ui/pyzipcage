"""Filesystem-confined safe extraction for inspected classic ZIP archives."""

from __future__ import annotations

import itertools
import os
import secrets
import stat
import threading
from typing import Optional, Tuple

from .core import (
    _archive_error_from_report,
    _as_bytes,
    _decompressed_entry_chunks,
    _read_file_bytes_limited,
    _resolve_policy,
    inspect_zip_bytes,
)
from .errors import (
    ENCRYPTED,
    EXTRACTION_COLLISION,
    EXTRACTION_FAILED,
    EXTRACTION_OVERWRITE,
    EXTRACTION_REFUSED,
    EXTRACTION_SYMLINK,
    INVALID_INPUT,
    SIZE_LIMIT,
    ZipCageError,
)
from .models import ExtractedFile, ExtractionReport, ZipEntryInfo, ZipPolicy

_TEMP_COUNTER = itertools.count(1)
_TEMP_COUNTER_LOCK = threading.Lock()


def _extraction_failure(code: str, reason: str, target: object) -> ZipCageError:
    return ZipCageError(code, reason, os.fspath(target) if isinstance(target, (str, bytes, os.PathLike)) else repr(target))


def _lstat_or_none(path: str) -> Optional[os.stat_result]:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise _extraction_failure(EXTRACTION_FAILED, "could not inspect destination filesystem object", path)


def _inside_root(root: str, path: str) -> bool:
    try:
        return os.path.commonpath((root, path)) == root
    except ValueError:
        return False


def _ensure_directory_path(root: str, segments: Tuple[str, ...]) -> int:
    current = root
    created = 0
    for segment in segments:
        current = os.path.join(current, segment)
        if not _inside_root(root, current):
            raise _extraction_failure(EXTRACTION_REFUSED, "refusing to write outside the extraction target", current)
        info = _lstat_or_none(current)
        if info is None:
            try:
                os.mkdir(current, 0o755)
                os.chmod(current, 0o755)
                created += 1
                info = os.lstat(current)
            except FileExistsError:
                info = _lstat_or_none(current)
            except OSError:
                raise _extraction_failure(EXTRACTION_FAILED, "could not create destination directory", current)
        if info is None:
            raise _extraction_failure(EXTRACTION_FAILED, "destination directory disappeared during extraction", current)
        if stat.S_ISLNK(info.st_mode):
            raise _extraction_failure(
                EXTRACTION_SYMLINK,
                "refusing to traverse a symlink inside the extraction target",
                current,
            )
        if not stat.S_ISDIR(info.st_mode):
            raise _extraction_failure(
                EXTRACTION_COLLISION,
                "a non-directory blocks a required extraction directory",
                current,
            )
        resolved = os.path.realpath(current)
        if not _inside_root(root, resolved):
            raise _extraction_failure(EXTRACTION_REFUSED, "directory resolves outside the extraction target", current)
    return created


def _temporary_sibling(parent: str) -> str:
    with _TEMP_COUNTER_LOCK:
        counter = next(_TEMP_COUNTER)
    return os.path.join(
        parent,
        ".pyzipcage-{}-{}-{}".format(os.getpid(), counter, secrets.token_hex(8)),
    )


def _open_temporary_sibling(parent: str) -> Tuple[str, int]:
    last_error: Optional[OSError] = None
    for _ in range(5):
        temporary = _temporary_sibling(parent)
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            return temporary, descriptor
        except FileExistsError as exc:
            last_error = exc
        except OSError:
            raise _extraction_failure(EXTRACTION_FAILED, "could not create a temporary extraction file", parent)
    raise _extraction_failure(EXTRACTION_FAILED, "could not create a unique temporary extraction file", parent)


def _write_all(descriptor: int, data: bytes, target: str) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(descriptor, data[offset:])
        except OSError:
            raise _extraction_failure(EXTRACTION_FAILED, "file write failed", target)
        if written == 0:
            raise _extraction_failure(EXTRACTION_FAILED, "file write made no progress", target)
        offset += written


def _check_destination(destination: str, overwrite: bool) -> None:
    existing = _lstat_or_none(destination)
    if existing is None:
        return
    if stat.S_ISLNK(existing.st_mode):
        raise _extraction_failure(
            EXTRACTION_SYMLINK,
            "refusing to overwrite a symlink inside the extraction target",
            destination,
        )
    if stat.S_ISDIR(existing.st_mode):
        raise _extraction_failure(
            EXTRACTION_COLLISION,
            "a directory already occupies a file extraction path",
            destination,
        )
    if not overwrite:
        raise _extraction_failure(EXTRACTION_OVERWRITE, "destination exists and overwrite is false", destination)
    if not stat.S_ISREG(existing.st_mode):
        raise _extraction_failure(
            EXTRACTION_COLLISION,
            "a special filesystem object occupies a file extraction path",
            destination,
        )


def _install_temporary_file(temporary: str, destination: str, overwrite: bool) -> None:
    if overwrite:
        try:
            os.replace(temporary, destination)
        except OSError:
            raise _extraction_failure(EXTRACTION_FAILED, "atomic extraction rename failed", destination)
        return
    try:
        os.link(temporary, destination)
    except FileExistsError:
        raise _extraction_failure(
            EXTRACTION_OVERWRITE,
            "destination appeared during extraction and overwrite is false",
            destination,
        )
    except OSError:
        raise _extraction_failure(EXTRACTION_FAILED, "atomic extraction link failed", destination)
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    except OSError:
        raise _extraction_failure(EXTRACTION_FAILED, "temporary extraction file could not be unlinked", temporary)


def _extract_regular_file(data: bytes, entry: ZipEntryInfo, root: str, policy: ZipPolicy) -> Tuple[str, int, int]:
    segments = list(entry.path_segments)
    if not segments:
        raise _extraction_failure(EXTRACTION_REFUSED, "file entry has no safe extraction path", entry.name)
    file_name = segments.pop()
    parent_relative = tuple(segments)
    created_parent_directories = _ensure_directory_path(root, parent_relative)
    parent = os.path.join(root, *parent_relative) if parent_relative else root
    destination = os.path.join(parent, file_name)
    if not _inside_root(root, destination):
        raise _extraction_failure(EXTRACTION_REFUSED, "refusing to write outside the extraction target", destination)
    _check_destination(destination, policy.overwrite)

    temporary: Optional[str] = None
    descriptor: Optional[int] = None
    try:
        temporary, descriptor = _open_temporary_sibling(parent)
        for chunk in _decompressed_entry_chunks(data, entry, policy):
            _write_all(descriptor, chunk, destination)
        try:
            os.fsync(descriptor)
        except OSError:
            raise _extraction_failure(EXTRACTION_FAILED, "file sync failed", destination)
        try:
            os.fchmod(descriptor, 0o644)
        except OSError:
            raise _extraction_failure(EXTRACTION_FAILED, "file permission hardening failed", destination)
        os.close(descriptor)
        descriptor = None
        _check_destination(destination, policy.overwrite)
        resolved_parent = os.path.realpath(parent)
        if not _inside_root(root, resolved_parent):
            raise _extraction_failure(EXTRACTION_REFUSED, "parent directory resolves outside the extraction target", parent)
        _install_temporary_file(temporary, destination, policy.overwrite)
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        raise
    return destination, entry.uncompressed_size, created_parent_directories


def extract_zip_bytes(data: bytes, target_dir: object, policy: Optional[ZipPolicy] = None) -> ExtractionReport:
    """Safely extract a fully inspected archive into an existing directory.

    Extraction never follows symlinks inside the target, never writes Unix
    special files, uses a random exclusive temporary sibling for every file,
    and hardens final file permissions to ``0o644`` and directories to
    ``0o755``.
    """

    config = _resolve_policy(policy)
    archive = _as_bytes(data, "zip input")
    try:
        target_text = os.fsdecode(os.fspath(target_dir))
    except TypeError:
        raise ZipCageError(INVALID_INPUT, "target_dir must be a filesystem path", repr(target_dir))
    if not isinstance(target_text, str) or len(target_text) == 0 or "\x00" in target_text:
        raise ZipCageError(INVALID_INPUT, "target_dir must be a non-empty path without NUL bytes", repr(target_dir))

    report = inspect_zip_bytes(archive, config)
    if not report.safe:
        raise _archive_error_from_report(report)
    for entry in report.entries:
        if entry.encrypted:
            raise ZipCageError(ENCRYPTED, "encrypted entries cannot be extracted safely", entry.name)
        if entry.unix_file_type not in ("file", "directory", "unspecified"):
            raise ZipCageError(
                EXTRACTION_REFUSED,
                "safe extraction never writes symlinks, devices, FIFOs or sockets",
                entry.name,
            )

    try:
        root = os.path.realpath(target_text)
    except OSError:
        raise _extraction_failure(EXTRACTION_FAILED, "target_dir cannot be resolved with realpath", target_text)
    root_info = _lstat_or_none(root)
    if root_info is None or not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise _extraction_failure(EXTRACTION_FAILED, "target_dir must resolve to a real directory", target_text)

    written = []
    directories = []
    created_directories = 0
    bytes_written = 0
    for entry in report.entries:
        if entry.directory:
            created_directories += _ensure_directory_path(root, entry.path_segments)
            if entry.path_segments:
                directories.append(os.path.join(root, *entry.path_segments))
            continue
        destination, byte_count, parent_count = _extract_regular_file(archive, entry, root, config)
        created_directories += parent_count
        written.append(ExtractedFile(name=entry.name, path=destination, bytes=byte_count))
        bytes_written += byte_count

    return ExtractionReport(
        target_dir=root,
        entries_written=len(written),
        directories_created=created_directories,
        bytes_written=bytes_written,
        files=tuple(written),
        directories=tuple(directories),
        report=report,
    )


def extract_zip_file(zip_path: object, target_dir: object, policy: Optional[ZipPolicy] = None) -> ExtractionReport:
    """Read a ZIP file within the archive cap and safely extract it."""

    config = _resolve_policy(policy)
    data, _ = _read_file_bytes_limited(zip_path, config.max_archive_bytes)
    if len(data) > config.max_archive_bytes:
        raise ZipCageError(SIZE_LIMIT, "archive byte length exceeds max_archive_bytes")
    return extract_zip_bytes(data, target_dir, config)


__all__ = ["extract_zip_bytes", "extract_zip_file"]
