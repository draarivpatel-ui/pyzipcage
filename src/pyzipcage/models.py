"""Public report and policy models for pyzipcage."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .errors import INVALID_OPTIONS, ZipCageError

DEFAULT_MAX_ENTRIES = 1000
DEFAULT_MAX_ENTRY_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 200 * 1024 * 1024
DEFAULT_MAX_COMPRESSION_RATIO = 100.0
DEFAULT_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_DEPTH = 20
DEFAULT_MAX_PATH_LENGTH = 512


def _fail_options(message: str, value: object) -> None:
    raise ZipCageError(INVALID_OPTIONS, message, repr(value))


def _positive_int(value: object, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail_options(key + " must be a positive integer", value)
    return int(value)


def _ratio(value: object, key: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail_options(key + " must be a number greater than or equal to 1", value)
    result = float(value)
    if math.isnan(result) or result < 1.0:
        _fail_options(key + " must be a number greater than or equal to 1", value)
    return result


def _boolean(value: object, key: str) -> bool:
    if not isinstance(value, bool):
        _fail_options(key + " must be a boolean", value)
    return value


@dataclass(frozen=True)
class ZipPolicy:
    """Fail-closed limits and extraction policy.

    The defaults are intentionally conservative. Raising a limit is an explicit
    caller decision and never changes parser correctness checks.
    """

    max_entries: int = DEFAULT_MAX_ENTRIES
    max_entry_bytes: int = DEFAULT_MAX_ENTRY_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_compression_ratio: float = DEFAULT_MAX_COMPRESSION_RATIO
    max_archive_bytes: int = DEFAULT_MAX_ARCHIVE_BYTES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH
    allow_symlinks: bool = False
    allow_special_files: bool = False
    allow_suid_sgid: bool = False
    allow_encrypted: bool = False
    allow_prototype_polluting_names: bool = False
    case_insensitive_duplicates: bool = True
    reject_polyglot: bool = True
    overwrite: bool = False

    def __post_init__(self) -> None:
        for key in (
            "max_entries",
            "max_entry_bytes",
            "max_total_bytes",
            "max_archive_bytes",
            "max_depth",
            "max_path_length",
        ):
            object.__setattr__(self, key, _positive_int(getattr(self, key), key))
        object.__setattr__(
            self,
            "max_compression_ratio",
            _ratio(self.max_compression_ratio, "max_compression_ratio"),
        )
        for key in (
            "allow_symlinks",
            "allow_special_files",
            "allow_suid_sgid",
            "allow_encrypted",
            "allow_prototype_polluting_names",
            "case_insensitive_duplicates",
            "reject_polyglot",
            "overwrite",
        ):
            object.__setattr__(self, key, _boolean(getattr(self, key), key))


@dataclass(frozen=True)
class Finding:
    """One machine readable inspection finding."""

    code: str
    message: str
    severity: str = "error"
    entry_index: Optional[int] = None
    entry_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
        }
        if self.entry_index is not None:
            output["entry_index"] = self.entry_index
        if self.entry_name is not None:
            output["entry_name"] = self.entry_name
        return output


@dataclass(frozen=True)
class ZipEntryInfo:
    """Public immutable view of one parsed central directory entry."""

    index: int
    name: str
    normalized_name: str
    path_segments: Tuple[str, ...]
    directory: bool
    version_made_by: int
    version_needed: int
    flags: int
    encrypted: bool
    utf8: bool
    data_descriptor: bool
    compression_method: int
    compression_method_name: str
    dos_time: int
    dos_date: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    compression_ratio: float
    file_name_length: int
    extra_length: int
    comment_length: int
    disk_number_start: int
    internal_attributes: int
    external_attributes: int
    unix_mode: int
    unix_file_type: str
    local_header_offset: int
    data_offset: Optional[int] = None
    data_end: Optional[int] = None
    local_version_needed: Optional[int] = None
    local_flags: Optional[int] = None
    local_compression_method: Optional[int] = None
    local_crc32: Optional[int] = None
    local_compressed_size: Optional[int] = None
    local_uncompressed_size: Optional[int] = None
    local_extra_length: Optional[int] = None
    invalid_encoding: bool = False

    def to_dict(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {}
        for key, value in self.__dict__.items():
            if isinstance(value, tuple):
                value = list(value)
            output[key] = value
        return output


@dataclass(frozen=True)
class Totals:
    """Aggregate archive measurements."""

    entries: int
    files: int
    directories: int
    compressed_bytes: int
    uncompressed_bytes: int
    archive_bytes: int
    compression_ratio: float
    maximum_entry_compression_ratio: float

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class InspectionReport:
    """Result of structural inspection. ``safe`` is true only with zero findings."""

    safe: bool
    entries: Tuple[ZipEntryInfo, ...]
    findings: Tuple[Finding, ...]
    totals: Totals

    def to_dict(self) -> Dict[str, Any]:
        return {
            "safe": self.safe,
            "entries": [entry.to_dict() for entry in self.entries],
            "findings": [finding.to_dict() for finding in self.findings],
            "totals": self.totals.to_dict(),
        }


@dataclass(frozen=True)
class ExtractedFile:
    """One file written by extraction."""

    name: str
    path: str
    bytes: int

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class ExtractionReport:
    """Result of a completed safe extraction."""

    target_dir: str
    entries_written: int
    directories_created: int
    bytes_written: int
    files: Tuple[ExtractedFile, ...]
    directories: Tuple[str, ...]
    report: InspectionReport

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_dir": self.target_dir,
            "entries_written": self.entries_written,
            "directories_created": self.directories_created,
            "bytes_written": self.bytes_written,
            "files": [item.to_dict() for item in self.files],
            "directories": list(self.directories),
            "report": self.report.to_dict(),
        }


__all__ = [
    "DEFAULT_MAX_ARCHIVE_BYTES",
    "DEFAULT_MAX_COMPRESSION_RATIO",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_MAX_ENTRY_BYTES",
    "DEFAULT_MAX_PATH_LENGTH",
    "DEFAULT_MAX_TOTAL_BYTES",
    "ExtractedFile",
    "ExtractionReport",
    "Finding",
    "InspectionReport",
    "Totals",
    "ZipEntryInfo",
    "ZipPolicy",
]
