"""Structural ZIP parser, bounded decompressor, and safe read API."""

from __future__ import annotations

import math
import os
import re
import stat
import struct
import unicodedata
import zlib
from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Tuple

from .errors import (
    ABSOLUTE_PATH,
    CONTROL_CHARACTER,
    CRC_MISMATCH,
    DEFLATE_ERROR,
    DRIVE_PATH,
    DUPLICATE_PATH,
    EMPTY_PATH,
    EMPTY_PATH_SEGMENT,
    ENCRYPTED,
    ENTRY_LIMIT,
    ENTRY_NOT_FOUND,
    EXTRACTION_REFUSED,
    FILE_DIRECTORY_COLLISION,
    HEADER_MISMATCH,
    INVALID_ENCODING,
    INVALID_INPUT,
    INVALID_OPTIONS,
    MALFORMED_ZIP,
    MULTI_DISK,
    OVERLAPPING_DATA,
    PATH_TOO_DEEP,
    PATH_TOO_LONG,
    PATH_TRAVERSAL,
    POLYGLOT,
    PROTOTYPE_POLLUTION,
    RATIO_LIMIT,
    RESERVED_NAME,
    SIZE_LIMIT,
    SIZE_MISMATCH,
    SPECIAL_FILE,
    SUID_SGID,
    SYMLINK,
    TRAILING_COMPRESSED_DATA,
    TRAILING_DOT_OR_SPACE,
    TRUNCATED,
    UNC_PATH,
    UNICODE_PATH_MISMATCH,
    UNSUPPORTED_FLAGS,
    UNSUPPORTED_METHOD,
    UNSUPPORTED_ZIP64,
    ZipCageError,
)
from .models import Finding, InspectionReport, Totals, ZipEntryInfo, ZipPolicy

UINT16_MAX = 0xFFFF
UINT32_MAX = 0xFFFFFFFF
EOCD_SIGNATURE = 0x06054B50
CENTRAL_SIGNATURE = 0x02014B50
LOCAL_SIGNATURE = 0x04034B50
DATA_DESCRIPTOR_SIGNATURE = 0x08074B50
UNICODE_PATH_EXTRA_ID = 0x7075
EOCD_MIN_LENGTH = 22
CENTRAL_FIXED_LENGTH = 46
LOCAL_FIXED_LENGTH = 30
METHOD_STORED = 0
METHOD_DEFLATE = 8
FLAG_ENCRYPTED = 0x0001
FLAG_DATA_DESCRIPTOR = 0x0008
FLAG_UTF8 = 0x0800
UNSUPPORTED_FLAG_MASK = (
    0x0010
    | 0x0020
    | 0x0040
    | 0x0080
    | 0x0100
    | 0x0200
    | 0x0400
    | 0x1000
    | 0x2000
    | 0x4000
    | 0x8000
)
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
RESERVED_DEVICE_RE = re.compile(r"^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])$")
DRIVE_RE = re.compile(r"^[A-Za-z]:")
TRAILING_DOT_SPACE_RE = re.compile(r"[. ]$")
PROTOTYPE_KEYS = frozenset(("__proto__", "constructor", "prototype"))
INFLATE_INPUT_CHUNK_BYTES = 64 * 1024
INFLATE_OUTPUT_CHUNK_BYTES = 64 * 1024


@dataclass
class _ExtraState:
    malformed: bool = False
    zip64: bool = False
    unicode_paths: List[bytes] = field(default_factory=list)


@dataclass
class _ParsedEntry:
    index: int
    name: str
    name_bytes: bytes
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
    central_extra: bytes
    invalid_encoding: bool
    data_offset: Optional[int] = None
    data_end: Optional[int] = None
    local_version_needed: Optional[int] = None
    local_flags: Optional[int] = None
    local_compression_method: Optional[int] = None
    local_crc32: Optional[int] = None
    local_compressed_size: Optional[int] = None
    local_uncompressed_size: Optional[int] = None
    local_extra_length: Optional[int] = None
    local_extra_state: Optional[_ExtraState] = None
    path_validation_failed: bool = False


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _crc32(data: bytes, value: int = 0) -> int:
    return zlib.crc32(data, value) & 0xFFFFFFFF


def _as_bytes(value: object, label: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise ZipCageError(
        INVALID_INPUT,
        label + " must be bytes, bytearray or memoryview",
        repr(value),
    )


def _resolve_policy(policy: Optional[ZipPolicy]) -> ZipPolicy:
    if policy is None:
        return ZipPolicy()
    if not isinstance(policy, ZipPolicy):
        raise ZipCageError(INVALID_OPTIONS, "policy must be a ZipPolicy instance", repr(policy))
    return policy


def _decode_entry_name(name_bytes: bytes, utf8: bool) -> Tuple[str, bool]:
    if not utf8:
        return name_bytes.decode("cp437"), False
    try:
        return name_bytes.decode("utf-8", "strict"), False
    except UnicodeDecodeError:
        return name_bytes.decode("utf-8", "replace"), True


def _extra_field_state(extra: bytes) -> _ExtraState:
    state = _ExtraState()
    offset = 0
    while offset + 4 <= len(extra):
        field_id = _u16(extra, offset)
        size = _u16(extra, offset + 2)
        if field_id == 0x0001:
            state.zip64 = True
        end = offset + 4 + size
        if end > len(extra):
            state.malformed = True
            break
        if field_id == UNICODE_PATH_EXTRA_ID:
            state.unicode_paths.append(extra[offset + 4 : end])
        offset = end
    if offset != len(extra):
        state.malformed = True
    return state


def _unix_type_name(file_type: int) -> str:
    if file_type == 0o100000:
        return "file"
    if file_type == 0o040000:
        return "directory"
    if file_type == 0o120000:
        return "symlink"
    if file_type == 0o010000:
        return "fifo"
    if file_type == 0o140000:
        return "socket"
    if file_type == 0o060000:
        return "block-device"
    if file_type == 0o020000:
        return "character-device"
    if file_type == 0:
        return "unspecified"
    return "unknown"


def _path_stem_and_directory(name: str) -> Tuple[str, bool]:
    directory = name.endswith("/")
    return (name[:-1] if directory else name), directory


def _validate_entry_path(
    entry: _ParsedEntry,
    policy: ZipPolicy,
    add_finding: Callable[[str, str, Optional[int], Optional[str]], None],
) -> None:
    name = entry.name
    index = entry.index
    if not isinstance(name, str) or len(name) == 0:
        add_finding(EMPTY_PATH, "entry path is empty", index, name)
        entry.normalized_name = ""
        entry.path_segments = ()
        return

    if name.startswith("//") or name.startswith("\\\\"):
        add_finding(UNC_PATH, "UNC paths are not safe extraction targets", index, name)
    elif name.startswith("/") or name.startswith("\\"):
        add_finding(ABSOLUTE_PATH, "absolute paths are not safe extraction targets", index, name)
    if CONTROL_RE.search(name):
        add_finding(
            CONTROL_CHARACTER,
            "entry path contains a NUL, C0 or C1 control character",
            index,
            name,
        )
    if DRIVE_RE.match(name):
        add_finding(DRIVE_PATH, "Windows drive-letter paths are rejected", index, name)
    if ":" in name and not DRIVE_RE.match(name):
        add_finding(
            DRIVE_PATH,
            "colons are rejected to prevent drive and alternate-stream confusion",
            index,
            name,
        )
    if "\\" in name:
        add_finding(
            PATH_TRAVERSAL,
            "backslashes are rejected as cross-platform path separators",
            index,
            name,
        )

    stem, _ = _path_stem_and_directory(name)
    if len(stem) == 0:
        add_finding(EMPTY_PATH, "entry path has no file or directory name", index, name)
    try:
        path_byte_length = len(name.encode("utf-8"))
    except UnicodeEncodeError:
        path_byte_length = policy.max_path_length + 1
    if path_byte_length > policy.max_path_length:
        add_finding(PATH_TOO_LONG, "entry path exceeds max_path_length", index, name)
        entry.normalized_name = stem
        entry.path_segments = ()
        return

    segments = tuple(stem.split("/")) if stem else ()
    for segment in segments:
        if len(segment) == 0:
            add_finding(EMPTY_PATH_SEGMENT, "entry path contains an empty path segment", index, name)
            continue
        if segment == "." or segment == "..":
            add_finding(PATH_TRAVERSAL, "dot segments are rejected instead of normalized", index, name)
        if TRAILING_DOT_SPACE_RE.search(segment):
            add_finding(
                TRAILING_DOT_OR_SPACE,
                "Windows strips trailing dots and spaces from path segments",
                index,
                name,
            )
        device_stem = re.sub(r"[. ]+$", "", segment.split(".")[0]).upper()
        if RESERVED_DEVICE_RE.match(device_stem):
            add_finding(RESERVED_NAME, "Windows reserved device names are rejected", index, name)
        if not policy.allow_prototype_polluting_names and segment.lower() in PROTOTYPE_KEYS:
            add_finding(
                PROTOTYPE_POLLUTION,
                "prototype-polluting path segment names are rejected",
                index,
                name,
            )
    if len(segments) > policy.max_depth:
        add_finding(PATH_TOO_DEEP, "entry path exceeds max_depth", index, name)
    entry.normalized_name = "/".join(segments)
    entry.path_segments = segments


def _validate_unix_attributes(
    entry: _ParsedEntry,
    policy: ZipPolicy,
    add_finding: Callable[[str, str, Optional[int], Optional[str]], None],
) -> None:
    unix_mode = entry.unix_mode
    file_type = unix_mode & 0o170000
    permissions = unix_mode & 0o7777
    entry.unix_file_type = _unix_type_name(file_type)
    if file_type == 0o120000 and not policy.allow_symlinks:
        add_finding(SYMLINK, "symlink entries are rejected by default", entry.index, entry.name)
    special_type = file_type in (0o010000, 0o140000, 0o060000, 0o020000) or file_type not in (
        0,
        0o100000,
        0o040000,
        0o120000,
    )
    if special_type and not policy.allow_special_files:
        add_finding(
            SPECIAL_FILE,
            "FIFO, socket, device and unknown special entries are rejected",
            entry.index,
            entry.name,
        )
    if permissions & 0o6000 and not policy.allow_suid_sgid:
        add_finding(SUID_SGID, "setuid and setgid permission bits are rejected", entry.index, entry.name)


def _parse_central_entry(
    data: bytes,
    offset: int,
    index: int,
    add_finding: Callable[[str, str, Optional[int], Optional[str]], None],
) -> Optional[Tuple[_ParsedEntry, int]]:
    if offset + CENTRAL_FIXED_LENGTH > len(data):
        add_finding(TRUNCATED, "central directory header is truncated", index, None)
        return None
    if _u32(data, offset) != CENTRAL_SIGNATURE:
        add_finding(MALFORMED_ZIP, "central directory signature is missing", index, None)
        return None
    version_made_by = _u16(data, offset + 4)
    version_needed = _u16(data, offset + 6)
    flags = _u16(data, offset + 8)
    compression_method = _u16(data, offset + 10)
    dos_time = _u16(data, offset + 12)
    dos_date = _u16(data, offset + 14)
    crc32_value = _u32(data, offset + 16)
    compressed_size = _u32(data, offset + 20)
    uncompressed_size = _u32(data, offset + 24)
    file_name_length = _u16(data, offset + 28)
    extra_length = _u16(data, offset + 30)
    comment_length = _u16(data, offset + 32)
    disk_number_start = _u16(data, offset + 34)
    internal_attributes = _u16(data, offset + 36)
    external_attributes = _u32(data, offset + 38)
    local_header_offset = _u32(data, offset + 42)
    end = offset + CENTRAL_FIXED_LENGTH + file_name_length + extra_length + comment_length
    if end > len(data):
        add_finding(TRUNCATED, "central directory variable-length fields are truncated", index, None)
        return None
    name_start = offset + CENTRAL_FIXED_LENGTH
    name_bytes = bytes(data[name_start : name_start + file_name_length])
    extra_start = name_start + file_name_length
    central_extra = bytes(data[extra_start : extra_start + extra_length])
    decoded_name, invalid_encoding = _decode_entry_name(name_bytes, bool(flags & FLAG_UTF8))
    unix_mode = external_attributes >> 16
    stem_directory = decoded_name.endswith("/")
    lower_dos_directory = bool(external_attributes & 0x10)
    unix_directory = (unix_mode & 0o170000) == 0o040000
    ratio: float
    if compressed_size == 0:
        ratio = 1.0 if uncompressed_size == 0 else math.inf
    else:
        ratio = uncompressed_size / compressed_size
    entry = _ParsedEntry(
        index=index,
        name=decoded_name,
        name_bytes=name_bytes,
        normalized_name=decoded_name,
        path_segments=(),
        directory=stem_directory or lower_dos_directory or unix_directory,
        version_made_by=version_made_by,
        version_needed=version_needed,
        flags=flags,
        encrypted=bool(flags & FLAG_ENCRYPTED),
        utf8=bool(flags & FLAG_UTF8),
        data_descriptor=bool(flags & FLAG_DATA_DESCRIPTOR),
        compression_method=compression_method,
        compression_method_name=(
            "stored" if compression_method == METHOD_STORED else "deflate" if compression_method == METHOD_DEFLATE else "unsupported"
        ),
        dos_time=dos_time,
        dos_date=dos_date,
        crc32=crc32_value,
        compressed_size=compressed_size,
        uncompressed_size=uncompressed_size,
        compression_ratio=ratio,
        file_name_length=file_name_length,
        extra_length=extra_length,
        comment_length=comment_length,
        disk_number_start=disk_number_start,
        internal_attributes=internal_attributes,
        external_attributes=external_attributes,
        unix_mode=unix_mode,
        unix_file_type=_unix_type_name(unix_mode & 0o170000),
        local_header_offset=local_header_offset,
        central_extra=central_extra,
        invalid_encoding=invalid_encoding,
    )
    return entry, end


def _compare_unsigned(
    field_name: str,
    central_value: int,
    local_value: int,
    entry: _ParsedEntry,
    add_finding: Callable[[str, str, Optional[int], Optional[str]], None],
) -> None:
    if central_value != local_value:
        add_finding(
            HEADER_MISMATCH,
            "local file header " + field_name + " does not match the central directory",
            entry.index,
            entry.name,
        )


def _data_descriptor_state(data: bytes, entry: _ParsedEntry, central_directory_offset: int) -> Tuple[int, bool, bool, bool]:
    assert entry.data_end is not None
    start = entry.data_end
    if start + 12 > central_directory_offset:
        return 0, True, False, False
    first = _u32(data, start)
    unsigned_matches = (
        first == entry.crc32
        and _u32(data, start + 4) == entry.compressed_size
        and _u32(data, start + 8) == entry.uncompressed_size
    )
    signed_available = first == DATA_DESCRIPTOR_SIGNATURE and start + 16 <= central_directory_offset
    signed_matches = False
    if signed_available:
        signed_matches = (
            _u32(data, start + 4) == entry.crc32
            and _u32(data, start + 8) == entry.compressed_size
            and _u32(data, start + 12) == entry.uncompressed_size
        )
    if unsigned_matches and signed_matches:
        return 16, False, False, True
    if unsigned_matches:
        return 12, False, False, False
    if signed_matches:
        return 16, False, False, False
    if first == DATA_DESCRIPTOR_SIGNATURE and not signed_available:
        return 0, True, False, False
    return (16 if signed_available else 12), False, True, False


def _verify_data_descriptor(
    data: bytes,
    entry: _ParsedEntry,
    central_directory_offset: int,
    add_finding: Callable[[str, str, Optional[int], Optional[str]], None],
) -> None:
    _length, truncated, mismatch, ambiguous = _data_descriptor_state(data, entry, central_directory_offset)
    if truncated:
        add_finding(TRUNCATED, "data descriptor is missing or truncated", entry.index, entry.name)
    elif ambiguous:
        add_finding(
            MALFORMED_ZIP,
            "data descriptor is ambiguous in signed and unsigned interpretations",
            entry.index,
            entry.name,
        )
    elif mismatch:
        add_finding(HEADER_MISMATCH, "data descriptor does not match the central directory", entry.index, entry.name)


def _verify_local_record(
    data: bytes,
    entry: _ParsedEntry,
    central_directory_offset: int,
    add_finding: Callable[[str, str, Optional[int], Optional[str]], None],
) -> None:
    offset = entry.local_header_offset
    if offset + LOCAL_FIXED_LENGTH > len(data) or offset + LOCAL_FIXED_LENGTH > central_directory_offset:
        add_finding(
            TRUNCATED,
            "local file header is truncated or outside the file-data region",
            entry.index,
            entry.name,
        )
        entry.data_offset = offset
        entry.data_end = offset
        return
    if _u32(data, offset) != LOCAL_SIGNATURE:
        add_finding(
            HEADER_MISMATCH,
            "central directory points at bytes without a local file header signature",
            entry.index,
            entry.name,
        )
        entry.data_offset = offset
        entry.data_end = offset
        return

    local_version_needed = _u16(data, offset + 4)
    local_flags = _u16(data, offset + 6)
    local_method = _u16(data, offset + 8)
    local_crc = _u32(data, offset + 14)
    local_compressed_size = _u32(data, offset + 18)
    local_uncompressed_size = _u32(data, offset + 22)
    local_name_length = _u16(data, offset + 26)
    local_extra_length = _u16(data, offset + 28)
    variable_end = offset + LOCAL_FIXED_LENGTH + local_name_length + local_extra_length
    if variable_end > len(data) or variable_end > central_directory_offset:
        add_finding(TRUNCATED, "local file header variable-length fields are truncated", entry.index, entry.name)
        entry.data_offset = offset
        entry.data_end = offset
        return
    local_name = data[offset + LOCAL_FIXED_LENGTH : offset + LOCAL_FIXED_LENGTH + local_name_length]
    if local_name != entry.name_bytes:
        add_finding(
            HEADER_MISMATCH,
            "local file header filename does not match the central directory filename",
            entry.index,
            entry.name,
        )
    if local_method != entry.compression_method:
        add_finding(
            HEADER_MISMATCH,
            "local file header compression method does not match the central directory",
            entry.index,
            entry.name,
        )
    if local_flags != entry.flags:
        add_finding(
            HEADER_MISMATCH,
            "local file header flags do not match the central directory",
            entry.index,
            entry.name,
        )
    _compare_unsigned("version-needed", entry.version_needed, local_version_needed, entry, add_finding)
    if not entry.flags & FLAG_DATA_DESCRIPTOR:
        _compare_unsigned("CRC-32", entry.crc32, local_crc, entry, add_finding)
        _compare_unsigned("compressed size", entry.compressed_size, local_compressed_size, entry, add_finding)
        _compare_unsigned("uncompressed size", entry.uncompressed_size, local_uncompressed_size, entry, add_finding)
    else:
        if local_crc != 0 and local_crc != entry.crc32:
            add_finding(
                HEADER_MISMATCH,
                "nonzero local CRC-32 conflicts with the central directory when a data descriptor is in use",
                entry.index,
                entry.name,
            )
        if local_compressed_size != 0 and local_compressed_size != entry.compressed_size:
            add_finding(
                HEADER_MISMATCH,
                "nonzero local compressed size conflicts with the central directory when a data descriptor is in use",
                entry.index,
                entry.name,
            )
        if local_uncompressed_size != 0 and local_uncompressed_size != entry.uncompressed_size:
            add_finding(
                HEADER_MISMATCH,
                "nonzero local uncompressed size conflicts with the central directory when a data descriptor is in use",
                entry.index,
                entry.name,
            )

    local_extra = data[offset + LOCAL_FIXED_LENGTH + local_name_length : variable_end]
    extra_state = _extra_field_state(local_extra)
    entry.local_extra_state = extra_state
    if extra_state.malformed:
        add_finding(MALFORMED_ZIP, "local file header extra field is malformed", entry.index, entry.name)
    if extra_state.zip64:
        add_finding(UNSUPPORTED_ZIP64, "ZIP64 local extra fields are outside the supported scope", entry.index, entry.name)

    entry.local_version_needed = local_version_needed
    entry.local_flags = local_flags
    entry.local_compression_method = local_method
    entry.local_crc32 = local_crc
    entry.local_compressed_size = local_compressed_size
    entry.local_uncompressed_size = local_uncompressed_size
    entry.local_extra_length = local_extra_length
    entry.data_offset = variable_end
    entry.data_end = variable_end + entry.compressed_size
    if entry.data_end > len(data) or entry.data_end > central_directory_offset:
        add_finding(
            TRUNCATED,
            "compressed entry data is truncated or reaches into the central directory",
            entry.index,
            entry.name,
        )
        return
    if entry.flags & FLAG_DATA_DESCRIPTOR:
        _verify_data_descriptor(data, entry, central_directory_offset, add_finding)


def _validate_unicode_path_extra(
    entry: _ParsedEntry,
    field_data: bytes,
    location: str,
    add_finding: Callable[[str, str, Optional[int], Optional[str]], None],
) -> None:
    if len(field_data) < 5:
        add_finding(
            MALFORMED_ZIP,
            "Unicode path extra field in the " + location + " is truncated",
            entry.index,
            entry.name,
        )
        return
    if field_data[0] != 1:
        add_finding(
            MALFORMED_ZIP,
            "Unicode path extra field in the " + location + " has an unsupported version",
            entry.index,
            entry.name,
        )
        return
    if _u32(field_data, 1) != _crc32(entry.name_bytes):
        add_finding(
            UNICODE_PATH_MISMATCH,
            "Unicode path extra field checksum does not match the primary filename bytes",
            entry.index,
            entry.name,
        )
    try:
        unicode_name = field_data[5:].decode("utf-8", "strict")
    except UnicodeDecodeError:
        add_finding(INVALID_ENCODING, "Unicode path extra field is not valid UTF-8", entry.index, entry.name)
        return
    if unicode_name != entry.name:
        add_finding(
            UNICODE_PATH_MISMATCH,
            "Unicode path extra field disagrees with the primary filename and is a parser-differential risk",
            entry.index,
            entry.name,
        )


def _validate_unicode_path_extras(
    entry: _ParsedEntry,
    central_state: _ExtraState,
    add_finding: Callable[[str, str, Optional[int], Optional[str]], None],
) -> None:
    states = [("central directory", central_state)]
    if entry.local_extra_state is not None:
        states.append(("local file header", entry.local_extra_state))
    for location, state in states:
        if len(state.unicode_paths) > 1:
            add_finding(
                MALFORMED_ZIP,
                "duplicate Unicode path extra fields in the " + location + " are ambiguous",
                entry.index,
                entry.name,
            )
        for field_data in state.unicode_paths:
            _validate_unicode_path_extra(entry, field_data, location, add_finding)


@dataclass(frozen=True)
class _EocdCandidate:
    offset: int
    end: int
    comment_length: int


@dataclass(frozen=True)
class _EocdResult:
    candidate: _EocdCandidate
    ambiguous: bool


def _locate_eocd(data: bytes, reject_polyglot: bool) -> Optional[_EocdResult]:
    minimum = max(0, len(data) - (EOCD_MIN_LENGTH + UINT16_MAX))
    exact: List[_EocdCandidate] = []
    trailing: List[_EocdCandidate] = []
    for offset in range(len(data) - EOCD_MIN_LENGTH, minimum - 1, -1):
        if _u32(data, offset) != EOCD_SIGNATURE:
            continue
        comment_length = _u16(data, offset + 20)
        end = offset + EOCD_MIN_LENGTH + comment_length
        if end > len(data):
            continue
        candidate = _EocdCandidate(offset=offset, end=end, comment_length=comment_length)
        if end == len(data):
            exact.append(candidate)
        else:
            trailing.append(candidate)
    if len(exact) == 1:
        return _EocdResult(exact[0], bool(not reject_polyglot and trailing))
    if len(exact) > 1:
        return _EocdResult(exact[0], True)
    if len(trailing) == 1:
        return _EocdResult(trailing[0], False)
    if len(trailing) > 1:
        return _EocdResult(trailing[0], True)
    return None


def _canonical_path_key(name: str) -> str:
    return unicodedata.normalize("NFC", name).lower()


def _finalize_totals(entries: Tuple[ZipEntryInfo, ...], archive_bytes: int) -> Totals:
    files = 0
    directories = 0
    compressed_bytes = 0
    uncompressed_bytes = 0
    maximum_ratio = 0.0
    for entry in entries:
        if entry.directory:
            directories += 1
        else:
            files += 1
        compressed_bytes += entry.compressed_size
        uncompressed_bytes += entry.uncompressed_size
        if entry.compression_ratio > maximum_ratio:
            maximum_ratio = entry.compression_ratio
    if compressed_bytes == 0:
        compression_ratio = 1.0 if uncompressed_bytes == 0 else math.inf
    else:
        compression_ratio = uncompressed_bytes / compressed_bytes
    return Totals(
        entries=len(entries),
        files=files,
        directories=directories,
        compressed_bytes=compressed_bytes,
        uncompressed_bytes=uncompressed_bytes,
        archive_bytes=archive_bytes,
        compression_ratio=compression_ratio,
        maximum_entry_compression_ratio=1.0 if not entries else maximum_ratio,
    )


def _public_entry(entry: _ParsedEntry) -> ZipEntryInfo:
    return ZipEntryInfo(
        index=entry.index,
        name=entry.name,
        normalized_name=entry.normalized_name,
        path_segments=tuple(entry.path_segments),
        directory=entry.directory,
        version_made_by=entry.version_made_by,
        version_needed=entry.version_needed,
        flags=entry.flags,
        encrypted=entry.encrypted,
        utf8=entry.utf8,
        data_descriptor=entry.data_descriptor,
        compression_method=entry.compression_method,
        compression_method_name=entry.compression_method_name,
        dos_time=entry.dos_time,
        dos_date=entry.dos_date,
        crc32=entry.crc32,
        compressed_size=entry.compressed_size,
        uncompressed_size=entry.uncompressed_size,
        compression_ratio=entry.compression_ratio,
        file_name_length=entry.file_name_length,
        extra_length=entry.extra_length,
        comment_length=entry.comment_length,
        disk_number_start=entry.disk_number_start,
        internal_attributes=entry.internal_attributes,
        external_attributes=entry.external_attributes,
        unix_mode=entry.unix_mode,
        unix_file_type=entry.unix_file_type,
        local_header_offset=entry.local_header_offset,
        data_offset=entry.data_offset,
        data_end=entry.data_end,
        local_version_needed=entry.local_version_needed,
        local_flags=entry.local_flags,
        local_compression_method=entry.local_compression_method,
        local_crc32=entry.local_crc32,
        local_compressed_size=entry.local_compressed_size,
        local_uncompressed_size=entry.local_uncompressed_size,
        local_extra_length=entry.local_extra_length,
        invalid_encoding=entry.invalid_encoding,
    )


def _finish_report(
    entries: List[_ParsedEntry],
    findings: List[Finding],
    archive_bytes: int,
) -> InspectionReport:
    public_entries = tuple(_public_entry(entry) for entry in entries)
    return InspectionReport(
        safe=len(findings) == 0,
        entries=public_entries,
        findings=tuple(findings),
        totals=_finalize_totals(public_entries, archive_bytes),
    )


def _add_duplicate_and_collision_findings(
    entries: List[_ParsedEntry],
    policy: ZipPolicy,
    add_finding: Callable[[str, str, Optional[int], Optional[str]], None],
) -> None:
    exact = {}
    folded = {}
    types = {}
    for entry in entries:
        if not entry.normalized_name or entry.path_validation_failed:
            continue
        key = entry.normalized_name
        folded_key = _canonical_path_key(key)
        if key in exact:
            add_finding(DUPLICATE_PATH, "duplicate normalized entry path", entry.index, entry.name)
        else:
            exact[key] = entry.index
        if policy.case_insensitive_duplicates:
            if folded_key in folded and folded[folded_key] != key:
                add_finding(
                    DUPLICATE_PATH,
                    "case-insensitive duplicate normalized entry path",
                    entry.index,
                    entry.name,
                )
            elif folded_key not in folded:
                folded[folded_key] = key
        types.setdefault(folded_key, set()).add("directory" if entry.directory else "file")

    emitted = set()

    def collision_finding(entry: _ParsedEntry, other_key: str, kind: str) -> None:
        pair = (entry.index, other_key, kind)
        if pair in emitted:
            return
        emitted.add(pair)
        add_finding(
            FILE_DIRECTORY_COLLISION,
            "entry path collides with a file or directory required by another entry",
            entry.index,
            entry.name,
        )

    for entry in entries:
        if not entry.normalized_name or entry.path_validation_failed:
            continue
        key = _canonical_path_key(entry.normalized_name)
        type_set = types.get(key)
        if type_set and "file" in type_set and "directory" in type_set:
            collision_finding(entry, key, "same-path")
        segments = entry.normalized_name.split("/")
        for length in range(1, len(segments)):
            ancestor = _canonical_path_key("/".join(segments[:length]))
            ancestor_types = types.get(ancestor)
            if ancestor_types and "file" in ancestor_types:
                collision_finding(entry, ancestor, "ancestor-file")


def _descriptor_length_for_entry(data: bytes, entry: _ParsedEntry, central_directory_offset: int) -> int:
    if not entry.flags & FLAG_DATA_DESCRIPTOR:
        return 0
    if entry.data_end is None or entry.data_end + 12 > central_directory_offset:
        return 0
    length, _truncated, _mismatch, _ambiguous = _data_descriptor_state(data, entry, central_directory_offset)
    return length


def _add_local_layout_findings(
    data: bytes,
    entries: List[_ParsedEntry],
    central_directory_offset: int,
    policy: ZipPolicy,
    add_finding: Callable[[str, str, Optional[int], Optional[str]], None],
) -> None:
    records = {}
    for entry in entries:
        if entry.data_offset is None or entry.data_end is None:
            continue
        if entry.data_end > central_directory_offset or entry.data_end < entry.data_offset:
            continue
        records.setdefault(entry.local_header_offset, []).append(entry)
    ordered = []
    for group in records.values():
        record_end = 0
        for entry in group:
            end = entry.data_end
            assert end is not None
            end += _descriptor_length_for_entry(data, entry, central_directory_offset)
            record_end = max(record_end, end)
        ordered.append({"offset": group[0].local_header_offset, "end": record_end, "entries": group})
    ordered.sort(key=lambda item: item["offset"])

    for index in range(1, len(ordered)):
        previous = ordered[index - 1]
        current = ordered[index]
        current_entry = current["entries"][0]
        if previous["end"] > current["offset"]:
            add_finding(
                MALFORMED_ZIP,
                "compressed data or a data descriptor overlaps the next local file header",
                current_entry.index,
                current_entry.name,
            )
        elif policy.reject_polyglot and previous["end"] < current["offset"]:
            add_finding(
                POLYGLOT,
                "unaccounted bytes appear between local file records",
                current_entry.index,
                current_entry.name,
            )
    if ordered:
        last = ordered[-1]
        entry = last["entries"][0]
        if last["end"] > central_directory_offset:
            add_finding(
                TRUNCATED,
                "final local file record reaches into the central directory",
                entry.index,
                entry.name,
            )
        elif policy.reject_polyglot and last["end"] < central_directory_offset:
            add_finding(
                POLYGLOT,
                "unaccounted bytes appear before the central directory",
                entry.index,
                entry.name,
            )


def _add_overlap_findings(
    entries: List[_ParsedEntry],
    add_finding: Callable[[str, str, Optional[int], Optional[str]], None],
) -> None:
    ranges = sorted(
        (entry for entry in entries if entry.data_offset is not None and entry.data_end is not None),
        key=lambda entry: (entry.data_offset, entry.data_end, entry.index),
    )
    empty_offsets = set()
    active_start = -1
    active_end = -1
    for current in ranges:
        assert current.data_offset is not None and current.data_end is not None
        if current.compressed_size == 0:
            empty_inside_positive = active_start < current.data_offset < active_end
            if current.data_offset in empty_offsets or empty_inside_positive:
                add_finding(
                    OVERLAPPING_DATA,
                    "compressed data ranges overlap, a non-recursive zip-bomb and parser-differential primitive",
                    current.index,
                    current.name,
                )
            else:
                empty_offsets.add(current.data_offset)
            continue
        if current.data_offset < active_end:
            add_finding(
                OVERLAPPING_DATA,
                "compressed data ranges overlap, a non-recursive zip-bomb and parser-differential primitive",
                current.index,
                current.name,
            )
        if current.data_end > active_end:
            active_start = current.data_offset
            active_end = current.data_end


def inspect_zip_bytes(data: bytes, policy: Optional[ZipPolicy] = None) -> InspectionReport:
    """Inspect a complete classic ZIP archive held in memory.

    The parser is deliberately independent from :mod:`zipfile` so hostile
    header differentials are measured rather than inherited. A report with
    ``safe`` false is never partially trusted by the read or extraction APIs.
    """

    config = _resolve_policy(policy)
    archive = _as_bytes(data, "zip input")
    entries: List[_ParsedEntry] = []
    findings: List[Finding] = []

    def add_finding(code: str, message: str, entry_index: Optional[int], entry_name: Optional[str]) -> None:
        findings.append(Finding(code=code, message=message, entry_index=entry_index, entry_name=entry_name))

    if len(archive) > config.max_archive_bytes:
        add_finding(SIZE_LIMIT, "archive byte length exceeds max_archive_bytes", None, None)
    if len(archive) < EOCD_MIN_LENGTH:
        add_finding(TRUNCATED, "input is too short to contain an end of central directory record", None, None)
        return _finish_report(entries, findings, len(archive))

    eocd_result = _locate_eocd(archive, config.reject_polyglot)
    if eocd_result is None:
        add_finding(MALFORMED_ZIP, "end of central directory record was not found", None, None)
        return _finish_report(entries, findings, len(archive))
    if eocd_result.ambiguous:
        add_finding(
            MALFORMED_ZIP,
            "multiple structurally plausible end of central directory records make the archive ambiguous",
            None,
            None,
        )
        return _finish_report(entries, findings, len(archive))
    eocd = eocd_result.candidate
    if config.reject_polyglot and eocd.end != len(archive):
        add_finding(POLYGLOT, "trailing bytes after the end of central directory are rejected", None, None)

    disk_number = _u16(archive, eocd.offset + 4)
    central_directory_disk = _u16(archive, eocd.offset + 6)
    entries_on_disk = _u16(archive, eocd.offset + 8)
    total_entries = _u16(archive, eocd.offset + 10)
    central_directory_size = _u32(archive, eocd.offset + 12)
    central_directory_offset = _u32(archive, eocd.offset + 16)
    if disk_number != 0 or central_directory_disk != 0 or entries_on_disk != total_entries:
        add_finding(MULTI_DISK, "multi-disk archives are outside the supported scope", None, None)
    if (
        total_entries == UINT16_MAX
        or entries_on_disk == UINT16_MAX
        or central_directory_size == UINT32_MAX
        or central_directory_offset == UINT32_MAX
    ):
        add_finding(UNSUPPORTED_ZIP64, "ZIP64 sentinel values are outside the supported scope", None, None)
        return _finish_report(entries, findings, len(archive))
    if total_entries > config.max_entries:
        add_finding(ENTRY_LIMIT, "entry count exceeds max_entries", None, None)

    central_directory_end = central_directory_offset + central_directory_size
    if central_directory_end > eocd.offset:
        add_finding(TRUNCATED, "central directory extends beyond its end record", None, None)
        return _finish_report(entries, findings, len(archive))
    if central_directory_end != eocd.offset:
        add_finding(MALFORMED_ZIP, "unexpected bytes appear between the central directory and its end record", None, None)

    parse_count = min(total_entries, config.max_entries)
    offset = central_directory_offset
    parsed = 0
    while parsed < parse_count:
        parsed_entry = _parse_central_entry(archive, offset, parsed, add_finding)
        if parsed_entry is None:
            break
        entry, end = parsed_entry
        if end > central_directory_end:
            add_finding(TRUNCATED, "central directory entry extends beyond the central directory", parsed, None)
            break
        entries.append(entry)
        offset = end
        parsed += 1
    if parsed != total_entries and total_entries <= config.max_entries:
        add_finding(MALFORMED_ZIP, "central directory entry count does not match the end record", None, None)
    if parsed == total_entries and offset != central_directory_end:
        add_finding(MALFORMED_ZIP, "central directory size does not match its parsed entries", None, None)

    for entry in entries:
        if entry.invalid_encoding:
            add_finding(
                INVALID_ENCODING,
                "UTF-8 filename flag is set but filename bytes are invalid UTF-8",
                entry.index,
                entry.name,
            )
        central_extra = _extra_field_state(entry.central_extra)
        if central_extra.malformed:
            add_finding(MALFORMED_ZIP, "central directory extra field is malformed", entry.index, entry.name)
        if central_extra.zip64:
            add_finding(UNSUPPORTED_ZIP64, "ZIP64 central extra fields are outside the supported scope", entry.index, entry.name)
        if (
            entry.compressed_size == UINT32_MAX
            or entry.uncompressed_size == UINT32_MAX
            or entry.local_header_offset == UINT32_MAX
        ):
            add_finding(
                UNSUPPORTED_ZIP64,
                "32-bit sentinel values reserved for ZIP64 are outside the supported scope",
                entry.index,
                entry.name,
            )
        if entry.disk_number_start != 0:
            add_finding(MULTI_DISK, "entry starts on a nonzero disk number", entry.index, entry.name)
        if entry.encrypted and not config.allow_encrypted:
            add_finding(
                ENCRYPTED,
                "encrypted entries are rejected because plaintext size and checksum cannot be verified",
                entry.index,
                entry.name,
            )
        if entry.flags & UNSUPPORTED_FLAG_MASK:
            add_finding(UNSUPPORTED_FLAGS, "unsupported or reserved general-purpose flag bits are set", entry.index, entry.name)
        if entry.compression_method == METHOD_STORED and entry.flags & 0x0006:
            add_finding(
                UNSUPPORTED_FLAGS,
                "compression-option flag bits are undefined for stored entries",
                entry.index,
                entry.name,
            )
        if entry.compression_method not in (METHOD_STORED, METHOD_DEFLATE):
            add_finding(
                UNSUPPORTED_METHOD,
                "only stored and deflate compression methods can be verified",
                entry.index,
                entry.name,
            )
        path_finding_count = len(findings)
        _validate_entry_path(entry, config, add_finding)
        entry.path_validation_failed = len(findings) != path_finding_count
        _validate_unix_attributes(entry, config, add_finding)
        if entry.directory and (entry.compressed_size != 0 or entry.uncompressed_size != 0):
            add_finding(
                MALFORMED_ZIP,
                "directory entries must not carry compressed or uncompressed file data",
                entry.index,
                entry.name,
            )
        _verify_local_record(archive, entry, central_directory_offset, add_finding)
        _validate_unicode_path_extras(entry, central_extra, add_finding)

    if entries:
        minimum_local_offset = min(entry.local_header_offset for entry in entries)
        if config.reject_polyglot and minimum_local_offset != 0:
            add_finding(POLYGLOT, "prepended bytes before the first local file header are rejected", None, None)
    elif config.reject_polyglot and central_directory_offset != 0:
        add_finding(POLYGLOT, "prepended bytes before an empty central directory are rejected", None, None)

    _add_duplicate_and_collision_findings(entries, config, add_finding)
    _add_overlap_findings(entries, add_finding)
    _add_local_layout_findings(archive, entries, central_directory_offset, config, add_finding)

    total_uncompressed = 0
    total_compressed = 0
    for entry in entries:
        total_uncompressed += entry.uncompressed_size
        total_compressed += entry.compressed_size
        if entry.uncompressed_size > config.max_entry_bytes:
            add_finding(SIZE_LIMIT, "entry uncompressed size exceeds max_entry_bytes", entry.index, entry.name)
        if entry.compressed_size == 0 and entry.uncompressed_size > 0:
            add_finding(RATIO_LIMIT, "entry claims nonzero output from zero compressed bytes", entry.index, entry.name)
        elif entry.compressed_size > 0 and entry.uncompressed_size / entry.compressed_size > config.max_compression_ratio:
            add_finding(RATIO_LIMIT, "entry compression ratio exceeds max_compression_ratio", entry.index, entry.name)
    if total_uncompressed > config.max_total_bytes:
        add_finding(SIZE_LIMIT, "aggregate uncompressed size exceeds max_total_bytes", None, None)
    if total_compressed > 0 and total_uncompressed / total_compressed > config.max_compression_ratio:
        add_finding(RATIO_LIMIT, "aggregate compression ratio exceeds max_compression_ratio", None, None)

    return _finish_report(entries, findings, len(archive))


def _read_file_bytes_limited(path: object, limit: int) -> Tuple[bytes, int]:
    try:
        file_path = os.fspath(path)
    except TypeError:
        raise ZipCageError(INVALID_INPUT, "path must be a filesystem path", repr(path))
    if not isinstance(file_path, (str, bytes)) or len(file_path) == 0:
        raise ZipCageError(INVALID_INPUT, "path must be a non-empty filesystem path", repr(path))
    if (isinstance(file_path, str) and "\x00" in file_path) or (isinstance(file_path, bytes) and b"\x00" in file_path):
        raise ZipCageError(INVALID_INPUT, "path must not contain NUL bytes", repr(path))

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(file_path, flags)
    except OSError as exc:
        raise ZipCageError(INVALID_INPUT, "zip file could not be read: " + exc.__class__.__name__, repr(path))
    try:
        try:
            initial_stat = os.fstat(descriptor)
            if not stat.S_ISREG(initial_stat.st_mode):
                raise ZipCageError(INVALID_INPUT, "zip file must be a regular file", repr(path))
            parts = []
            remaining = limit + 1
            while remaining > 0:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                parts.append(chunk)
                remaining -= len(chunk)
            data = b"".join(parts)
            try:
                observed_size = os.fstat(descriptor).st_size
            except OSError:
                observed_size = len(data)
        except OSError as exc:
            raise ZipCageError(INVALID_INPUT, "zip file could not be read: " + exc.__class__.__name__, repr(path))
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return data, max(observed_size, len(data))


def inspect_zip_file(path: object, policy: Optional[ZipPolicy] = None) -> InspectionReport:
    """Read a ZIP file from disk with the archive cap applied before parsing."""

    config = _resolve_policy(policy)
    data, observed_size = _read_file_bytes_limited(path, config.max_archive_bytes)
    if observed_size > config.max_archive_bytes:
        findings = [
            Finding(
                code=SIZE_LIMIT,
                message="archive byte length exceeds max_archive_bytes",
                entry_index=None,
                entry_name=None,
            )
        ]
        return _finish_report([], findings, observed_size)
    return inspect_zip_bytes(data, config)


def _archive_error_from_report(report: InspectionReport) -> ZipCageError:
    first = report.findings[0]
    return ZipCageError(first.code, first.message, first.entry_name, report.findings)


def assert_safe_zip_bytes(data: bytes, policy: Optional[ZipPolicy] = None) -> InspectionReport:
    """Inspect bytes and raise :class:`ZipCageError` unless zero findings exist."""

    report = inspect_zip_bytes(data, policy)
    if report.safe:
        return report
    raise _archive_error_from_report(report)


def _find_entry(report: InspectionReport, entry_name: str) -> ZipEntryInfo:
    if not isinstance(entry_name, str) or len(entry_name) == 0:
        raise ZipCageError(INVALID_INPUT, "entry_name must be a non-empty string", repr(entry_name))
    matches = [
        entry
        for entry in report.entries
        if entry.name == entry_name or entry.normalized_name == entry_name
    ]
    if not matches:
        raise ZipCageError(ENTRY_NOT_FOUND, "entry was not found in the inspected archive", entry_name)
    if len(matches) > 1:
        raise ZipCageError(INVALID_INPUT, "entry_name is ambiguous in this archive", entry_name)
    return matches[0]


def _compressed_bytes_for_entry(data: bytes, entry: ZipEntryInfo) -> bytes:
    if entry.data_offset is None or entry.data_end is None or entry.data_end < entry.data_offset:
        raise ZipCageError(MALFORMED_ZIP, "entry compressed data range is unavailable", entry.name)
    return data[entry.data_offset : entry.data_end]


def _inflate_raw_bounded(compressed: bytes, maximum_output_bytes: int, input_name: str) -> Iterator[bytes]:
    """Yield raw deflate output with every output call hard capped.

    ``max_length`` is never the declared size because that size is attacker
    controlled and may be huge. Each zlib output allocation is at most 64 KiB,
    while the aggregate cap is enforced independently.
    """

    decompressor = zlib.decompressobj(wbits=-15)
    produced = 0
    position = 0
    pending = b""
    eof = False
    trailing_bytes = 0
    while True:
        if not pending:
            if position >= len(compressed):
                break
            pending = compressed[position : position + INFLATE_INPUT_CHUNK_BYTES]
            position += len(pending)
        allowance = maximum_output_bytes + 1 - produced
        max_length = min(INFLATE_OUTPUT_CHUNK_BYTES, max(1, allowance))
        try:
            chunk = decompressor.decompress(pending, max_length)
        except zlib.error:
            raise ZipCageError(DEFLATE_ERROR, "deflate stream is malformed or truncated", input_name)
        if chunk:
            produced += len(chunk)
            if produced > maximum_output_bytes:
                raise ZipCageError(SIZE_LIMIT, "decompressed output exceeded the hard byte cap", input_name)
            yield chunk
        if decompressor.eof:
            eof = True
            trailing_bytes = len(decompressor.unused_data) + (len(compressed) - position)
            break
        unconsumed = decompressor.unconsumed_tail
        pending = unconsumed if unconsumed else b""
        if not pending and position >= len(compressed):
            break
    if not eof:
        raise ZipCageError(DEFLATE_ERROR, "deflate stream is malformed or truncated", input_name)
    if trailing_bytes:
        raise ZipCageError(
            TRAILING_COMPRESSED_DATA,
            "compressed size contains bytes after the end of the deflate stream",
            input_name,
        )


def _decompressed_entry_chunks(data: bytes, entry: ZipEntryInfo, policy: ZipPolicy) -> Iterator[bytes]:
    if entry.encrypted:
        raise ZipCageError(ENCRYPTED, "encrypted entries cannot be verified or decompressed", entry.name)
    if entry.compression_method not in (METHOD_STORED, METHOD_DEFLATE):
        raise ZipCageError(UNSUPPORTED_METHOD, "entry compression method is unsupported", entry.name)
    compressed = _compressed_bytes_for_entry(data, entry)
    if entry.compression_method == METHOD_STORED:
        if entry.compressed_size != entry.uncompressed_size:
            raise ZipCageError(SIZE_MISMATCH, "stored entry compressed and uncompressed sizes differ", entry.name)
        checksum = _crc32(compressed)
        if len(compressed) != entry.uncompressed_size:
            raise ZipCageError(SIZE_MISMATCH, "actual stored size does not match the central directory", entry.name)
        if checksum != entry.crc32:
            raise ZipCageError(CRC_MISMATCH, "actual stored CRC-32 does not match the central directory", entry.name)
        if compressed:
            yield bytes(compressed)
        return

    maximum_output_bytes = min(policy.max_entry_bytes, entry.uncompressed_size)
    produced = 0
    checksum = 0
    for chunk in _inflate_raw_bounded(compressed, maximum_output_bytes, entry.name):
        produced += len(chunk)
        checksum = _crc32(chunk, checksum)
        yield chunk
    if produced != entry.uncompressed_size:
        raise ZipCageError(SIZE_MISMATCH, "actual decompressed size does not match the central directory", entry.name)
    if checksum != entry.crc32:
        raise ZipCageError(CRC_MISMATCH, "actual decompressed CRC-32 does not match the central directory", entry.name)


def _decompress_entry(data: bytes, entry: ZipEntryInfo, policy: ZipPolicy) -> bytes:
    parts = []
    for chunk in _decompressed_entry_chunks(data, entry, policy):
        parts.append(chunk)
    return b"".join(parts)


def read_zip_entry(data: bytes, entry_name: str, policy: Optional[ZipPolicy] = None) -> bytes:
    """Read one regular file after full archive inspection and exact verification."""

    config = _resolve_policy(policy)
    archive = _as_bytes(data, "zip input")
    report = inspect_zip_bytes(archive, config)
    if not report.safe:
        raise _archive_error_from_report(report)
    entry = _find_entry(report, entry_name)
    if entry.directory:
        raise ZipCageError(INVALID_INPUT, "directory entries do not have file content", entry_name)
    if entry.unix_file_type not in ("file", "unspecified"):
        raise ZipCageError(EXTRACTION_REFUSED, "only regular file content can be read safely", entry_name)
    return _decompress_entry(archive, entry, config)


__all__ = [
    "CENTRAL_FIXED_LENGTH",
    "CENTRAL_SIGNATURE",
    "DATA_DESCRIPTOR_SIGNATURE",
    "EOCD_MIN_LENGTH",
    "EOCD_SIGNATURE",
    "FLAG_DATA_DESCRIPTOR",
    "FLAG_ENCRYPTED",
    "FLAG_UTF8",
    "LOCAL_FIXED_LENGTH",
    "LOCAL_SIGNATURE",
    "METHOD_DEFLATE",
    "METHOD_STORED",
    "UNICODE_PATH_EXTRA_ID",
    "assert_safe_zip_bytes",
    "inspect_zip_bytes",
    "inspect_zip_file",
    "read_zip_entry",
]
