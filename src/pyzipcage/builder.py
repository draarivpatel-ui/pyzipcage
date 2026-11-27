"""Deterministic classic ZIP builder used by tests and careful callers."""

from __future__ import annotations

import struct
import zlib
from collections.abc import Mapping
from typing import Any, Iterable, List, Optional, Tuple

from .core import (
    CENTRAL_FIXED_LENGTH,
    CENTRAL_SIGNATURE,
    DATA_DESCRIPTOR_SIGNATURE,
    EOCD_MIN_LENGTH,
    EOCD_SIGNATURE,
    FLAG_DATA_DESCRIPTOR,
    FLAG_UTF8,
    LOCAL_FIXED_LENGTH,
    LOCAL_SIGNATURE,
    METHOD_DEFLATE,
    METHOD_STORED,
    inspect_zip_bytes,
)
from .errors import INVALID_INPUT, ZipCageError

UINT16_MAX = 0xFFFF
UINT32_MAX = 0xFFFFFFFF

_BUILDER_OPTION_KEYS = frozenset(("validate", "prepend_bytes", "trailing_bytes", "comment"))
_BUILDER_ENTRY_KEYS = frozenset(
    (
        "name",
        "name_bytes",
        "local_name_bytes",
        "data",
        "method",
        "compressed_data",
        "directory",
        "utf8",
        "data_descriptor",
        "signed_descriptor",
        "mode",
        "unix_mode",
        "external_attributes",
        "dos_time",
        "dos_date",
        "version_needed",
        "version_made_by",
        "flags",
        "central_flags",
        "local_flags",
        "crc32",
        "central_crc32",
        "local_crc32",
        "compressed_size",
        "central_compressed_size",
        "local_compressed_size",
        "uncompressed_size",
        "central_uncompressed_size",
        "local_uncompressed_size",
        "central_method",
        "local_method",
        "local_extra",
        "central_extra",
        "comment",
        "write_local",
        "central_local_header_offset",
    )
)


def _invalid(message: str, value: object) -> None:
    raise ZipCageError(INVALID_INPUT, message, repr(value))


def _bytes_from(value: object, label: str) -> bytes:
    if value is None:
        return b""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    _invalid(label + " must be text or bytes", value)
    return b""


def _bool_value(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        _invalid(label + " must be a boolean", value)
    return value


def _uint32(value: object, fallback: int, label: str) -> int:
    if value is None:
        return fallback & UINT32_MAX
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > UINT32_MAX:
        _invalid(label + " must be an unsigned 32-bit integer", value)
    return value


def _uint16(value: object, fallback: int, label: str) -> int:
    if value is None:
        return fallback & UINT16_MAX
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > UINT16_MAX:
        _invalid(label + " must be an unsigned 16-bit integer", value)
    return value


def _method(value: object) -> int:
    if value is None:
        return METHOD_STORED
    if value in (METHOD_STORED, "stored", "store"):
        return METHOD_STORED
    if value in (METHOD_DEFLATE, "deflate"):
        return METHOD_DEFLATE
    _invalid("ZIP entry method must be 0, 8, stored or deflate", value)
    return METHOD_STORED


def _local_header(values: Mapping[str, int]) -> bytes:
    return struct.pack(
        "<IHHHHHIIIHH",
        LOCAL_SIGNATURE,
        values["version_needed"],
        values["flags"],
        values["method"],
        values["dos_time"],
        values["dos_date"],
        values["crc32"],
        values["compressed_size"],
        values["uncompressed_size"],
        values["file_name_length"],
        values["extra_length"],
    )


def _central_header(values: Mapping[str, int]) -> bytes:
    return struct.pack(
        "<IHHHHHHIIIHHHHHII",
        CENTRAL_SIGNATURE,
        values["version_made_by"],
        values["version_needed"],
        values["flags"],
        values["method"],
        values["dos_time"],
        values["dos_date"],
        values["crc32"],
        values["compressed_size"],
        values["uncompressed_size"],
        values["file_name_length"],
        values["extra_length"],
        values["comment_length"],
        values["disk_number_start"],
        values["internal_attributes"],
        values["external_attributes"],
        values["local_header_offset"],
    )


def _deflate_raw(data: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-15)
    return compressor.compress(data) + compressor.flush()


def create_zip_bytes(entries: Iterable[Mapping[str, Any]], options: Optional[Mapping[str, Any]] = None) -> bytes:
    """Build a deterministic classic ZIP archive.

    Each entry normally needs only ``name``, ``data``, and optionally
    ``method`` (``"stored"`` or ``"deflate"``). Advanced override keys exist so
    the test suite can construct exact parser-differential fixtures without
    relying on the platform ZIP implementation.
    """

    if isinstance(entries, (str, bytes, bytearray, memoryview)):
        _invalid("entries must be an iterable of mappings", entries)
    try:
        input_entries = list(entries)
    except TypeError:
        _invalid("entries must be an iterable of mappings", entries)
    if options is None:
        builder_options = {}
    elif isinstance(options, Mapping):
        builder_options = dict(options)
    else:
        _invalid("create_zip_bytes options must be a mapping", options)
    for key in builder_options:
        if key not in _BUILDER_OPTION_KEYS:
            _invalid("unknown create_zip_bytes option key: " + str(key), key)
    validate_value = builder_options.get("validate", True)
    validate = _bool_value(validate_value, "validate")
    prefix = _bytes_from(builder_options.get("prepend_bytes"), "prepend_bytes")
    trailing = _bytes_from(builder_options.get("trailing_bytes"), "trailing_bytes")
    archive_comment = _bytes_from(builder_options.get("comment"), "comment")
    if len(input_entries) > UINT16_MAX:
        _invalid("classic ZIP supports at most 65535 entries", len(input_entries))
    if len(archive_comment) > UINT16_MAX:
        _invalid("ZIP comments are limited to 65535 bytes", len(archive_comment))

    prepared: List[dict] = []
    for index, input_entry in enumerate(input_entries):
        if not isinstance(input_entry, Mapping):
            _invalid("each ZIP entry must be a mapping", input_entry)
        for key in input_entry:
            if key not in _BUILDER_ENTRY_KEYS:
                _invalid("unknown ZIP builder entry key: " + str(key), key)
        name_value = input_entry.get("name", "")
        central_name_bytes = (
            _bytes_from(input_entry.get("name_bytes"), "name_bytes")
            if input_entry.get("name_bytes") is not None
            else _bytes_from(name_value, "entry name")
        )
        if len(central_name_bytes) > UINT16_MAX:
            _invalid("entry name is too long for classic ZIP", name_value)
        local_name_bytes = (
            _bytes_from(input_entry.get("local_name_bytes"), "local_name_bytes")
            if input_entry.get("local_name_bytes") is not None
            else central_name_bytes
        )
        if len(local_name_bytes) > UINT16_MAX:
            _invalid("local entry name is too long for classic ZIP", name_value)
        data = _bytes_from(input_entry.get("data"), "entry data")
        method = _method(input_entry.get("method"))
        if input_entry.get("compressed_data") is not None:
            compressed = _bytes_from(input_entry.get("compressed_data"), "compressed_data")
        elif method == METHOD_DEFLATE:
            compressed = _deflate_raw(data)
        else:
            compressed = bytes(data)
        directory = input_entry.get("directory") is True or (isinstance(name_value, str) and name_value.endswith("/"))
        utf8 = input_entry.get("utf8", True) is True
        data_descriptor = input_entry.get("data_descriptor") is True
        flags = (FLAG_UTF8 if utf8 else 0) | (FLAG_DATA_DESCRIPTOR if data_descriptor else 0)
        base_flags = _uint16(input_entry.get("flags"), flags, "flags")
        central_flags = _uint16(input_entry.get("central_flags"), base_flags, "central_flags")
        local_flags = _uint16(input_entry.get("local_flags"), central_flags, "local_flags")
        dos_time = _uint16(input_entry.get("dos_time"), 0, "dos_time")
        dos_date = _uint16(input_entry.get("dos_date"), 33, "dos_date")
        actual_crc = zlib.crc32(data) & UINT32_MAX
        actual_compressed_size = len(compressed)
        actual_uncompressed_size = len(data)
        base_crc = _uint32(input_entry.get("crc32"), actual_crc, "crc32")
        central_crc = _uint32(input_entry.get("central_crc32"), base_crc, "central_crc32")
        local_crc = _uint32(input_entry.get("local_crc32"), 0 if data_descriptor else central_crc, "local_crc32")
        base_compressed_size = _uint32(input_entry.get("compressed_size"), actual_compressed_size, "compressed_size")
        central_compressed_size = _uint32(
            input_entry.get("central_compressed_size"), base_compressed_size, "central_compressed_size"
        )
        local_compressed_size = _uint32(
            input_entry.get("local_compressed_size"), 0 if data_descriptor else central_compressed_size, "local_compressed_size"
        )
        base_uncompressed_size = _uint32(input_entry.get("uncompressed_size"), actual_uncompressed_size, "uncompressed_size")
        central_uncompressed_size = _uint32(
            input_entry.get("central_uncompressed_size"), base_uncompressed_size, "central_uncompressed_size"
        )
        local_uncompressed_size = _uint32(
            input_entry.get("local_uncompressed_size"), 0 if data_descriptor else central_uncompressed_size, "local_uncompressed_size"
        )
        central_method = _uint16(input_entry.get("central_method"), method, "central_method")
        local_method = _uint16(input_entry.get("local_method"), central_method, "local_method")
        version_needed = _uint16(input_entry.get("version_needed"), 20 if method == METHOD_DEFLATE else 10, "version_needed")
        version_made_by = _uint16(input_entry.get("version_made_by"), (3 << 8) | version_needed, "version_made_by")
        mode_value = input_entry.get("mode", 0o755 if directory else 0o644)
        if isinstance(mode_value, bool) or not isinstance(mode_value, int) or mode_value < 0 or mode_value > 0o7777:
            _invalid("entry mode must contain only permission and special bits", mode_value)
        if input_entry.get("unix_mode") is None:
            unix_mode = (0o040000 if directory else 0o100000) | mode_value
        else:
            unix_mode = input_entry.get("unix_mode")
        if isinstance(unix_mode, bool) or not isinstance(unix_mode, int) or unix_mode < 0 or unix_mode > 0xFFFF:
            _invalid("unix_mode must be an unsigned 16-bit mode", unix_mode)
        if input_entry.get("external_attributes") is None:
            external_attributes = ((unix_mode & 0xFFFF) << 16) | (0x10 if directory else 0)
        else:
            external_attributes = _uint32(input_entry.get("external_attributes"), 0, "external_attributes")
        local_extra = _bytes_from(input_entry.get("local_extra"), "local_extra")
        central_extra = _bytes_from(input_entry.get("central_extra"), "central_extra")
        entry_comment = _bytes_from(input_entry.get("comment"), "entry comment")
        if len(local_extra) > UINT16_MAX or len(central_extra) > UINT16_MAX or len(entry_comment) > UINT16_MAX:
            _invalid("extra fields and entry comments are limited to 65535 bytes", name_value)
        write_local = input_entry.get("write_local", True)
        if not isinstance(write_local, bool):
            _invalid("write_local must be a boolean", write_local)
        signed_descriptor = input_entry.get("signed_descriptor", True)
        if not isinstance(signed_descriptor, bool):
            _invalid("signed_descriptor must be a boolean", signed_descriptor)
        prepared.append(
            {
                "index": index,
                "name": name_value if isinstance(name_value, str) else "<binary>",
                "central_name_bytes": central_name_bytes,
                "local_name_bytes": local_name_bytes,
                "compressed": compressed,
                "write_local": write_local,
                "central_local_header_offset": input_entry.get("central_local_header_offset"),
                "central_flags": central_flags,
                "local_flags": local_flags,
                "dos_time": dos_time,
                "dos_date": dos_date,
                "central_crc": central_crc,
                "local_crc": local_crc,
                "central_compressed_size": central_compressed_size,
                "local_compressed_size": local_compressed_size,
                "central_uncompressed_size": central_uncompressed_size,
                "local_uncompressed_size": local_uncompressed_size,
                "central_method": central_method,
                "local_method": local_method,
                "version_needed": version_needed,
                "version_made_by": version_made_by,
                "external_attributes": external_attributes,
                "local_extra": local_extra,
                "central_extra": central_extra,
                "entry_comment": entry_comment,
                "data_descriptor": data_descriptor,
                "signed_descriptor": signed_descriptor,
            }
        )

    local_parts: List[bytes] = []
    offset = len(prefix)
    actual_offsets: List[Optional[int]] = []
    for entry in prepared:
        if not entry["write_local"]:
            actual_offsets.append(None)
            continue
        actual_offsets.append(offset)
        header = _local_header(
            {
                "version_needed": entry["version_needed"],
                "flags": entry["local_flags"],
                "method": entry["local_method"],
                "dos_time": entry["dos_time"],
                "dos_date": entry["dos_date"],
                "crc32": entry["local_crc"],
                "compressed_size": entry["local_compressed_size"],
                "uncompressed_size": entry["local_uncompressed_size"],
                "file_name_length": len(entry["local_name_bytes"]),
                "extra_length": len(entry["local_extra"]),
            }
        )
        local_parts.extend((header, entry["local_name_bytes"], entry["local_extra"], entry["compressed"]))
        offset += len(header) + len(entry["local_name_bytes"]) + len(entry["local_extra"]) + len(entry["compressed"])
        if entry["data_descriptor"]:
            if entry["signed_descriptor"]:
                descriptor = struct.pack(
                    "<IIII",
                    DATA_DESCRIPTOR_SIGNATURE,
                    entry["central_crc"],
                    entry["central_compressed_size"],
                    entry["central_uncompressed_size"],
                )
            else:
                descriptor = struct.pack(
                    "<III",
                    entry["central_crc"],
                    entry["central_compressed_size"],
                    entry["central_uncompressed_size"],
                )
            local_parts.append(descriptor)
            offset += len(descriptor)
        if offset > UINT32_MAX:
            _invalid("classic ZIP offsets cannot exceed 32 bits", entry["name"])

    central_offset = offset
    central_parts: List[bytes] = []
    for index, entry in enumerate(prepared):
        if entry["central_local_header_offset"] is None:
            local_offset = actual_offsets[index]
        else:
            local_offset = _uint32(entry["central_local_header_offset"], 0, "central_local_header_offset")
        if local_offset is None:
            _invalid("write_local false requires central_local_header_offset", entry["name"])
        central = _central_header(
            {
                "version_made_by": entry["version_made_by"],
                "version_needed": entry["version_needed"],
                "flags": entry["central_flags"],
                "method": entry["central_method"],
                "dos_time": entry["dos_time"],
                "dos_date": entry["dos_date"],
                "crc32": entry["central_crc"],
                "compressed_size": entry["central_compressed_size"],
                "uncompressed_size": entry["central_uncompressed_size"],
                "file_name_length": len(entry["central_name_bytes"]),
                "extra_length": len(entry["central_extra"]),
                "comment_length": len(entry["entry_comment"]),
                "disk_number_start": 0,
                "internal_attributes": 0,
                "external_attributes": entry["external_attributes"],
                "local_header_offset": local_offset,
            }
        )
        central_parts.extend((central, entry["central_name_bytes"], entry["central_extra"], entry["entry_comment"]))
        offset += len(central) + len(entry["central_name_bytes"]) + len(entry["central_extra"]) + len(entry["entry_comment"])
    central_size = offset - central_offset

    eocd = struct.pack(
        "<IHHHHIIH",
        EOCD_SIGNATURE,
        0,
        0,
        len(prepared),
        len(prepared),
        central_size,
        central_offset,
        len(archive_comment),
    )
    output = b"".join([prefix] + local_parts + central_parts + [eocd, archive_comment, trailing])
    if validate:
        report = inspect_zip_bytes(output)
        if not report.safe:
            first = report.findings[0]
            raise ZipCageError(first.code, first.message, first.entry_name, report.findings)
    return output


__all__ = ["create_zip_bytes"]
