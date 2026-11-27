"""pyzipcage: zero-dependency ZIP security inspection and safe extraction.

Typical use::

    from pyzipcage import assert_safe_zip_bytes, extract_zip_bytes

    assert_safe_zip_bytes(archive_bytes)
    result = extract_zip_bytes(archive_bytes, "private-empty-directory")
"""

from __future__ import annotations

from .builder import create_zip_bytes
from .core import assert_safe_zip_bytes, inspect_zip_bytes, inspect_zip_file, read_zip_entry
from .errors import ERROR_CODES, ZipCageError
from .extract import extract_zip_bytes, extract_zip_file
from .guard import ZipGuard
from .models import (
    ExtractedFile,
    ExtractionReport,
    Finding,
    InspectionReport,
    Totals,
    ZipEntryInfo,
    ZipPolicy,
)

__version__ = "1.0.0"

__all__ = [
    "ERROR_CODES",
    "ExtractedFile",
    "ExtractionReport",
    "Finding",
    "InspectionReport",
    "Totals",
    "ZipCageError",
    "ZipEntryInfo",
    "ZipGuard",
    "ZipPolicy",
    "__version__",
    "assert_safe_zip_bytes",
    "create_zip_bytes",
    "extract_zip_bytes",
    "extract_zip_file",
    "inspect_zip_bytes",
    "inspect_zip_file",
    "read_zip_entry",
]
