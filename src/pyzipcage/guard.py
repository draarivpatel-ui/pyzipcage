"""Reusable configured guard object."""

from __future__ import annotations

from typing import Optional

from .builder import create_zip_bytes
from .core import assert_safe_zip_bytes, inspect_zip_bytes, inspect_zip_file, read_zip_entry
from .extract import extract_zip_bytes, extract_zip_file
from .models import ExtractionReport, InspectionReport, ZipPolicy


class ZipGuard:
    """Reusable guard carrying one immutable :class:`ZipPolicy`."""

    __slots__ = ("policy",)

    def __init__(self, policy: Optional[ZipPolicy] = None) -> None:
        self.policy = policy if policy is not None else ZipPolicy()
        if not isinstance(self.policy, ZipPolicy):
            from .errors import INVALID_OPTIONS, ZipCageError

            raise ZipCageError(INVALID_OPTIONS, "policy must be a ZipPolicy instance", repr(policy))

    def inspect(self, data: bytes) -> InspectionReport:
        """Inspect archive bytes with this guard's policy."""

        return inspect_zip_bytes(data, self.policy)

    def inspect_file(self, path: object) -> InspectionReport:
        """Inspect a ZIP file with this guard's policy."""

        return inspect_zip_file(path, self.policy)

    def assert_safe(self, data: bytes) -> InspectionReport:
        """Raise unless archive bytes are safe under this guard's policy."""

        return assert_safe_zip_bytes(data, self.policy)

    def read_entry(self, data: bytes, entry_name: str) -> bytes:
        """Read one regular file from safe archive bytes."""

        return read_zip_entry(data, entry_name, self.policy)

    def extract(self, data: bytes, target_dir: object) -> ExtractionReport:
        """Extract safe archive bytes with this guard's policy."""

        return extract_zip_bytes(data, target_dir, self.policy)

    def extract_file(self, zip_path: object, target_dir: object) -> ExtractionReport:
        """Read and extract a ZIP file with this guard's policy."""

        return extract_zip_file(zip_path, target_dir, self.policy)

    @staticmethod
    def create(entries: object) -> bytes:
        """Build deterministic archive bytes. See :func:`create_zip_bytes`."""

        return create_zip_bytes(entries)  # type: ignore[arg-type]


__all__ = ["ZipGuard"]
