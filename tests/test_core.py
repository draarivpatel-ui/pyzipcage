"""Core valid-archive, API, and bounded decompression tests."""

from __future__ import annotations

import dataclasses
import os
import tempfile
import unittest

import pyzipcage
from pyzipcage import ZipCageError, ZipPolicy

from _support import (
    build,
    crc32,
    deflate_raw,
    finding_codes,
    simple_zip,
    unicode_path_extra,
    unknown_extra,
    valid_build,
    ZipCageTestCase,
)


class CoreArchiveTests(ZipCageTestCase):
    def test_empty_archive_is_safe(self):
        archive = valid_build([])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertEqual(0, report.totals.entries)
        self.assertEqual(1.0, report.totals.compression_ratio)

    def test_stored_file_is_safe(self):
        report = pyzipcage.inspect_zip_bytes(simple_zip())
        self.assertTrue(report.safe)
        self.assertEqual(1, report.totals.files)
        self.assertEqual("stored", report.entries[0].compression_method_name)

    def test_deflate_file_is_safe(self):
        report = pyzipcage.inspect_zip_bytes(simple_zip(method="deflate"))
        self.assertTrue(report.safe)
        self.assertEqual("deflate", report.entries[0].compression_method_name)

    def test_mixed_files_and_directories_are_safe(self):
        archive = valid_build([
            {"name": "dir/"},
            {"name": "dir/a.txt", "data": b"a"},
            {"name": "b.bin", "data": bytes(range(32)), "method": "deflate"},
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertEqual(2, report.totals.files)
        self.assertEqual(1, report.totals.directories)

    def test_nested_directory_metadata_is_reported(self):
        archive = valid_build([{"name": "a/b/c.txt", "data": b"x"}])
        entry = pyzipcage.inspect_zip_bytes(archive).entries[0]
        self.assertEqual(("a", "b", "c.txt"), entry.path_segments)
        self.assertEqual("a/b/c.txt", entry.normalized_name)

    def test_unicode_utf8_name_is_safe(self):
        archive = valid_build([{"name": "caf\u00e9.txt", "data": b"x"}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertTrue(report.entries[0].utf8)
        self.assertEqual("caf\u00e9.txt", report.entries[0].name)

    def test_cp437_high_bit_name_is_safe_without_utf8_flag(self):
        archive = valid_build([{"name": "cp.txt", "name_bytes": b"caf\x82.txt", "utf8": False, "data": b"x"}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertFalse(report.entries[0].utf8)
        self.assertEqual("caf\u00e9.txt", report.entries[0].name)

    def test_archive_comment_is_safe(self):
        archive = valid_build([{"name": "ok.txt", "data": b"x"}], comment=b"archive comment")
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)

    def test_entry_comment_is_safe(self):
        archive = valid_build([{"name": "ok.txt", "data": b"x", "comment": b"entry comment"}])
        entry = pyzipcage.inspect_zip_bytes(archive).entries[0]
        self.assertEqual(len("entry comment"), entry.comment_length)

    def test_empty_stored_file_is_safe(self):
        archive = valid_build([{"name": "empty", "data": b""}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertEqual(b"", pyzipcage.read_zip_entry(archive, "empty"))

    def test_empty_deflate_file_is_safe(self):
        archive = valid_build([{"name": "empty", "data": b"", "method": "deflate"}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertEqual(b"", pyzipcage.read_zip_entry(archive, "empty"))

    def test_signed_data_descriptor_is_safe(self):
        archive = valid_build([{"name": "x", "data": b"abc", "method": "deflate", "data_descriptor": True}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertTrue(report.entries[0].data_descriptor)
        self.assertEqual(b"abc", pyzipcage.read_zip_entry(archive, "x"))

    def test_unsigned_data_descriptor_is_safe(self):
        archive = valid_build([
            {"name": "x", "data": b"abc", "method": "deflate", "data_descriptor": True, "signed_descriptor": False}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertEqual(b"abc", pyzipcage.read_zip_entry(archive, "x"))

    def test_unknown_well_formed_central_extra_is_safe(self):
        archive = valid_build([{"name": "ok.txt", "data": b"x", "central_extra": unknown_extra()}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertEqual(6, report.entries[0].extra_length)

    def test_unknown_well_formed_local_extra_is_safe(self):
        archive = valid_build([{"name": "ok.txt", "data": b"x", "local_extra": unknown_extra(0xBEEF, b"local")}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertEqual(9, report.entries[0].local_extra_length)

    def test_consistent_unicode_path_extra_is_accepted(self):
        name = "unicode-\u2603.txt"
        encoded = name.encode("utf-8")
        archive = valid_build([
            {"name": name, "data": b"x", "central_extra": unicode_path_extra(encoded, encoded)}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)

    def test_non_unix_version_made_by_regular_file_is_safe(self):
        archive = valid_build([{"name": "ok.txt", "data": b"x", "version_made_by": 20}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertEqual(20, report.entries[0].version_made_by)

    def test_totals_measure_archive_and_content_bytes(self):
        payload = bytes(range(64))
        archive = simple_zip(data=payload, method="deflate")
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertEqual(len(archive), report.totals.archive_bytes)
        self.assertEqual(len(payload), report.totals.uncompressed_bytes)
        self.assertEqual(report.entries[0].compressed_size, report.totals.compressed_bytes)

    def test_entry_metadata_is_complete(self):
        archive = simple_zip()
        entry = pyzipcage.inspect_zip_bytes(archive).entries[0]
        for key in (
            "index",
            "name",
            "normalized_name",
            "path_segments",
            "directory",
            "version_made_by",
            "version_needed",
            "flags",
            "crc32",
            "compressed_size",
            "uncompressed_size",
            "local_header_offset",
            "data_offset",
            "data_end",
            "local_crc32",
            "invalid_encoding",
        ):
            self.assertIn(key, entry.to_dict())

    def test_inspect_file_accepts_string_path(self):
        archive = simple_zip()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "in.zip")
            with open(path, "wb") as handle:
                handle.write(archive)
            report = pyzipcage.inspect_zip_file(path)
        self.assertTrue(report.safe)

    def test_inspect_file_accepts_pathlike(self):
        archive = simple_zip()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "in.zip")
            with open(path, "wb") as handle:
                handle.write(archive)
            import pathlib

            report = pyzipcage.inspect_zip_file(pathlib.Path(path))
        self.assertTrue(report.safe)

    def test_assert_safe_returns_report_for_safe_archive(self):
        archive = simple_zip()
        report = pyzipcage.assert_safe_zip_bytes(archive)
        self.assertTrue(report.safe)

    def test_assert_safe_raises_machine_readable_findings(self):
        archive = build([{"name": "../evil", "data": b"x"}])
        error = self.assertError(
            pyzipcage.errors.PATH_TRAVERSAL if hasattr(pyzipcage, "errors") else "ERR_ZIPCAGE_PATH_TRAVERSAL",
            pyzipcage.assert_safe_zip_bytes,
            archive,
        )
        self.assertTrue(error.findings)

    def test_bytearray_input_is_accepted(self):
        archive = simple_zip()
        report = pyzipcage.inspect_zip_bytes(bytearray(archive))
        self.assertTrue(report.safe)

    def test_memoryview_input_is_accepted(self):
        archive = simple_zip()
        report = pyzipcage.inspect_zip_bytes(memoryview(archive))
        self.assertTrue(report.safe)

    def test_string_archive_input_is_rejected(self):
        self.assertError("ERR_ZIPCAGE_INVALID_INPUT", pyzipcage.inspect_zip_bytes, "not bytes")

    def test_invalid_policy_object_is_rejected(self):
        self.assertError("ERR_ZIPCAGE_INVALID_OPTIONS", pyzipcage.inspect_zip_bytes, simple_zip(), object())

    def test_read_returns_stored_bytes(self):
        payload = b"stored payload"
        archive = simple_zip(data=payload)
        self.assertEqual(payload, pyzipcage.read_zip_entry(archive, "ok.txt"))

    def test_read_returns_deflate_bytes(self):
        payload = bytes(range(128))
        archive = simple_zip(data=payload, method="deflate")
        self.assertEqual(payload, pyzipcage.read_zip_entry(archive, "ok.txt"))

    def test_read_missing_entry_raises_entry_not_found(self):
        self.assertReadError("ERR_ZIPCAGE_ENTRY_NOT_FOUND", simple_zip(), "missing.txt")

    def test_read_empty_entry_name_is_invalid(self):
        self.assertError("ERR_ZIPCAGE_INVALID_INPUT", pyzipcage.read_zip_entry, simple_zip(), "")

    def test_read_nonstring_entry_name_is_invalid(self):
        self.assertError("ERR_ZIPCAGE_INVALID_INPUT", pyzipcage.read_zip_entry, simple_zip(), None)

    def test_read_directory_entry_is_invalid_input(self):
        archive = valid_build([{"name": "dir/"}])
        self.assertError("ERR_ZIPCAGE_INVALID_INPUT", pyzipcage.read_zip_entry, archive, "dir")

    def test_read_symlink_is_refused_even_when_inspection_policy_allows_it(self):
        archive = build([
            {"name": "link", "data": b"target", "unix_mode": 0o120777, "external_attributes": (0o120777 << 16)}
        ])
        policy = ZipPolicy(allow_symlinks=True)
        report = pyzipcage.inspect_zip_bytes(archive, policy)
        self.assertTrue(report.safe)
        self.assertError("ERR_ZIPCAGE_EXTRACTION_REFUSED", pyzipcage.read_zip_entry, archive, "link", policy)

    def test_read_detects_crc_mismatch(self):
        payload = b"abc"
        archive = build([
            {"name": "ok.txt", "data": payload, "central_crc32": crc32(payload) + 1, "local_crc32": crc32(payload) + 1}
        ])
        self.assertReadError("ERR_ZIPCAGE_CRC_MISMATCH", archive)

    def test_read_detects_stored_crc_mismatch(self):
        archive = build([{"name": "ok.txt", "data": b"abc", "crc32": 0}])
        self.assertReadError("ERR_ZIPCAGE_CRC_MISMATCH", archive)

    def test_read_detects_deflate_size_mismatch(self):
        payload = b"abcdef"
        archive = build([
            {
                "name": "ok.txt",
                "data": payload,
                "method": "deflate",
                "central_uncompressed_size": len(payload) + 1,
                "local_uncompressed_size": len(payload) + 1,
            }
        ])
        self.assertReadError("ERR_ZIPCAGE_SIZE_MISMATCH", archive)

    def test_read_detects_stored_size_mismatch(self):
        archive = build([
            {
                "name": "ok.txt",
                "data": b"abcdef",
                "central_uncompressed_size": 3,
                "local_uncompressed_size": 3,
            }
        ])
        self.assertReadError("ERR_ZIPCAGE_SIZE_MISMATCH", archive)

    def test_read_rejects_trailing_bytes_inside_compressed_range(self):
        payload = b"abc"
        compressed = deflate_raw(payload) + b"X"
        archive = build([
            {"name": "ok.txt", "data": payload, "method": "deflate", "compressed_data": compressed}
        ])
        self.assertReadError("ERR_ZIPCAGE_TRAILING_COMPRESSED_DATA", archive)

    def test_read_rejects_malformed_deflate_stream(self):
        archive = build([
            {"name": "ok.txt", "data": b"abc", "method": "deflate", "compressed_data": b"bad"}
        ])
        self.assertReadError("ERR_ZIPCAGE_DEFLATE_ERROR", archive)

    def test_deceptive_deflate_output_is_capped_at_declared_size(self):
        payload = bytes(range(100))
        archive = build([
            {
                "name": "ok.txt",
                "data": payload,
                "method": "deflate",
                "central_uncompressed_size": 9,
                "local_uncompressed_size": 9,
            }
        ])
        self.assertReadError("ERR_ZIPCAGE_SIZE_LIMIT", archive)

    def test_exact_declared_deflate_size_is_accepted(self):
        payload = bytes(range(100))
        archive = build([
            {
                "name": "ok.txt",
                "data": payload,
                "method": "deflate",
                "central_uncompressed_size": len(payload),
                "local_uncompressed_size": len(payload),
            }
        ])
        self.assertEqual(payload, pyzipcage.read_zip_entry(archive, "ok.txt"))

    def test_unsupported_method_is_an_inspection_finding(self):
        archive = build([{"name": "ok.txt", "data": b"x", "central_method": 99, "local_method": 99}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_UNSUPPORTED_METHOD")

    def test_encrypted_entry_is_rejected_by_default(self):
        archive = build([{"name": "ok.txt", "data": b"x", "flags": 0x0801}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_ENCRYPTED")

    def test_encrypted_entry_can_be_inspected_but_not_read_when_allowed(self):
        archive = build([{"name": "ok.txt", "data": b"x", "flags": 0x0801}])
        policy = ZipPolicy(allow_encrypted=True)
        report = pyzipcage.inspect_zip_bytes(archive, policy)
        self.assertTrue(report.safe)
        self.assertError("ERR_ZIPCAGE_ENCRYPTED", pyzipcage.read_zip_entry, archive, "ok.txt", policy)

    def test_policy_rejects_zero_max_entries(self):
        with self.assertRaises(ZipCageError):
            ZipPolicy(max_entries=0)

    def test_policy_rejects_boolean_limit(self):
        with self.assertRaises(ZipCageError):
            ZipPolicy(max_entry_bytes=True)

    def test_policy_rejects_low_ratio(self):
        with self.assertRaises(ZipCageError):
            ZipPolicy(max_compression_ratio=0.5)

    def test_entry_count_limit_is_enforced(self):
        archive = valid_build([{"name": "a", "data": b""}, {"name": "b", "data": b""}])
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(max_entries=1))
        self.assertHasFinding(report, "ERR_ZIPCAGE_ENTRY_LIMIT")

    def test_archive_size_limit_is_enforced(self):
        archive = simple_zip()
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(max_archive_bytes=len(archive) - 1))
        self.assertHasFinding(report, "ERR_ZIPCAGE_SIZE_LIMIT")

    def test_report_dataclasses_are_frozen(self):
        report = pyzipcage.inspect_zip_bytes(simple_zip())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.safe = False

    def test_findings_and_entries_are_tuples(self):
        report = pyzipcage.inspect_zip_bytes(simple_zip())
        self.assertIsInstance(report.entries, tuple)
        self.assertIsInstance(report.findings, tuple)

    def test_builder_is_deterministic(self):
        entries = [{"name": "same.txt", "data": b"same", "method": "deflate"}]
        self.assertEqual(valid_build(entries), valid_build(entries))

    def test_builder_rejects_unknown_entry_key(self):
        self.assertError("ERR_ZIPCAGE_INVALID_INPUT", pyzipcage.create_zip_bytes, [{"name": "x", "surprise": 1}])

    def test_builder_rejects_unknown_option_key(self):
        self.assertError("ERR_ZIPCAGE_INVALID_INPUT", pyzipcage.create_zip_bytes, [], {"surprise": True})

    def test_builder_rejects_non_mapping_entry(self):
        self.assertError("ERR_ZIPCAGE_INVALID_INPUT", pyzipcage.create_zip_bytes, ["x"])

    def test_guard_reuses_policy(self):
        archive = valid_build([{"name": "a", "data": b""}, {"name": "b", "data": b""}])
        guard = pyzipcage.ZipGuard(ZipPolicy(max_entries=1))
        report = guard.inspect(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_ENTRY_LIMIT")

    def test_guard_read_entry(self):
        archive = simple_zip(data=b"guard")
        guard = pyzipcage.ZipGuard()
        self.assertEqual(b"guard", guard.read_entry(archive, "ok.txt"))

    def test_guard_rejects_invalid_policy(self):
        self.assertError("ERR_ZIPCAGE_INVALID_OPTIONS", pyzipcage.ZipGuard, object())

    def test_read_never_returns_data_when_archive_has_findings(self):
        archive = build([{"name": "../evil", "data": b"x"}])
        error = self.assertReadError("ERR_ZIPCAGE_PATH_TRAVERSAL", archive, "../evil")
        self.assertTrue(error.findings)


class BoundedFileAndMutationTests(ZipCageTestCase):
    def test_inspect_file_applies_archive_cap_before_parsing(self):
        archive = simple_zip()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "in.zip")
            with open(path, "wb") as handle:
                handle.write(archive)
            report = pyzipcage.inspect_zip_file(path, ZipPolicy(max_archive_bytes=len(archive) - 1))
        self.assertEqual(["ERR_ZIPCAGE_SIZE_LIMIT"], [finding.code for finding in report.findings])
        self.assertEqual(len(archive), report.totals.archive_bytes)

    def test_extract_file_applies_archive_cap_before_extraction(self):
        archive = simple_zip()
        with tempfile.TemporaryDirectory() as directory:
            zip_path = os.path.join(directory, "in.zip")
            target = os.path.join(directory, "out")
            os.mkdir(target)
            with open(zip_path, "wb") as handle:
                handle.write(archive)
            self.assertError(
                "ERR_ZIPCAGE_SIZE_LIMIT",
                pyzipcage.extract_zip_file,
                zip_path,
                target,
                ZipPolicy(max_archive_bytes=len(archive) - 1),
            )
            self.assertEqual([], os.listdir(target))

    def test_deterministic_mutations_never_raise_uncaught_exceptions(self):
        import random

        base = valid_build([
            {"name": "a.txt", "data": bytes(range(32)), "method": "deflate"},
            {"name": "dir/"},
        ])
        rng = random.Random(1394)
        for _ in range(1000):
            mutated = bytearray(base)
            choice = rng.randrange(5)
            if choice == 0:
                del mutated[rng.randrange(len(mutated)) :]
            elif choice == 1:
                position = rng.randrange(len(mutated))
                mutated[position] ^= 1 << rng.randrange(8)
            elif choice == 2:
                position = rng.randrange(len(mutated))
                mutated[position] = rng.randrange(256)
            elif choice == 3 and len(mutated) > 2:
                start = rng.randrange(len(mutated) - 1)
                end = rng.randrange(start + 1, len(mutated))
                del mutated[start:end]
            else:
                mutated.extend(bytes([rng.randrange(256) for _ in range(rng.randrange(1, 8))]))
            try:
                pyzipcage.inspect_zip_bytes(bytes(mutated))
            except Exception as exc:  # pragma: no cover - failure message path
                self.fail("mutation raised {}: {}".format(type(exc).__name__, exc))


if __name__ == "__main__":
    unittest.main()
