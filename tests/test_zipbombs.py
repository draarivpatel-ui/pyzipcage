"""CWE-409 zip-bomb, overlap, size, ratio, and duplicate collision tests."""

from __future__ import annotations

import unittest

import pyzipcage
from pyzipcage import ZipPolicy

from _support import (
    ZipCageTestCase,
    build,
    central_offset,
    crc32,
    deflate_raw,
    eocd_offset,
    first_central,
    first_local,
    patch_u32,
    simple_zip,
    u16,
    u32,
    valid_build,
)


def archive_with_local_gap():
    original = build([{"name": "a", "data": b"x"}, {"name": "b", "data": b"y"}])
    first_len = 30 + 1 + 1
    gap_at = first_len
    padding = b"GAP"
    mutated = bytearray(original[:gap_at] + padding + original[gap_at:])
    eocd = eocd_offset(original)
    shifted_eocd = eocd + len(padding)
    original_central = central_offset(original)
    shifted_central = original_central + len(padding)
    # The second central header starts after one fixed header plus the one byte name.
    second_central = shifted_central + 46 + 1
    second_local = u32(mutated, second_central + 42) + len(padding)
    mutated = bytearray(patch_u32(bytes(mutated), second_central + 42, second_local))
    mutated = bytearray(patch_u32(bytes(mutated), shifted_eocd + 16, shifted_central))
    return bytes(mutated)


class SizeAndRatioLimitTests(ZipCageTestCase):
    def test_entry_size_exact_limit_is_accepted(self):
        archive = valid_build([{"name": "ok.txt", "data": b"0123456789"}])
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(max_entry_bytes=10))
        self.assertTrue(report.safe)

    def test_entry_size_over_limit_is_rejected(self):
        archive = valid_build([{"name": "ok.txt", "data": b"0123456789"}])
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(max_entry_bytes=9))
        self.assertHasFinding(report, "ERR_ZIPCAGE_SIZE_LIMIT")

    def test_total_size_exact_limit_is_accepted(self):
        archive = valid_build([{"name": "a", "data": b"12345"}, {"name": "b", "data": b"67890"}])
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(max_total_bytes=10))
        self.assertTrue(report.safe)

    def test_total_size_over_limit_is_rejected(self):
        archive = valid_build([{"name": "a", "data": b"12345"}, {"name": "b", "data": b"67890"}])
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(max_total_bytes=9))
        self.assertHasFinding(report, "ERR_ZIPCAGE_SIZE_LIMIT")

    def test_entry_ratio_exact_limit_is_accepted(self):
        archive = build([
            {"name": "ok.txt", "data": b"x" * 200, "method": "deflate", "compressed_data": b"xx"}
        ])
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(max_compression_ratio=100))
        self.assertTrue(report.safe, [finding.to_dict() for finding in report.findings])

    def test_entry_ratio_over_limit_is_rejected(self):
        archive = build([
            {"name": "ok.txt", "data": b"x" * 202, "method": "deflate", "compressed_data": b"xx"}
        ])
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(max_compression_ratio=100))
        self.assertHasFinding(report, "ERR_ZIPCAGE_RATIO_LIMIT")

    def test_real_highly_compressed_entry_is_rejected(self):
        archive = build([{"name": "bomb", "data": b"A" * 10000, "method": "deflate"}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_RATIO_LIMIT")

    def test_zero_compressed_bytes_with_nonzero_output_is_rejected(self):
        archive = build([
            {"name": "ok.txt", "data": b"x", "method": "deflate", "compressed_data": b""}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_RATIO_LIMIT")

    def test_zero_compressed_zero_output_is_accepted(self):
        archive = build([
            {"name": "ok.txt", "data": b"", "method": "deflate", "compressed_data": b""}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)

    def test_ratio_policy_can_be_raised_explicitly(self):
        archive = build([{"name": "bomb", "data": b"A" * 10000, "method": "deflate"}])
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(max_compression_ratio=1000))
        self.assertTrue(report.safe)

    def test_archive_size_exact_limit_is_accepted(self):
        archive = simple_zip()
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(max_archive_bytes=len(archive)))
        self.assertTrue(report.safe)

    def test_entry_limit_allows_first_entry_but_reports_archive_unsafe(self):
        archive = valid_build([{"name": "a", "data": b""}, {"name": "b", "data": b""}])
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(max_entries=1))
        self.assertHasFinding(report, "ERR_ZIPCAGE_ENTRY_LIMIT")
        self.assertEqual(1, len(report.entries))

    def test_compression_ratio_totals_are_reported(self):
        archive = valid_build([{"name": "ok.txt", "data": bytes(range(100)), "method": "deflate"}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertGreater(report.totals.maximum_entry_compression_ratio, 0)
        self.assertGreater(report.totals.compression_ratio, 0)


class OverlapAndLayoutTests(ZipCageTestCase):
    def test_positive_compressed_range_overlap_is_rejected(self):
        archive = build([
            {"name": "a", "data": b"payload"},
            {"name": "b", "data": b"z", "write_local": False, "central_local_header_offset": 0},
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_OVERLAPPING_DATA")

    def test_aliased_empty_compressed_ranges_are_rejected(self):
        archive = build([
            {"name": "a", "data": b""},
            {"name": "b", "data": b"", "write_local": False, "central_local_header_offset": 0},
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_OVERLAPPING_DATA")

    def test_empty_range_inside_positive_compressed_range_is_rejected(self):
        archive = build([{"name": "a", "data": b"x"}, {"name": "b", "data": b""}])
        central = first_central(archive)
        mutated = patch_u32(archive, 18, 33)
        mutated = patch_u32(mutated, 22, 33)
        mutated = patch_u32(mutated, central + 20, 33)
        mutated = patch_u32(mutated, central + 24, 33)
        report = pyzipcage.inspect_zip_bytes(mutated)
        self.assertHasFinding(report, "ERR_ZIPCAGE_OVERLAPPING_DATA")

    def test_distinct_empty_entries_do_not_alias(self):
        archive = valid_build([{"name": "a", "data": b""}, {"name": "b", "data": b""}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)

    def test_unaccounted_gap_between_local_records_is_polyglot(self):
        report = pyzipcage.inspect_zip_bytes(archive_with_local_gap())
        self.assertHasFinding(report, "ERR_ZIPCAGE_POLYGLOT")

    def test_unaccounted_gap_between_local_records_can_be_tolerated(self):
        report = pyzipcage.inspect_zip_bytes(archive_with_local_gap(), ZipPolicy(reject_polyglot=False))
        self.assertTrue(report.safe, [finding.to_dict() for finding in report.findings])

    def test_data_overlapping_next_local_header_is_malformed(self):
        archive = build([
            {"name": "a", "data": b"x", "central_compressed_size": 2, "local_compressed_size": 2},
            {"name": "b", "data": b"y"},
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_directory_with_payload_bytes_is_malformed(self):
        archive = build([{"name": "dir/", "data": b"payload"}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")


class DeflateDeceptionTests(ZipCageTestCase):
    pass


for declared in (0, 1, 2, 9, 10, 50):
    def deceptive_test(declared_size):
        def test(self):
            payload = bytes(range(100))
            archive = build([
                {
                    "name": "ok.txt",
                    "data": payload,
                    "method": "deflate",
                    "central_uncompressed_size": declared_size,
                    "local_uncompressed_size": declared_size,
                }
            ])
            self.assertReadError("ERR_ZIPCAGE_SIZE_LIMIT", archive)

        return test

    setattr(DeflateDeceptionTests, "test_deceptive_declared_size_%03d" % declared, deceptive_test(declared))


for cut in (1, 2, 3):
    def truncated_deflate_test(cut_length):
        def test(self):
            payload = b"abcdef"
            compressed = deflate_raw(payload)[:cut_length]
            archive = build([
                {"name": "ok.txt", "data": payload, "method": "deflate", "compressed_data": compressed}
            ])
            self.assertReadError("ERR_ZIPCAGE_DEFLATE_ERROR", archive)

        return test

    setattr(DeflateDeceptionTests, "test_truncated_deflate_%d" % cut, truncated_deflate_test(cut))


for extra in (1, 2, 10):
    def trailing_test(extra_count):
        def test(self):
            payload = b"abcdef"
            compressed = deflate_raw(payload) + (b"X" * extra_count)
            archive = build([
                {"name": "ok.txt", "data": payload, "method": "deflate", "compressed_data": compressed}
            ])
            self.assertReadError("ERR_ZIPCAGE_TRAILING_COMPRESSED_DATA", archive)

        return test

    setattr(DeflateDeceptionTests, "test_trailing_deflate_bytes_%d" % extra, trailing_test(extra))


class IntegrityMismatchTests(ZipCageTestCase):
    pass


for delta in (1, 2, 255, 65536):
    def crc_delta_test(delta_value):
        def test(self):
            payload = b"abcdef"
            bad = (crc32(payload) + delta_value) & 0xFFFFFFFF
            archive = build([
                {"name": "ok.txt", "data": payload, "method": "deflate", "central_crc32": bad, "local_crc32": bad}
            ])
            self.assertReadError("ERR_ZIPCAGE_CRC_MISMATCH", archive)

        return test

    setattr(IntegrityMismatchTests, "test_crc_delta_%d" % delta, crc_delta_test(delta))


for delta in (-2, -1, 1, 2, 100):
    def size_delta_test(delta_value):
        def test(self):
            payload = b"abcdef"
            wrong = len(payload) + delta_value
            archive = build([
                {
                    "name": "ok.txt",
                    "data": payload,
                    "method": "deflate",
                    "central_uncompressed_size": wrong,
                    "local_uncompressed_size": wrong,
                }
            ])
            expected = "ERR_ZIPCAGE_SIZE_LIMIT" if wrong < len(payload) else "ERR_ZIPCAGE_SIZE_MISMATCH"
            self.assertReadError(expected, archive)

        return test

    if delta >= -len("abcdef"):
        setattr(IntegrityMismatchTests, "test_size_delta_%s" % str(delta).replace("-", "minus"), size_delta_test(delta))


class DuplicateAndCollisionTests(ZipCageTestCase):
    def test_exact_duplicate_file_path_is_rejected(self):
        archive = build([{"name": "same", "data": b"1"}, {"name": "same", "data": b"2"}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_DUPLICATE_PATH")

    def test_case_variant_duplicate_is_rejected_by_default(self):
        archive = build([{"name": "Same.txt", "data": b"1"}, {"name": "same.txt", "data": b"2"}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_DUPLICATE_PATH")

    def test_case_variant_duplicate_can_be_allowed_explicitly(self):
        archive = build([{"name": "Same.txt", "data": b"1"}, {"name": "same.txt", "data": b"2"}])
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(case_insensitive_duplicates=False))
        self.assertTrue(report.safe)

    def test_unicode_normalization_duplicate_is_rejected(self):
        composed = "caf\u00e9.txt"
        decomposed = "caf\u0065\u0301.txt"
        archive = build([{"name": composed, "data": b"1"}, {"name": decomposed, "data": b"2"}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_DUPLICATE_PATH")

    def test_file_and_directory_same_path_collision_is_rejected(self):
        archive = build([{"name": "a", "data": b"x"}, {"name": "a/", "data": b""}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_FILE_DIRECTORY_COLLISION")

    def test_file_ancestor_collision_is_rejected(self):
        archive = build([{"name": "a", "data": b"x"}, {"name": "a/b", "data": b"y"}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_FILE_DIRECTORY_COLLISION")

    def test_explicit_directory_then_nested_file_is_safe(self):
        archive = valid_build([{"name": "a/"}, {"name": "a/b", "data": b"y"}])
        self.assertTrue(pyzipcage.inspect_zip_bytes(archive).safe)

    def test_reverse_ordered_directory_and_nested_file_is_safe(self):
        archive = valid_build([{"name": "a/b", "data": b"y"}, {"name": "a/"}])
        self.assertTrue(pyzipcage.inspect_zip_bytes(archive).safe)

    def test_sibling_directories_are_safe(self):
        archive = valid_build([{"name": "a/x", "data": b"1"}, {"name": "b/x", "data": b"2"}])
        self.assertTrue(pyzipcage.inspect_zip_bytes(archive).safe)

    def test_case_variant_file_directory_collision_is_rejected(self):
        archive = build([{"name": "A", "data": b"x"}, {"name": "a/", "data": b""}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_FILE_DIRECTORY_COLLISION")


if __name__ == "__main__":
    unittest.main()
