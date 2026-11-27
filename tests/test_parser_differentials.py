"""Parser differential, malformed header, EOCD, ZIP64, and encoding tests."""

from __future__ import annotations

import struct
import unittest

import pyzipcage
from pyzipcage import ZipPolicy

from _support import (
    ZipCageTestCase,
    build,
    central_offset,
    crc32,
    data_offset,
    deflate_raw,
    eocd_offset,
    first_central,
    first_local,
    p32,
    patch_u16,
    patch_u32,
    simple_zip,
    u16,
    u32,
    unicode_path_extra,
    valid_build,
)


def forged_eocd(entries=0, central_size=0, central_offset=0, comment=b""):
    return struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        entries,
        entries,
        central_size,
        central_offset,
        len(comment),
    ) + comment


class HeaderMismatchTests(ZipCageTestCase):
    def test_local_filename_mismatch_is_rejected(self):
        archive = build([{"name": "central.txt", "local_name_bytes": b"local.txt", "data": b"x"}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_local_method_mismatch_is_rejected(self):
        archive = build([{"name": "ok.txt", "data": b"x", "central_method": 0, "local_method": 8}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_local_flags_mismatch_is_rejected(self):
        archive = build([{"name": "ok.txt", "data": b"x", "central_flags": 0x0800, "local_flags": 0}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_local_crc_mismatch_is_rejected(self):
        archive = build([{"name": "ok.txt", "data": b"x", "local_crc32": crc32(b"x") + 1}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_local_compressed_size_mismatch_is_rejected(self):
        archive = build([{"name": "ok.txt", "data": b"x", "local_compressed_size": 2}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_local_uncompressed_size_mismatch_is_rejected(self):
        archive = build([{"name": "ok.txt", "data": b"x", "local_uncompressed_size": 2}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_local_version_needed_mismatch_is_rejected(self):
        archive = simple_zip()
        local = first_local(archive)
        report = pyzipcage.inspect_zip_bytes(patch_u16(archive, local + 4, u16(archive, local + 4) + 1))
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_nonzero_local_crc_conflicts_under_data_descriptor(self):
        archive = build([
            {"name": "ok.txt", "data": b"x", "method": "deflate", "data_descriptor": True, "local_crc32": 1}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_nonzero_local_compressed_size_conflicts_under_data_descriptor(self):
        archive = build([
            {"name": "ok.txt", "data": b"x", "method": "deflate", "data_descriptor": True, "local_compressed_size": 1}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_nonzero_local_uncompressed_size_conflicts_under_data_descriptor(self):
        archive = build([
            {"name": "ok.txt", "data": b"x", "method": "deflate", "data_descriptor": True, "local_uncompressed_size": 2}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_signed_descriptor_crc_mismatch_is_rejected(self):
        archive = build([{"name": "ok.txt", "data": b"x", "method": "deflate", "data_descriptor": True}])
        start = data_offset(archive) + u32(archive, first_central(archive) + 20)
        mutated = patch_u32(archive, start + 4, crc32(b"x") + 1)
        report = pyzipcage.inspect_zip_bytes(mutated)
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_unsigned_descriptor_size_mismatch_is_rejected(self):
        archive = build([
            {"name": "ok.txt", "data": b"x", "method": "deflate", "data_descriptor": True, "signed_descriptor": False}
        ])
        start = data_offset(archive) + u32(archive, first_central(archive) + 20)
        mutated = patch_u32(archive, start + 4, u32(archive, start + 4) + 1)
        report = pyzipcage.inspect_zip_bytes(mutated)
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_missing_local_signature_is_header_mismatch(self):
        archive = simple_zip()
        report = pyzipcage.inspect_zip_bytes(patch_u32(archive, first_local(archive), 0))
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_missing_central_signature_is_malformed(self):
        archive = simple_zip()
        report = pyzipcage.inspect_zip_bytes(patch_u32(archive, first_central(archive), 0))
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_wrong_local_header_offset_is_rejected(self):
        archive = simple_zip()
        central = first_central(archive)
        report = pyzipcage.inspect_zip_bytes(patch_u32(archive, central + 42, first_local(archive) + 1))
        self.assertHasFinding(report, "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_compressed_data_reaching_central_directory_is_truncated(self):
        archive = build([
            {"name": "ok.txt", "data": b"x", "central_compressed_size": 100, "local_compressed_size": 100}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_TRUNCATED")


class UnicodePathDifferentialTests(ZipCageTestCase):
    def test_central_unicode_path_mismatch_is_rejected(self):
        archive = build([
            {"name": "safe.txt", "data": b"x", "central_extra": unicode_path_extra(b"safe.txt", "../evil.txt")}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_UNICODE_PATH_MISMATCH")

    def test_local_unicode_path_mismatch_is_rejected(self):
        archive = build([
            {"name": "safe.txt", "data": b"x", "local_extra": unicode_path_extra(b"safe.txt", "../evil.txt")}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_UNICODE_PATH_MISMATCH")

    def test_unicode_path_checksum_mismatch_is_rejected(self):
        archive = build([
            {
                "name": "safe.txt",
                "data": b"x",
                "central_extra": unicode_path_extra(b"safe.txt", "safe.txt", correct_crc=False),
            }
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_UNICODE_PATH_MISMATCH")

    def test_unicode_path_invalid_utf8_is_rejected(self):
        archive = build([
            {"name": "safe.txt", "data": b"x", "central_extra": unicode_path_extra(b"safe.txt", b"\xff")}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_INVALID_ENCODING")

    def test_duplicate_central_unicode_path_fields_are_rejected(self):
        field = unicode_path_extra(b"safe.txt", "safe.txt")
        archive = build([{"name": "safe.txt", "data": b"x", "central_extra": field + field}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_duplicate_local_unicode_path_fields_are_rejected(self):
        field = unicode_path_extra(b"safe.txt", "safe.txt")
        archive = build([{"name": "safe.txt", "data": b"x", "local_extra": field + field}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_truncated_unicode_path_field_is_rejected(self):
        field = b"\x75\x70\x02\x00\x01\x00"
        archive = build([{"name": "safe.txt", "data": b"x", "central_extra": field}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_unsupported_unicode_path_version_is_rejected(self):
        archive = build([
            {"name": "safe.txt", "data": b"x", "central_extra": unicode_path_extra(b"safe.txt", "safe.txt", version=2)}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_malformed_central_extra_is_rejected(self):
        archive = build([{"name": "safe.txt", "data": b"x", "central_extra": b"\x01\x00"}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_malformed_local_extra_is_rejected(self):
        archive = build([{"name": "safe.txt", "data": b"x", "local_extra": b"\x01\x00"}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_consistent_local_unicode_path_is_accepted(self):
        archive = valid_build([
            {"name": "safe.txt", "data": b"x", "local_extra": unicode_path_extra(b"safe.txt", "safe.txt")}
        ])
        self.assertTrue(pyzipcage.inspect_zip_bytes(archive).safe)


class EocdAndPolyglotTests(ZipCageTestCase):
    def test_too_short_input_is_truncated(self):
        report = pyzipcage.inspect_zip_bytes(b"tiny")
        self.assertHasFinding(report, "ERR_ZIPCAGE_TRUNCATED")

    def test_missing_eocd_is_malformed(self):
        report = pyzipcage.inspect_zip_bytes(b"x" * 100)
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_trailing_bytes_are_polyglot_by_default(self):
        archive = build([{"name": "ok.txt", "data": b"x"}], trailing_bytes=b"trailing")
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_POLYGLOT")

    def test_trailing_bytes_can_be_explicitly_tolerated(self):
        archive = build([{"name": "ok.txt", "data": b"x"}], trailing_bytes=b"trailing")
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(reject_polyglot=False))
        self.assertTrue(report.safe, [finding.to_dict() for finding in report.findings])

    def test_prepended_bytes_are_polyglot_by_default(self):
        archive = build([{"name": "ok.txt", "data": b"x"}], prepend_bytes=b"prefix")
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_POLYGLOT")

    def test_prepended_bytes_can_be_explicitly_tolerated(self):
        archive = build([{"name": "ok.txt", "data": b"x"}], prepend_bytes=b"prefix")
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(reject_polyglot=False))
        self.assertTrue(report.safe, [finding.to_dict() for finding in report.findings])

    def test_exact_forged_eocd_inside_comment_is_ambiguous_strict(self):
        forged = forged_eocd()
        archive = build([{"name": "ok.txt", "data": b"x"}], comment=b"padding" + forged)
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_exact_forged_eocd_inside_comment_is_ambiguous_relaxed(self):
        forged = forged_eocd()
        archive = build([{"name": "ok.txt", "data": b"x"}], comment=b"padding" + forged)
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(reject_polyglot=False))
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_exact_forged_eocd_in_trailing_bytes_is_ambiguous_relaxed(self):
        forged = forged_eocd()
        archive = simple_zip() + forged
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(reject_polyglot=False))
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_incomplete_eocd_like_comment_bytes_are_safe_strict(self):
        archive = valid_build([{"name": "ok.txt", "data": b"x"}], comment=b"xxPK\x05\x06")
        self.assertTrue(pyzipcage.inspect_zip_bytes(archive).safe)

    def test_incomplete_eocd_like_comment_bytes_are_safe_relaxed(self):
        archive = valid_build([{"name": "ok.txt", "data": b"x"}], comment=b"xxPK\x05\x06")
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(reject_polyglot=False))
        self.assertTrue(report.safe)

    def test_eocd_inside_stored_data_is_safe_strict(self):
        archive = valid_build([{"name": "ok.txt", "data": forged_eocd()}])
        self.assertTrue(pyzipcage.inspect_zip_bytes(archive).safe)

    def test_eocd_inside_stored_data_is_ambiguous_relaxed(self):
        archive = valid_build([{"name": "ok.txt", "data": forged_eocd()}])
        report = pyzipcage.inspect_zip_bytes(archive, ZipPolicy(reject_polyglot=False))
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_central_directory_size_mismatch_is_rejected(self):
        archive = simple_zip()
        eocd = eocd_offset(archive)
        report = pyzipcage.inspect_zip_bytes(patch_u32(archive, eocd + 12, u32(archive, eocd + 12) - 1))
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_central_directory_extending_past_eocd_is_truncated(self):
        archive = simple_zip()
        eocd = eocd_offset(archive)
        report = pyzipcage.inspect_zip_bytes(patch_u32(archive, eocd + 12, 1000))
        self.assertHasFinding(report, "ERR_ZIPCAGE_TRUNCATED")

    def test_entry_count_larger_than_central_directory_is_rejected(self):
        archive = simple_zip()
        eocd = eocd_offset(archive)
        mutated = patch_u16(archive, eocd + 8, 2)
        mutated = patch_u16(mutated, eocd + 10, 2)
        report = pyzipcage.inspect_zip_bytes(mutated)
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")

    def test_zero_entry_count_with_nonempty_central_directory_is_rejected(self):
        archive = simple_zip()
        eocd = eocd_offset(archive)
        mutated = patch_u16(archive, eocd + 8, 0)
        mutated = patch_u16(mutated, eocd + 10, 0)
        report = pyzipcage.inspect_zip_bytes(mutated)
        self.assertHasFinding(report, "ERR_ZIPCAGE_MALFORMED_ZIP")


class Zip64AndDiskTests(ZipCageTestCase):
    def test_compressed_size_zip64_sentinel_is_rejected(self):
        archive = build([
            {"name": "ok.txt", "data": b"x", "central_compressed_size": 0xFFFFFFFF, "local_compressed_size": 0xFFFFFFFF}
        ])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_UNSUPPORTED_ZIP64")

    def test_uncompressed_size_zip64_sentinel_is_rejected(self):
        archive = build([
            {"name": "ok.txt", "data": b"x", "central_uncompressed_size": 0xFFFFFFFF, "local_uncompressed_size": 0xFFFFFFFF}
        ])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_UNSUPPORTED_ZIP64")

    def test_local_offset_zip64_sentinel_is_rejected(self):
        archive = build([{"name": "ok.txt", "data": b"x", "central_local_header_offset": 0xFFFFFFFF}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_UNSUPPORTED_ZIP64")

    def test_eocd_count_zip64_sentinel_is_rejected(self):
        archive = simple_zip()
        eocd = eocd_offset(archive)
        mutated = patch_u16(archive, eocd + 8, 0xFFFF)
        mutated = patch_u16(mutated, eocd + 10, 0xFFFF)
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(mutated), "ERR_ZIPCAGE_UNSUPPORTED_ZIP64")

    def test_eocd_central_size_zip64_sentinel_is_rejected(self):
        archive = simple_zip()
        eocd = eocd_offset(archive)
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(patch_u32(archive, eocd + 12, 0xFFFFFFFF)), "ERR_ZIPCAGE_UNSUPPORTED_ZIP64")

    def test_eocd_central_offset_zip64_sentinel_is_rejected(self):
        archive = simple_zip()
        eocd = eocd_offset(archive)
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(patch_u32(archive, eocd + 16, 0xFFFFFFFF)), "ERR_ZIPCAGE_UNSUPPORTED_ZIP64")

    def test_central_zip64_extra_is_rejected(self):
        archive = build([{"name": "ok.txt", "data": b"x", "central_extra": b"\x01\x00\x00\x00"}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_UNSUPPORTED_ZIP64")

    def test_local_zip64_extra_is_rejected(self):
        archive = build([{"name": "ok.txt", "data": b"x", "local_extra": b"\x01\x00\x00\x00"}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_UNSUPPORTED_ZIP64")

    def test_nonzero_eocd_disk_number_is_rejected(self):
        archive = simple_zip()
        eocd = eocd_offset(archive)
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(patch_u16(archive, eocd + 4, 1)), "ERR_ZIPCAGE_MULTI_DISK")

    def test_nonzero_central_directory_disk_is_rejected(self):
        archive = simple_zip()
        eocd = eocd_offset(archive)
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(patch_u16(archive, eocd + 6, 1)), "ERR_ZIPCAGE_MULTI_DISK")

    def test_entries_on_disk_count_mismatch_is_rejected(self):
        archive = simple_zip()
        eocd = eocd_offset(archive)
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(patch_u16(archive, eocd + 8, 0)), "ERR_ZIPCAGE_MULTI_DISK")

    def test_nonzero_entry_start_disk_is_rejected(self):
        archive = simple_zip()
        central = first_central(archive)
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(patch_u16(archive, central + 34, 1)), "ERR_ZIPCAGE_MULTI_DISK")


class FlagAndEncodingTests(ZipCageTestCase):
    pass


for bit in (0x0010, 0x0020, 0x0040, 0x0080, 0x0100, 0x0200, 0x0400, 0x1000, 0x2000, 0x4000, 0x8000):
    def unsupported_bit_test(bit):
        def test(self):
            archive = build([{"name": "ok.txt", "data": b"x", "flags": 0x0800 | bit}])
            self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_UNSUPPORTED_FLAGS")

        return test

    setattr(FlagAndEncodingTests, "test_unsupported_flag_bit_%04x" % bit, unsupported_bit_test(bit))


class FlagAndEncodingMoreTests(ZipCageTestCase):
    def test_stored_compression_option_bit_one_is_rejected(self):
        archive = build([{"name": "ok.txt", "data": b"x", "flags": 0x0802}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_UNSUPPORTED_FLAGS")

    def test_stored_compression_option_bit_two_is_rejected(self):
        archive = build([{"name": "ok.txt", "data": b"x", "flags": 0x0804}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_UNSUPPORTED_FLAGS")

    def test_deflate_compression_option_bit_one_is_accepted(self):
        archive = valid_build([{"name": "ok.txt", "data": b"x", "method": "deflate", "flags": 0x0802}])
        self.assertTrue(pyzipcage.inspect_zip_bytes(archive).safe)

    def test_deflate_compression_option_bit_two_is_accepted(self):
        archive = valid_build([{"name": "ok.txt", "data": b"x", "method": "deflate", "flags": 0x0804}])
        self.assertTrue(pyzipcage.inspect_zip_bytes(archive).safe)

    def test_invalid_utf8_filename_is_rejected(self):
        archive = build([{"name": "x", "name_bytes": b"\xff", "utf8": True, "data": b"x"}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_INVALID_ENCODING")

    def test_invalid_utf8_report_uses_replacement_name_safely(self):
        archive = build([{"name": "x", "name_bytes": b"\xff", "utf8": True, "data": b"x"}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.entries[0].invalid_encoding)
        self.assertIn("\ufffd", report.entries[0].name)

    def test_method_nine_is_unsupported(self):
        archive = build([{"name": "ok.txt", "data": b"x", "central_method": 9, "local_method": 9}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_UNSUPPORTED_METHOD")

    def test_method_twelve_is_unsupported(self):
        archive = build([{"name": "ok.txt", "data": b"x", "central_method": 12, "local_method": 12}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_UNSUPPORTED_METHOD")

    def test_method_ninety_nine_is_unsupported(self):
        archive = build([{"name": "ok.txt", "data": b"x", "central_method": 99, "local_method": 99}])
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive), "ERR_ZIPCAGE_UNSUPPORTED_METHOD")


class AdditionalParserRegressionTests(ZipCageTestCase):
    def test_matching_nonzero_local_sizes_are_accepted_with_data_descriptor(self):
        payload = b"abc"
        compressed = deflate_raw(payload)
        archive = valid_build([
            {
                "name": "x",
                "data": payload,
                "method": "deflate",
                "data_descriptor": True,
                "local_crc32": crc32(payload),
                "local_compressed_size": len(compressed),
                "local_uncompressed_size": len(payload),
            }
        ])
        self.assertTrue(pyzipcage.inspect_zip_bytes(archive).safe)

    def test_corrupt_signed_descriptor_compressed_size_is_rejected(self):
        archive = build([{"name": "x", "data": b"abc", "method": "deflate", "data_descriptor": True}])
        start = data_offset(archive) + u32(archive, first_central(archive) + 20)
        mutated = patch_u32(archive, start + 8, u32(archive, start + 8) + 1)
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(mutated), "ERR_ZIPCAGE_HEADER_MISMATCH")

    def test_central_offset_beyond_eocd_is_truncated(self):
        archive = simple_zip()
        eocd = eocd_offset(archive)
        mutated = patch_u32(archive, eocd + 16, eocd + 1)
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(mutated), "ERR_ZIPCAGE_TRUNCATED")

    def test_zip64_uncompressed_sentinel_is_rejected_with_permissive_limits(self):
        archive = build([
            {"name": "ok.txt", "data": b"x", "central_uncompressed_size": 0xFFFFFFFF, "local_uncompressed_size": 0xFFFFFFFF}
        ])
        policy = ZipPolicy(max_entry_bytes=0xFFFFFFFF, max_total_bytes=0xFFFFFFFF, max_compression_ratio=1000000)
        self.assertHasFinding(pyzipcage.inspect_zip_bytes(archive, policy), "ERR_ZIPCAGE_UNSUPPORTED_ZIP64")


if __name__ == "__main__":
    unittest.main()
