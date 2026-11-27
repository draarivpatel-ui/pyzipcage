"""Unix file type and permission attribute tests."""

from __future__ import annotations

import unittest

import pyzipcage
from pyzipcage import ZipPolicy

from _support import ZipCageTestCase, build, valid_build


def special_archive(file_type, permissions=0o644, version_made_by=None):
    unix_mode = file_type | permissions
    entry = {
        "name": "entry",
        "data": b"x",
        "unix_mode": unix_mode,
        "external_attributes": (unix_mode & 0xFFFF) << 16,
    }
    if version_made_by is not None:
        entry["version_made_by"] = version_made_by
    return build([entry])


class UnixSpecialFileTests(ZipCageTestCase):
    pass


for label, file_type in (
    ("fifo", 0o010000),
    ("socket", 0o140000),
    ("block_device", 0o060000),
    ("character_device", 0o020000),
    ("unknown_type", 0o030000),
):
    def special_reject_test(kind):
        def test(self):
            report = pyzipcage.inspect_zip_bytes(special_archive(kind))
            self.assertHasFinding(report, "ERR_ZIPCAGE_SPECIAL_FILE")

        return test

    setattr(UnixSpecialFileTests, "test_" + label + "_is_rejected", special_reject_test(file_type))

    def special_allow_test(kind):
        def test(self):
            report = pyzipcage.inspect_zip_bytes(special_archive(kind), ZipPolicy(allow_special_files=True))
            self.assertTrue(report.safe, [finding.to_dict() for finding in report.findings])

        return test

    setattr(UnixSpecialFileTests, "test_" + label + "_can_be_inspected_when_allowed", special_allow_test(file_type))


class SymlinkAndPermissionTests(ZipCageTestCase):
    def test_symlink_is_rejected_by_default(self):
        report = pyzipcage.inspect_zip_bytes(special_archive(0o120000, 0o777))
        self.assertHasFinding(report, "ERR_ZIPCAGE_SYMLINK")

    def test_symlink_can_be_inspected_when_allowed(self):
        report = pyzipcage.inspect_zip_bytes(special_archive(0o120000, 0o777), ZipPolicy(allow_symlinks=True))
        self.assertTrue(report.safe)
        self.assertEqual("symlink", report.entries[0].unix_file_type)

    def test_symlink_bits_are_rejected_even_for_non_unix_version_made_by(self):
        report = pyzipcage.inspect_zip_bytes(special_archive(0o120000, 0o777, version_made_by=20))
        self.assertHasFinding(report, "ERR_ZIPCAGE_SYMLINK")

    def test_suid_is_rejected(self):
        report = pyzipcage.inspect_zip_bytes(special_archive(0o100000, 0o4644))
        self.assertHasFinding(report, "ERR_ZIPCAGE_SUID_SGID")

    def test_sgid_is_rejected(self):
        report = pyzipcage.inspect_zip_bytes(special_archive(0o100000, 0o2644))
        self.assertHasFinding(report, "ERR_ZIPCAGE_SUID_SGID")

    def test_suid_and_sgid_are_rejected_together(self):
        report = pyzipcage.inspect_zip_bytes(special_archive(0o100000, 0o6644))
        self.assertHasFinding(report, "ERR_ZIPCAGE_SUID_SGID")

    def test_suid_sgid_can_be_inspected_when_allowed(self):
        report = pyzipcage.inspect_zip_bytes(special_archive(0o100000, 0o6644), ZipPolicy(allow_suid_sgid=True))
        self.assertTrue(report.safe)

    def test_executable_permission_bits_do_not_fail_inspection(self):
        archive = valid_build([{"name": "tool", "data": b"x", "mode": 0o755}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertEqual(0o100755, report.entries[0].unix_mode)

    def test_regular_file_type_is_safe(self):
        report = pyzipcage.inspect_zip_bytes(special_archive(0o100000, 0o644))
        self.assertTrue(report.safe)
        self.assertEqual("file", report.entries[0].unix_file_type)

    def test_unspecified_file_type_is_safe(self):
        report = pyzipcage.inspect_zip_bytes(special_archive(0, 0))
        self.assertTrue(report.safe)
        self.assertEqual("unspecified", report.entries[0].unix_file_type)

    def test_unix_directory_type_is_safe_when_empty(self):
        unix_mode = 0o040755
        archive = build([
            {"name": "dir", "data": b"", "unix_mode": unix_mode, "external_attributes": (unix_mode << 16) | 0x10}
        ])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertTrue(report.safe)
        self.assertTrue(report.entries[0].directory)
        self.assertEqual("directory", report.entries[0].unix_file_type)

    def test_unix_file_type_names_are_exposed(self):
        regular = pyzipcage.inspect_zip_bytes(special_archive(0o100000)).entries[0]
        fifo = pyzipcage.inspect_zip_bytes(special_archive(0o010000), ZipPolicy(allow_special_files=True)).entries[0]
        self.assertEqual("file", regular.unix_file_type)
        self.assertEqual("fifo", fifo.unix_file_type)


if __name__ == "__main__":
    unittest.main()
