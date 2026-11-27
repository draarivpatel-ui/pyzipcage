"""Filesystem extraction confinement, atomicity, and permission tests."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from unittest import mock

import pyzipcage
from pyzipcage import ZipPolicy

from _support import ZipCageTestCase, build, deflate_raw, simple_zip, valid_build


def mode_of(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def temp_names(root):
    output = []
    for current, directories, files in os.walk(root):
        for name in directories + files:
            if name.startswith(".pyzipcage-"):
                output.append(os.path.join(current, name))
    return output


class ExtractionTests(ZipCageTestCase):
    def test_extracts_stored_file_contents(self):
        archive = simple_zip(data=b"payload")
        with tempfile.TemporaryDirectory() as directory:
            result = pyzipcage.extract_zip_bytes(archive, directory)
            with open(os.path.join(directory, "ok.txt"), "rb") as handle:
                self.assertEqual(b"payload", handle.read())
        self.assertEqual(1, result.entries_written)

    def test_extracts_deflate_file_contents(self):
        payload = bytes(range(128))
        archive = simple_zip(data=payload, method="deflate")
        with tempfile.TemporaryDirectory() as directory:
            pyzipcage.extract_zip_bytes(archive, directory)
            with open(os.path.join(directory, "ok.txt"), "rb") as handle:
                self.assertEqual(payload, handle.read())

    def test_extracts_explicit_nested_directories(self):
        archive = valid_build([{"name": "a/"}, {"name": "a/b/"}, {"name": "a/b/c.txt", "data": b"c"}])
        with tempfile.TemporaryDirectory() as directory:
            result = pyzipcage.extract_zip_bytes(archive, directory)
            self.assertTrue(os.path.isdir(os.path.join(directory, "a", "b")))
            self.assertEqual(1, result.entries_written)

    def test_extracts_implicit_parent_directories(self):
        archive = valid_build([{"name": "a/b/c.txt", "data": b"c"}])
        with tempfile.TemporaryDirectory() as directory:
            result = pyzipcage.extract_zip_bytes(archive, directory)
            self.assertTrue(os.path.isdir(os.path.join(directory, "a", "b")))
            self.assertEqual(2, result.directories_created)

    def test_extracts_reverse_ordered_directory_entries(self):
        archive = valid_build([{"name": "a/b/c.txt", "data": b"c"}, {"name": "a/"}, {"name": "a/b/"}])
        with tempfile.TemporaryDirectory() as directory:
            pyzipcage.extract_zip_bytes(archive, directory)
            self.assertTrue(os.path.isfile(os.path.join(directory, "a", "b", "c.txt")))

    def test_extracts_empty_file(self):
        archive = valid_build([{"name": "empty", "data": b""}])
        with tempfile.TemporaryDirectory() as directory:
            pyzipcage.extract_zip_bytes(archive, directory)
            self.assertEqual(0, os.path.getsize(os.path.join(directory, "empty")))

    def test_extraction_report_counts_bytes_and_files(self):
        archive = valid_build([{"name": "a", "data": b"123"}, {"name": "b", "data": b"4567"}])
        with tempfile.TemporaryDirectory() as directory:
            result = pyzipcage.extract_zip_bytes(archive, directory)
            self.assertEqual(2, result.entries_written)
            self.assertEqual(7, result.bytes_written)
            self.assertEqual(("a", "b"), tuple(item.name for item in result.files))

    def test_extraction_report_uses_realpath_target(self):
        archive = simple_zip()
        with tempfile.TemporaryDirectory() as directory:
            result = pyzipcage.extract_zip_bytes(archive, os.path.join(directory, "."))
            self.assertEqual(os.path.realpath(directory), result.target_dir)

    def test_extraction_report_serializes(self):
        archive = simple_zip()
        with tempfile.TemporaryDirectory() as directory:
            result = pyzipcage.extract_zip_bytes(archive, directory)
            output = result.to_dict()
            for key in ("target_dir", "entries_written", "directories_created", "bytes_written", "files", "directories", "report"):
                self.assertIn(key, output)

    def test_files_are_hardened_to_0644(self):
        archive = valid_build([{"name": "exec", "data": b"x", "mode": 0o755}])
        with tempfile.TemporaryDirectory() as directory:
            pyzipcage.extract_zip_bytes(archive, directory)
            self.assertEqual(0o644, mode_of(os.path.join(directory, "exec")))

    def test_directories_are_hardened_to_0755(self):
        archive = valid_build([{"name": "dir/"}])
        with tempfile.TemporaryDirectory() as directory:
            pyzipcage.extract_zip_bytes(archive, directory)
            self.assertEqual(0o755, mode_of(os.path.join(directory, "dir")))

    def test_suid_sgid_and_exec_bits_are_stripped_on_write(self):
        unix_mode = 0o100000 | 0o6755
        archive = build([
            {"name": "badbits", "data": b"x", "unix_mode": unix_mode, "external_attributes": unix_mode << 16}
        ])
        policy = ZipPolicy(allow_suid_sgid=True)
        with tempfile.TemporaryDirectory() as directory:
            pyzipcage.extract_zip_bytes(archive, directory, policy)
            self.assertEqual(0o644, mode_of(os.path.join(directory, "badbits")))

    def test_existing_regular_file_is_not_overwritten_by_default(self):
        archive = simple_zip()
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "ok.txt")
            with open(target, "wb") as handle:
                handle.write(b"original")
            self.assertError("ERR_ZIPCAGE_EXTRACTION_OVERWRITE", pyzipcage.extract_zip_bytes, archive, directory)
            with open(target, "rb") as handle:
                self.assertEqual(b"original", handle.read())

    def test_existing_regular_file_is_replaced_with_explicit_overwrite(self):
        archive = simple_zip(data=b"new")
        policy = ZipPolicy(overwrite=True)
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "ok.txt")
            with open(target, "wb") as handle:
                handle.write(b"original")
            pyzipcage.extract_zip_bytes(archive, directory, policy)
            with open(target, "rb") as handle:
                self.assertEqual(b"new", handle.read())

    def test_existing_destination_symlink_is_refused_without_overwrite(self):
        archive = simple_zip()
        with tempfile.TemporaryDirectory() as directory:
            outside = os.path.join(directory, "outside")
            with open(outside, "wb") as handle:
                handle.write(b"outside")
            os.symlink(outside, os.path.join(directory, "ok.txt"))
            self.assertError("ERR_ZIPCAGE_EXTRACTION_SYMLINK", pyzipcage.extract_zip_bytes, archive, directory)
            with open(outside, "rb") as handle:
                self.assertEqual(b"outside", handle.read())

    def test_existing_destination_symlink_is_refused_with_overwrite(self):
        archive = simple_zip()
        policy = ZipPolicy(overwrite=True)
        with tempfile.TemporaryDirectory() as directory:
            outside = os.path.join(directory, "outside")
            with open(outside, "wb") as handle:
                handle.write(b"outside")
            os.symlink(outside, os.path.join(directory, "ok.txt"))
            self.assertError("ERR_ZIPCAGE_EXTRACTION_SYMLINK", pyzipcage.extract_zip_bytes, archive, directory, policy)

    def test_existing_directory_at_file_path_is_collision(self):
        archive = simple_zip()
        with tempfile.TemporaryDirectory() as directory:
            os.mkdir(os.path.join(directory, "ok.txt"))
            self.assertError("ERR_ZIPCAGE_EXTRACTION_COLLISION", pyzipcage.extract_zip_bytes, archive, directory)

    def test_file_blocking_required_parent_is_collision(self):
        archive = valid_build([{"name": "a/b.txt", "data": b"x"}])
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "a"), "wb") as handle:
                handle.write(b"file")
            self.assertError("ERR_ZIPCAGE_EXTRACTION_COLLISION", pyzipcage.extract_zip_bytes, archive, directory)

    def test_symlink_parent_is_not_traversed(self):
        archive = valid_build([{"name": "a/b.txt", "data": b"x"}])
        with tempfile.TemporaryDirectory() as directory:
            real = os.path.join(directory, "real")
            os.mkdir(real)
            os.symlink(real, os.path.join(directory, "a"))
            self.assertError("ERR_ZIPCAGE_EXTRACTION_SYMLINK", pyzipcage.extract_zip_bytes, archive, directory)
            self.assertFalse(os.path.exists(os.path.join(real, "b.txt")))

    def test_symlink_grandparent_is_not_traversed(self):
        archive = valid_build([{"name": "a/b/c.txt", "data": b"x"}])
        with tempfile.TemporaryDirectory() as directory:
            os.mkdir(os.path.join(directory, "a"))
            real = os.path.join(directory, "real")
            os.mkdir(real)
            os.symlink(real, os.path.join(directory, "a", "b"))
            self.assertError("ERR_ZIPCAGE_EXTRACTION_SYMLINK", pyzipcage.extract_zip_bytes, archive, directory)
            self.assertFalse(os.path.exists(os.path.join(real, "c.txt")))

    def test_missing_target_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "missing")
            self.assertError("ERR_ZIPCAGE_EXTRACTION_FAILED", pyzipcage.extract_zip_bytes, simple_zip(), missing)

    def test_file_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "file")
            with open(target, "wb") as handle:
                handle.write(b"x")
            self.assertError("ERR_ZIPCAGE_EXTRACTION_FAILED", pyzipcage.extract_zip_bytes, simple_zip(), target)

    def test_empty_target_is_invalid_input(self):
        self.assertError("ERR_ZIPCAGE_INVALID_INPUT", pyzipcage.extract_zip_bytes, simple_zip(), "")

    def test_nul_target_is_invalid_input(self):
        self.assertError("ERR_ZIPCAGE_INVALID_INPUT", pyzipcage.extract_zip_bytes, simple_zip(), "a\x00b")

    def test_nonpath_target_is_invalid_input(self):
        self.assertError("ERR_ZIPCAGE_INVALID_INPUT", pyzipcage.extract_zip_bytes, simple_zip(), None)

    def test_symlinked_target_directory_is_resolved_and_confined(self):
        archive = simple_zip()
        with tempfile.TemporaryDirectory() as directory:
            real = os.path.join(directory, "real")
            os.mkdir(real)
            link = os.path.join(directory, "link")
            os.symlink(real, link)
            result = pyzipcage.extract_zip_bytes(archive, link)
            self.assertEqual(os.path.realpath(real), result.target_dir)
            self.assertTrue(os.path.isfile(os.path.join(real, "ok.txt")))

    def test_extract_file_reads_archive_from_disk(self):
        archive = simple_zip(data=b"disk")
        with tempfile.TemporaryDirectory() as directory:
            zip_path = os.path.join(directory, "in.zip")
            target = os.path.join(directory, "out")
            os.mkdir(target)
            with open(zip_path, "wb") as handle:
                handle.write(archive)
            result = pyzipcage.extract_zip_file(zip_path, target)
            self.assertEqual(1, result.entries_written)
            with open(os.path.join(target, "ok.txt"), "rb") as handle:
                self.assertEqual(b"disk", handle.read())

    def test_extract_file_missing_input_is_invalid_input(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertError(
                "ERR_ZIPCAGE_INVALID_INPUT",
                pyzipcage.extract_zip_file,
                os.path.join(directory, "missing.zip"),
                directory,
            )

    def test_symlink_entry_is_never_written_even_when_allowed(self):
        unix_mode = 0o120777
        archive = build([
            {"name": "link", "data": b"target", "unix_mode": unix_mode, "external_attributes": unix_mode << 16}
        ])
        policy = ZipPolicy(allow_symlinks=True)
        with tempfile.TemporaryDirectory() as directory:
            self.assertError("ERR_ZIPCAGE_EXTRACTION_REFUSED", pyzipcage.extract_zip_bytes, archive, directory, policy)
            self.assertEqual([], os.listdir(directory))

    def test_fifo_entry_is_never_written_even_when_allowed(self):
        unix_mode = 0o010644
        archive = build([
            {"name": "fifo", "data": b"", "unix_mode": unix_mode, "external_attributes": unix_mode << 16}
        ])
        policy = ZipPolicy(allow_special_files=True)
        with tempfile.TemporaryDirectory() as directory:
            self.assertError("ERR_ZIPCAGE_EXTRACTION_REFUSED", pyzipcage.extract_zip_bytes, archive, directory, policy)
            self.assertEqual([], os.listdir(directory))

    def test_special_entry_preflight_prevents_all_file_writes(self):
        unix_mode = 0o010644
        archive = build([
            {"name": "first", "data": b"x"},
            {"name": "fifo", "data": b"", "unix_mode": unix_mode, "external_attributes": unix_mode << 16},
        ])
        policy = ZipPolicy(allow_special_files=True)
        with tempfile.TemporaryDirectory() as directory:
            self.assertError("ERR_ZIPCAGE_EXTRACTION_REFUSED", pyzipcage.extract_zip_bytes, archive, directory, policy)
            self.assertFalse(os.path.exists(os.path.join(directory, "first")))

    def test_partial_failure_cleans_temporary_file(self):
        payload = b"abc"
        archive = build([
            {"name": "first", "data": b"ok"},
            {"name": "bad", "data": payload, "method": "deflate", "compressed_data": b"bad"},
        ])
        with tempfile.TemporaryDirectory() as directory:
            self.assertError("ERR_ZIPCAGE_DEFLATE_ERROR", pyzipcage.extract_zip_bytes, archive, directory)
            self.assertEqual([], temp_names(directory))

    def test_partial_failure_does_not_write_bad_destination(self):
        payload = b"abc"
        archive = build([
            {"name": "first", "data": b"ok"},
            {"name": "bad", "data": payload, "method": "deflate", "compressed_data": b"bad"},
        ])
        with tempfile.TemporaryDirectory() as directory:
            self.assertError("ERR_ZIPCAGE_DEFLATE_ERROR", pyzipcage.extract_zip_bytes, archive, directory)
            self.assertFalse(os.path.exists(os.path.join(directory, "bad")))

    def test_partial_failure_leaves_completed_prefix_files(self):
        payload = b"abc"
        archive = build([
            {"name": "first", "data": b"ok"},
            {"name": "bad", "data": payload, "method": "deflate", "compressed_data": b"bad"},
        ])
        with tempfile.TemporaryDirectory() as directory:
            self.assertError("ERR_ZIPCAGE_DEFLATE_ERROR", pyzipcage.extract_zip_bytes, archive, directory)
            self.assertTrue(os.path.exists(os.path.join(directory, "first")))

    def test_preexisting_temporary_looking_file_is_not_deleted(self):
        archive = simple_zip(data=b"new")
        with tempfile.TemporaryDirectory() as directory:
            collision = os.path.join(directory, ".pyzipcage-collision")
            unique = os.path.join(directory, ".pyzipcage-unique")
            with open(collision, "wb") as handle:
                handle.write(b"foreign")
            with mock.patch("pyzipcage.extract._temporary_sibling", side_effect=[collision, unique]):
                pyzipcage.extract_zip_bytes(archive, directory)
            with open(collision, "rb") as handle:
                self.assertEqual(b"foreign", handle.read())
            with open(os.path.join(directory, "ok.txt"), "rb") as handle:
                self.assertEqual(b"new", handle.read())

    def test_real_temporary_names_include_random_hex(self):
        import pyzipcage.extract as extract_module

        with tempfile.TemporaryDirectory() as directory:
            name = os.path.basename(extract_module._temporary_sibling(directory))
            self.assertRegex(name, r"^\.pyzipcage-[0-9]+-[0-9]+-[0-9a-f]{16}$")

    def test_no_temporary_files_remain_after_success(self):
        archive = valid_build([{"name": "a", "data": b"1"}, {"name": "dir/b", "data": b"2"}])
        with tempfile.TemporaryDirectory() as directory:
            pyzipcage.extract_zip_bytes(archive, directory)
            self.assertEqual([], temp_names(directory))

    def test_archive_with_traversal_writes_nothing(self):
        archive = build([{"name": "../evil", "data": b"x"}])
        with tempfile.TemporaryDirectory() as directory:
            self.assertError("ERR_ZIPCAGE_PATH_TRAVERSAL", pyzipcage.extract_zip_bytes, archive, directory)
            self.assertEqual([], os.listdir(directory))

    def test_file_directory_collision_archive_writes_nothing(self):
        archive = build([{"name": "a", "data": b"x"}, {"name": "a/b", "data": b"y"}])
        with tempfile.TemporaryDirectory() as directory:
            self.assertError("ERR_ZIPCAGE_FILE_DIRECTORY_COLLISION", pyzipcage.extract_zip_bytes, archive, directory)
            self.assertEqual([], os.listdir(directory))

    def test_case_duplicate_archive_writes_nothing(self):
        archive = build([{"name": "Same", "data": b"x"}, {"name": "same", "data": b"y"}])
        with tempfile.TemporaryDirectory() as directory:
            self.assertError("ERR_ZIPCAGE_DUPLICATE_PATH", pyzipcage.extract_zip_bytes, archive, directory)
            self.assertEqual([], os.listdir(directory))

    def test_central_order_is_preserved_in_report(self):
        archive = valid_build([{"name": "z", "data": b"z"}, {"name": "a", "data": b"a"}, {"name": "m", "data": b"m"}])
        with tempfile.TemporaryDirectory() as directory:
            result = pyzipcage.extract_zip_bytes(archive, directory)
            self.assertEqual(("z", "a", "m"), tuple(item.name for item in result.files))

    def test_unicode_filename_extracts(self):
        name = "caf\u00e9/\u2603.txt"
        archive = valid_build([{"name": name, "data": b"unicode"}])
        with tempfile.TemporaryDirectory() as directory:
            pyzipcage.extract_zip_bytes(archive, directory)
            self.assertTrue(os.path.isfile(os.path.join(directory, "caf\u00e9", "\u2603.txt")))

    def test_empty_archive_extracts_zero_entries(self):
        archive = valid_build([])
        with tempfile.TemporaryDirectory() as directory:
            result = pyzipcage.extract_zip_bytes(archive, directory)
            self.assertEqual(0, result.entries_written)
            self.assertEqual(0, result.bytes_written)

    def test_bytearray_archive_input_extracts(self):
        archive = bytearray(simple_zip(data=b"bytes"))
        with tempfile.TemporaryDirectory() as directory:
            result = pyzipcage.extract_zip_bytes(archive, directory)
            self.assertEqual(1, result.entries_written)

    def test_crc_error_cleans_temporary_file(self):
        archive = build([{"name": "bad", "data": b"abc", "crc32": 0}])
        with tempfile.TemporaryDirectory() as directory:
            self.assertError("ERR_ZIPCAGE_CRC_MISMATCH", pyzipcage.extract_zip_bytes, archive, directory)
            self.assertEqual([], temp_names(directory))
            self.assertFalse(os.path.exists(os.path.join(directory, "bad")))

    def test_deceptive_deflate_aborts_without_large_output_file(self):
        payload = bytes(range(100))
        archive = build([
            {
                "name": "small",
                "data": payload,
                "method": "deflate",
                "central_uncompressed_size": 4,
                "local_uncompressed_size": 4,
            }
        ])
        with tempfile.TemporaryDirectory() as directory:
            self.assertError("ERR_ZIPCAGE_SIZE_LIMIT", pyzipcage.extract_zip_bytes, archive, directory)
            self.assertFalse(os.path.exists(os.path.join(directory, "small")))
            self.assertEqual([], temp_names(directory))

    def test_guard_extract_uses_configured_overwrite_policy(self):
        archive = simple_zip(data=b"new")
        guard = pyzipcage.ZipGuard(ZipPolicy(overwrite=True))
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "ok.txt")
            with open(target, "wb") as handle:
                handle.write(b"old")
            result = guard.extract(archive, directory)
            self.assertEqual(1, result.entries_written)
            with open(target, "rb") as handle:
                self.assertEqual(b"new", handle.read())

    def test_existing_fifo_destination_is_collision_with_overwrite(self):
        archive = simple_zip()
        policy = ZipPolicy(overwrite=True)
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "ok.txt")
            os.mkfifo(target)
            self.assertError("ERR_ZIPCAGE_EXTRACTION_COLLISION", pyzipcage.extract_zip_bytes, archive, directory, policy)

    def test_dotdot_in_target_path_is_resolved(self):
        archive = simple_zip()
        with tempfile.TemporaryDirectory() as directory:
            real = os.path.join(directory, "real")
            other = os.path.join(directory, "other")
            os.mkdir(real)
            os.mkdir(other)
            result = pyzipcage.extract_zip_bytes(archive, os.path.join(other, "..", "real"))
            self.assertEqual(os.path.realpath(real), result.target_dir)

    def test_output_paths_stay_under_realpath_root(self):
        archive = valid_build([{"name": "a/b/c", "data": b"x"}])
        with tempfile.TemporaryDirectory() as directory:
            result = pyzipcage.extract_zip_bytes(archive, directory)
            root = os.path.realpath(directory)
            for item in result.files:
                self.assertEqual(root, os.path.commonpath((root, os.path.realpath(item.path))))


class PositiveExtractionNameTests(ZipCageTestCase):
    pass


for label, name in (
    ("simple", "file.txt"),
    ("nested", "x/y/z.txt"),
    ("space", "my file.txt"),
    ("dotfile", ".hidden"),
    ("hyphen", "a-b-c.txt"),
    ("underscore", "a_b_c.txt"),
    ("digits", "1/2/3.txt"),
    ("unicode_dir", "\u2603/file.txt"),
    ("unicode_file", "dir/\u2603.txt"),
    ("deep", "a/b/c/d/e.txt"),
):
    def positive_name_test(entry_name):
        def test(self):
            archive = valid_build([{"name": entry_name, "data": b"x"}])
            with tempfile.TemporaryDirectory() as directory:
                pyzipcage.extract_zip_bytes(archive, directory)
                self.assertTrue(os.path.isfile(os.path.join(directory, *entry_name.split("/"))))

        return test

    setattr(PositiveExtractionNameTests, "test_extract_name_" + label, positive_name_test(name))


if __name__ == "__main__":
    unittest.main()
