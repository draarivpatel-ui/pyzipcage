"""Inspect-only command line interface tests."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pyzipcage
from pyzipcage.cli import build_parser, main

from _support import ZipCageTestCase, build, simple_zip, valid_build

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "pyzipcage"] + list(args),
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )


class CliTests(ZipCageTestCase):
    def write_zip(self, directory, archive):
        path = os.path.join(directory, "in.zip")
        with open(path, "wb") as handle:
            handle.write(archive)
        return path

    def test_version_exits_zero(self):
        result = run_cli("--version")
        self.assertEqual(0, result.returncode)
        self.assertIn("pyzipcage 1.0.0", result.stdout)

    def test_no_command_is_usage_error(self):
        result = run_cli()
        self.assertEqual(2, result.returncode)
        self.assertIn("usage:", result.stderr)

    def test_help_lists_inspect_but_no_extract_command(self):
        result = run_cli("--help")
        self.assertEqual(0, result.returncode)
        self.assertIn("inspect", result.stdout)
        self.assertNotIn("{extract}", result.stdout)

    def test_unknown_command_is_usage_error(self):
        result = run_cli("extract")
        self.assertEqual(2, result.returncode)

    def test_safe_archive_json_exits_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_zip(directory, simple_zip())
            result = run_cli("inspect", path)
        self.assertEqual(0, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["safe"])
        self.assertEqual([], report["findings"])
        self.assertEqual(1, report["totals"]["entries"])

    def test_traversal_archive_json_exits_three_with_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_zip(directory, build([{"name": "../evil", "data": b"x"}]))
            result = run_cli("inspect", path)
        self.assertEqual(3, result.returncode)
        report = json.loads(result.stdout)
        self.assertFalse(report["safe"])
        self.assertIn("ERR_ZIPCAGE_PATH_TRAVERSAL", [finding["code"] for finding in report["findings"]])

    def test_missing_file_exits_three_with_error_on_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_cli("inspect", os.path.join(directory, "missing.zip"))
        self.assertEqual(3, result.returncode)
        self.assertIn("ERR_ZIPCAGE_INVALID_INPUT", result.stderr)
        self.assertEqual("", result.stdout)

    def test_strict_polyglot_default_exits_three(self):
        archive = build([{"name": "ok.txt", "data": b"x"}], trailing_bytes=b"x")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_zip(directory, archive)
            result = run_cli("inspect", path)
        self.assertEqual(3, result.returncode)
        self.assertIn("ERR_ZIPCAGE_POLYGLOT", result.stdout)

    def test_allow_polyglot_exits_zero(self):
        archive = build([{"name": "ok.txt", "data": b"x"}], trailing_bytes=b"x")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_zip(directory, archive)
            result = run_cli("inspect", "--allow-polyglot", path)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(json.loads(result.stdout)["safe"])

    def test_case_variants_flag_by_default(self):
        archive = build([{"name": "Same", "data": b"1"}, {"name": "same", "data": b"2"}])
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_zip(directory, archive)
            result = run_cli("inspect", path)
        self.assertEqual(3, result.returncode)
        self.assertIn("ERR_ZIPCAGE_DUPLICATE_PATH", result.stdout)

    def test_case_sensitive_duplicates_option(self):
        archive = build([{"name": "Same", "data": b"1"}, {"name": "same", "data": b"2"}])
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_zip(directory, archive)
            result = run_cli("inspect", "--case-sensitive-duplicates", path)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_max_entries_option(self):
        archive = valid_build([{"name": "a", "data": b""}, {"name": "b", "data": b""}])
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_zip(directory, archive)
            result = run_cli("inspect", "--max-entries", "1", path)
        self.assertEqual(3, result.returncode)
        self.assertIn("ERR_ZIPCAGE_ENTRY_LIMIT", result.stdout)

    def test_max_entry_bytes_option(self):
        archive = simple_zip(data=b"12345")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_zip(directory, archive)
            result = run_cli("inspect", "--max-entry-bytes", "4", path)
        self.assertEqual(3, result.returncode)
        self.assertIn("ERR_ZIPCAGE_SIZE_LIMIT", result.stdout)

    def test_max_total_bytes_option(self):
        archive = valid_build([{"name": "a", "data": b"123"}, {"name": "b", "data": b"456"}])
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_zip(directory, archive)
            result = run_cli("inspect", "--max-total-bytes", "5", path)
        self.assertEqual(3, result.returncode)
        self.assertIn("ERR_ZIPCAGE_SIZE_LIMIT", result.stdout)

    def test_ratio_option(self):
        archive = build([{"name": "ok.txt", "data": b"x" * 200, "method": "deflate", "compressed_data": b"xx"}])
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_zip(directory, archive)
            low = run_cli("inspect", "--max-compression-ratio", "99", path)
            high = run_cli("inspect", "--max-compression-ratio", "100", path)
        self.assertEqual(3, low.returncode)
        self.assertEqual(0, high.returncode)

    def test_invalid_integer_option_is_usage_error(self):
        result = run_cli("inspect", "--max-entries", "0", "x.zip")
        self.assertEqual(2, result.returncode)

    def test_infinite_ratio_is_json_safe_string(self):
        archive = build([{"name": "ok.txt", "data": b"x", "method": "deflate", "compressed_data": b""}])
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_zip(directory, archive)
            result = run_cli("inspect", path)
        self.assertEqual(3, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual("Infinity", report["totals"]["compression_ratio"])

    def test_direct_main_returns_zero_for_safe_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_zip(directory, simple_zip())
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["inspect", path])
        self.assertEqual(0, code)
        self.assertTrue(json.loads(stdout.getvalue())["safe"])

    def test_direct_main_without_command_returns_two(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main([])
        self.assertEqual(2, code)
        self.assertIn("usage:", stderr.getvalue())

    def test_parser_prog_is_pyzipcage(self):
        self.assertEqual("pyzipcage", build_parser().prog)

    def test_module_is_importable_as_main(self):
        import pyzipcage.__main__ as module

        self.assertTrue(callable(module.main))


if __name__ == "__main__":
    unittest.main()
