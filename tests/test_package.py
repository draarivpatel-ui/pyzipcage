"""Package metadata, public API, typing, and repository hygiene tests."""

from __future__ import annotations

import ast
import dataclasses
import inspect
import re
import subprocess
import typing
import unittest
from pathlib import Path

import pyzipcage
from pyzipcage import ERROR_CODES, ZipCageError, ZipPolicy

ROOT = Path(__file__).resolve().parents[1]


def read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def project_files():
    skipped = {".git", "__pycache__", ".pytest_cache", "build", "dist", ".venv", "venv"}
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skipped for part in path.parts):
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        yield path


class PackageMetadataTests(unittest.TestCase):
    def test_runtime_dependencies_are_empty(self):
        self.assertIn("dependencies = []", read("pyproject.toml"))

    def test_dev_dependencies_are_empty(self):
        self.assertIn("dev = []", read("pyproject.toml"))

    def test_python_floor_is_39(self):
        self.assertIn('requires-python = ">=3.9"', read("pyproject.toml"))

    def test_project_urls_point_to_public_repository(self):
        text = read("pyproject.toml")
        self.assertIn('Homepage = "https://github.com/draarivpatel-ui/pyzipcage"', text)
        self.assertIn('Repository = "https://github.com/draarivpatel-ui/pyzipcage"', text)
        self.assertIn('Issues = "https://github.com/draarivpatel-ui/pyzipcage/issues"', text)

    def test_version_matches_package(self):
        self.assertIn('version = "1.0.0"', read("pyproject.toml"))
        self.assertEqual("1.0.0", pyzipcage.__version__)

    def test_py_typed_is_present(self):
        self.assertTrue((ROOT / "src" / "pyzipcage" / "py.typed").is_file())

    def test_src_layout_is_used(self):
        self.assertIn('package-dir = { "" = "src" }', read("pyproject.toml"))
        self.assertTrue((ROOT / "src" / "pyzipcage" / "__init__.py").is_file())

    def test_package_data_includes_py_typed(self):
        self.assertIn('pyzipcage = ["py.typed"]', read("pyproject.toml"))

    def test_classifiers_cover_python_39_to_313(self):
        text = read("pyproject.toml")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn("Programming Language :: Python :: " + version, text)


class WorkflowTests(unittest.TestCase):
    def test_ci_uses_ubuntu_2404(self):
        self.assertIn("runs-on: ubuntu-24.04", read(".github/workflows/ci.yml"))

    def test_ci_matrix_covers_python_39_to_313(self):
        text = read(".github/workflows/ci.yml")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn('"' + version + '"', text)

    def test_ci_runs_unittest_suite(self):
        self.assertIn("PYTHONPATH=src python3 -m unittest discover -s tests", read(".github/workflows/ci.yml"))

    def test_publish_uses_oidc_trusted_publishing_permission(self):
        text = read(".github/workflows/publish.yml")
        self.assertIn("id-token: write", text)
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", text)

    def test_publish_workflow_targets_pypi_environment(self):
        text = read(".github/workflows/publish.yml")
        self.assertIn("name: pypi", text)
        self.assertIn("url: https://pypi.org/p/pyzipcage", text)


class DocumentationTests(unittest.TestCase):
    def test_required_documents_exist(self):
        for relative in (
            "README.md",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "LICENSE",
            "docs/good-first-issues.md",
            ".github/PULL_REQUEST_TEMPLATE.md",
            ".github/ISSUE_TEMPLATE/bug_report.md",
            ".github/ISSUE_TEMPLATE/feature_request.md",
        ):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_good_first_issues_has_ten_items(self):
        count = len(re.findall(r"^\d+\. \*\*", read("docs/good-first-issues.md"), re.MULTILINE))
        self.assertEqual(10, count)

    def test_good_first_issues_includes_zip64_design_task(self):
        self.assertIn("ZIP64", read("docs/good-first-issues.md"))

    def test_readme_documents_honest_store_deflate_scope(self):
        text = read("README.md")
        self.assertIn("Store method 0 or Deflate method 8", text)
        self.assertIn("ZIP64", text)
        self.assertIn("multi-disk", text)

    def test_readme_documents_memory_scope(self):
        self.assertIn("complete archive in memory", read("README.md"))

    def test_readme_warns_structural_inspection_is_not_content_verification(self):
        text = read("README.md")
        self.assertIn("does not decompress every entry", text)
        self.assertIn("CRC", text)

    def test_readme_documents_major_attack_classes_without_hype(self):
        text = read("README.md")
        for phrase in ("CWE-22", "CWE-409", "Zip-Slip", "zip-bomb", "symlink"):
            self.assertIn(phrase, text)
        for hype in ("military grade", "unbreakable", "perfect security", "100% safe"):
            self.assertNotIn(hype, text.lower())

    def test_security_policy_has_private_reporting_path(self):
        self.assertIn("private security advisory", read("SECURITY.md"))

    def test_security_policy_defines_scope(self):
        text = read("SECURITY.md")
        self.assertIn("## In scope", text)
        self.assertIn("## Out of scope", text)

    def test_contributing_preserves_zero_dependency_rule(self):
        text = read("CONTRIBUTING.md")
        self.assertIn("zero runtime dependencies", text)
        self.assertIn("dependencies = []", text)

    def test_license_is_mit_without_private_data(self):
        text = read("LICENSE")
        self.assertIn("MIT License", text)
        self.assertIn("pyzipcage contributors", text)

    def test_readme_exact_test_count_is_current(self):
        match = re.search(r"currently contains (\d+) real tests", read("README.md"))
        self.assertIsNotNone(match)
        self.assertEqual(487, int(match.group(1)))


class PublicApiTests(unittest.TestCase):
    def test_required_public_names_exist(self):
        for name in (
            "ERROR_CODES",
            "ExtractionReport",
            "Finding",
            "InspectionReport",
            "Totals",
            "ZipCageError",
            "ZipEntryInfo",
            "ZipGuard",
            "ZipPolicy",
            "assert_safe_zip_bytes",
            "create_zip_bytes",
            "extract_zip_bytes",
            "extract_zip_file",
            "inspect_zip_bytes",
            "inspect_zip_file",
            "read_zip_entry",
        ):
            self.assertTrue(hasattr(pyzipcage, name), name)

    def test_all_exports_exist(self):
        for name in pyzipcage.__all__:
            self.assertTrue(hasattr(pyzipcage, name), name)

    def test_error_codes_are_unique(self):
        self.assertEqual(len(ERROR_CODES), len(set(ERROR_CODES)))

    def test_error_codes_are_machine_readable(self):
        for code in ERROR_CODES:
            self.assertRegex(code, r"^ERR_ZIPCAGE_[A-Z0-9_]+$")

    def test_error_contains_code_and_findings_attributes(self):
        error = ZipCageError("ERR_ZIPCAGE_INVALID_INPUT", "example", findings=("a", "b"))
        self.assertEqual("ERR_ZIPCAGE_INVALID_INPUT", error.code)
        self.assertEqual(("a", "b"), error.findings)

    def test_policy_is_frozen(self):
        policy = ZipPolicy()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy.max_entries = 1

    def test_public_functions_have_type_annotations(self):
        for function in (
            pyzipcage.inspect_zip_bytes,
            pyzipcage.inspect_zip_file,
            pyzipcage.assert_safe_zip_bytes,
            pyzipcage.read_zip_entry,
            pyzipcage.extract_zip_bytes,
            pyzipcage.extract_zip_file,
            pyzipcage.create_zip_bytes,
        ):
            hints = typing.get_type_hints(function)
            self.assertIn("return", hints, function.__name__)

    def test_no_unsafe_decode_alias_exists(self):
        self.assertFalse(hasattr(pyzipcage, "extract_unsafe"))
        self.assertFalse(hasattr(pyzipcage, "read_unsafe"))


class SourceHygieneTests(unittest.TestCase):
    def test_source_has_no_third_party_imports(self):
        allowed = {
            "__future__",
            "argparse",
            "collections",
            "dataclasses",
            "itertools",
            "json",
            "math",
            "os",
            "pyzipcage",
            "re",
            "secrets",
            "stat",
            "struct",
            "sys",
            "threading",
            "typing",
            "unicodedata",
            "zlib",
        }
        for path in (ROOT / "src" / "pyzipcage").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:
                        continue
                    names = [(node.module or "").split(".")[0]]
                else:
                    continue
                for name in names:
                    self.assertIn(name, allowed, "{} imports {}".format(path.name, name))

    def test_tracked_text_has_no_em_or_en_dashes(self):
        forbidden = (chr(0x2013), chr(0x2014))
        for path in project_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for char in forbidden:
                self.assertNotIn(char, text, "{} contains a Unicode dash".format(path))

    def test_tracked_text_has_no_local_private_markers(self):
        markers = (
            "/" + "Users/",
            "someone@" + "gmail.com",
            "handle-redacted286@" + "gmail.com",
            "Exampleton" + " Manor",
        )
        for path in project_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for marker in markers:
                self.assertNotIn(marker, text, "{} contains a private marker".format(path))

    def test_repository_text_uses_lf_line_endings(self):
        for path in project_files():
            data = path.read_bytes()
            self.assertNotIn(b"\r\n", data, "{} contains CRLF".format(path))
            self.assertNotIn(b"\r", data, "{} contains a carriage return".format(path))

    def test_no_vendor_shaped_placeholder_tokens(self):
        prefixes = (
            "ts" + "key-",
            "s" + "k-",
            "gh" + "p_",
            "github" + "_pat_",
            "AK" + "IA",
            "x" + "ox",
            "gs" + "k_",
            "nv" + "api-",
            "tv" + "ly-",
            "AI" + "za",
        )
        for path in project_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for prefix in prefixes:
                self.assertNotIn(prefix, text, "{} contains a vendor-shaped token".format(path))

    def test_no_pycache_or_compiled_python_files_are_tracked(self):
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        for relative in result.stdout.splitlines():
            parts = tuple(relative.split("/"))
            self.assertNotIn("__pycache__", parts)
            self.assertFalse(relative.endswith((".pyc", ".pyo")), relative)

    def test_source_avoids_dynamic_code_and_network_modules(self):
        forbidden = ("eval(", "exec(", "import subprocess", "import socket", "import urllib", "import requests", "import ctypes")
        for path in (ROOT / "src" / "pyzipcage").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                self.assertNotIn(marker, text, "{} contains {}".format(path, marker))

    def test_repository_file_count_is_intentionally_small(self):
        files = list(project_files())
        self.assertLessEqual(len(files), 40)
        self.assertGreaterEqual(len(files), 20)

    def test_no_dependency_or_build_output_directories_are_present(self):
        for relative in ("node_modules", "dist", "build", ".venv", "venv"):
            self.assertFalse((ROOT / relative).exists(), relative)


if __name__ == "__main__":
    unittest.main()
