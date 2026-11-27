"""CWE-22 path validation matrices."""

from __future__ import annotations

import unittest

import pyzipcage
from pyzipcage import ZipPolicy

from _support import ZipCageTestCase, build, valid_build


def _reject_test(path, code, policy=None):
    def test(self):
        archive = build([{"name": path, "data": b"x"}])
        report = pyzipcage.inspect_zip_bytes(archive, policy)
        self.assertFalse(report.safe)
        self.assertHasFinding(report, code)

    return test


def _accept_test(path, policy=None):
    def test(self):
        data = b"" if path.endswith("/") else b"x"
        archive = build([{"name": path, "data": data}])
        report = pyzipcage.inspect_zip_bytes(archive, policy)
        self.assertTrue(report.safe, [finding.to_dict() for finding in report.findings])

    return test


class PathAttackTests(ZipCageTestCase):
    pass


_REJECT_CASES = []
for index, path in enumerate(
    (
        "../evil",
        "../../evil",
        "a/../evil",
        "a/../../evil",
        "..",
        "a/..",
        "./evil",
        "a/./evil",
        "x/.",
        "x/..",
    )
):
    _REJECT_CASES.append(("dot_%02d" % index, path, "ERR_ZIPCAGE_PATH_TRAVERSAL", None))

for index, path in enumerate(
    (
        "..\\evil",
        "a\\..\\evil",
        "a\\evil",
        "dir\\file.txt",
        "\\\\server\\share",
        "\\evil",
    )
):
    _REJECT_CASES.append(("backslash_%02d" % index, path, "ERR_ZIPCAGE_PATH_TRAVERSAL", None))

for index, path in enumerate(("/evil", "/", "//server/share")):
    _REJECT_CASES.append(("absolute_%02d" % index, path, "ERR_ZIPCAGE_ABSOLUTE_PATH" if index == 0 else "ERR_ZIPCAGE_UNC_PATH" if index == 2 else "ERR_ZIPCAGE_EMPTY_PATH", None))

for index, path in enumerate(("C:\\evil", "c:/evil", "D:relative", "z:/evil")):
    _REJECT_CASES.append(("drive_%02d" % index, path, "ERR_ZIPCAGE_DRIVE_PATH", None))

for index, path in enumerate(("a:b", "x/y:z", "file.txt:stream", "x::y", "a/b:c/d")):
    _REJECT_CASES.append(("colon_%02d" % index, path, "ERR_ZIPCAGE_DRIVE_PATH", None))

for value in (0, 1, 7, 8, 9, 10, 11, 12, 13, 14, 27, 31, 127, 128, 133, 159):
    _REJECT_CASES.append(("control_%02x" % value, "a" + chr(value) + "b", "ERR_ZIPCAGE_CONTROL_CHARACTER", None))

for name in ("CON", "con", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"):
    _REJECT_CASES.append(("reserved_" + name.lower(), name, "ERR_ZIPCAGE_RESERVED_NAME", None))
for index, path in enumerate(("CON.txt", "con.txt", "dir/CON/x", "NUL.txt", "com1.txt", "lpt9.txt")):
    _REJECT_CASES.append(("reserved_variant_%02d" % index, path, "ERR_ZIPCAGE_RESERVED_NAME", None))

for index, path in enumerate(("COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³", "com¹.txt", "lpt³.txt")):
    _REJECT_CASES.append(("reserved_superscript_%02d" % index, path, "ERR_ZIPCAGE_RESERVED_NAME", None))

for index, path in enumerate(("CONIN$", "CONOUT$", "conin$", "conout$", "conin$.txt", "conout$.txt", "dir/CONIN$/x", "dir/CONOUT$/x")):
    _REJECT_CASES.append(("reserved_console_%02d" % index, path, "ERR_ZIPCAGE_RESERVED_NAME", None))

for index, path in enumerate(("file.", "file ", "dir/file./x", "dir/file /x", "file..", "file  ", "a/b. ", "a/b  .")):
    _REJECT_CASES.append(("trailing_%02d" % index, path, "ERR_ZIPCAGE_TRAILING_DOT_OR_SPACE", None))

for index, path in enumerate(("a//b", "a///b", "//", "a//", "///", "a////b")):
    _REJECT_CASES.append(("empty_segment_%02d" % index, path, "ERR_ZIPCAGE_EMPTY_PATH_SEGMENT", None))

_REJECT_CASES.extend(
    (
        ("empty_name", "", "ERR_ZIPCAGE_EMPTY_PATH", None),
        ("depth_default", "/".join("d%02d" % index for index in range(21)), "ERR_ZIPCAGE_PATH_TOO_DEEP", None),
        ("depth_custom", "a/b/c/d", "ERR_ZIPCAGE_PATH_TOO_DEEP", ZipPolicy(max_depth=3)),
        ("depth_deeply_nested", "/".join("x" for _ in range(100)), "ERR_ZIPCAGE_PATH_TOO_DEEP", None),
        ("length_default", "a" * 513, "ERR_ZIPCAGE_PATH_TOO_LONG", None),
        ("length_custom", "12345678901", "ERR_ZIPCAGE_PATH_TOO_LONG", ZipPolicy(max_path_length=10)),
        ("length_multibyte", "\u2603" * 171, "ERR_ZIPCAGE_PATH_TOO_LONG", None),
        ("proto_lowercase", "__proto__", "ERR_ZIPCAGE_PROTOTYPE_POLLUTION", None),
        ("proto_constructor", "constructor", "ERR_ZIPCAGE_PROTOTYPE_POLLUTION", None),
        ("proto_prototype", "prototype", "ERR_ZIPCAGE_PROTOTYPE_POLLUTION", None),
        ("proto_uppercase", "__PROTO__", "ERR_ZIPCAGE_PROTOTYPE_POLLUTION", None),
        ("proto_nested", "safe/constructor/file", "ERR_ZIPCAGE_PROTOTYPE_POLLUTION", None),
    )
)

for label, path, code, policy in _REJECT_CASES:
    setattr(PathAttackTests, "test_reject_" + label, _reject_test(path, code, policy))


class SafePathTests(ZipCageTestCase):
    pass


_SAFE_CASES = [
    ("simple", "file.txt", None),
    ("nested", "dir/sub/file.txt", None),
    ("unicode", "dir/caf\u00e9.txt", None),
    ("snowman", "\u2603.txt", None),
    ("internal_space", "my file.txt", None),
    ("internal_dot", "file.name.txt", None),
    ("hidden_file", ".hidden", None),
    ("hidden_directory", ".config/file", None),
    ("underscore", "a_b/c_d.txt", None),
    ("hyphen", "a-b/c-d.txt", None),
    ("digits", "123/456.txt", None),
    ("com0_not_reserved", "com0.txt", None),
    ("com10_not_reserved", "com10.txt", None),
    ("lpt0_not_reserved", "lpt0.txt", None),
    ("nul_prefix_not_reserved", "nulx.txt", None),
    ("con_suffix_not_reserved", "xcon.txt", None),
    ("depth_boundary", "/".join("d%02d" % index for index in range(20)), None),
    ("depth_custom_boundary", "a/b/c", ZipPolicy(max_depth=3)),
    ("length_custom_boundary", "1234567890", ZipPolicy(max_path_length=10)),
    ("proto_allowed_explicitly", "constructor", ZipPolicy(allow_prototype_polluting_names=True)),
    ("directory", "dir/", None),
    ("unicode_combining", "caf\u0065\u0301.txt", None),
]
for label, path, policy in _SAFE_CASES:
    setattr(SafePathTests, "test_accept_" + label, _accept_test(path, policy))


class PathBoundaryTests(ZipCageTestCase):
    def test_utf8_byte_length_boundary_is_accepted(self):
        name = "\u2603" * 170
        self.assertEqual(510, len(name.encode("utf-8")))
        archive = valid_build([{"name": name, "data": b"x"}])
        self.assertTrue(pyzipcage.inspect_zip_bytes(archive).safe)

    def test_exact_default_length_is_accepted(self):
        name = "a" * 512
        archive = valid_build([{"name": name, "data": b"x"}])
        self.assertTrue(pyzipcage.inspect_zip_bytes(archive).safe)

    def test_path_length_uses_bytes_not_characters(self):
        name = "\u2603" * 171
        archive = build([{"name": name, "data": b"x"}])
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_PATH_TOO_LONG")

    def test_invalid_long_path_is_excluded_from_collision_analysis(self):
        long_name = "/".join("x" for _ in range(100))
        entries = [{"name": long_name, "data": b""} for _ in range(50)]
        archive = build(entries)
        report = pyzipcage.inspect_zip_bytes(archive)
        self.assertHasFinding(report, "ERR_ZIPCAGE_PATH_TOO_DEEP")
        self.assertNotIn("ERR_ZIPCAGE_FILE_DIRECTORY_COLLISION", [finding.code for finding in report.findings])


if __name__ == "__main__":
    unittest.main()
