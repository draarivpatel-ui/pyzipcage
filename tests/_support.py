"""Shared deterministic helpers for the pyzipcage test suite."""

from __future__ import annotations

import os
import struct
import unittest
import zlib

import pyzipcage
from pyzipcage import ZipCageError, create_zip_bytes


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def p16(value):
    return struct.pack("<H", value)


def p32(value):
    return struct.pack("<I", value)


def patch_u16(data, offset, value):
    output = bytearray(data)
    struct.pack_into("<H", output, offset, value)
    return bytes(output)


def patch_u32(data, offset, value):
    output = bytearray(data)
    struct.pack_into("<I", output, offset, value)
    return bytes(output)


def deflate_raw(data):
    compressor = zlib.compressobj(level=9, wbits=-15)
    return compressor.compress(data) + compressor.flush()


def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def build(entries, validate=False, **options):
    merged = dict(options)
    merged["validate"] = validate
    return create_zip_bytes(entries, merged)


def valid_build(entries, **options):
    merged = dict(options)
    merged["validate"] = True
    return create_zip_bytes(entries, merged)


def simple_zip(data=b"hello", name="ok.txt", method="stored", **overrides):
    entry = {"name": name, "data": data, "method": method}
    entry.update(overrides)
    return valid_build([entry])


def eocd_offset(data):
    offset = data.rfind(b"PK\x05\x06")
    if offset < 0:
        raise AssertionError("fixture has no EOCD")
    return offset


def central_offset(data):
    return u32(data, eocd_offset(data) + 16)


def first_central(data):
    return central_offset(data)


def first_local(data):
    return u32(data, first_central(data) + 42)


def local_name_length(data, local_offset=None):
    if local_offset is None:
        local_offset = first_local(data)
    return u16(data, local_offset + 26)


def local_extra_length(data, local_offset=None):
    if local_offset is None:
        local_offset = first_local(data)
    return u16(data, local_offset + 28)


def data_offset(data, local_offset=None):
    if local_offset is None:
        local_offset = first_local(data)
    return local_offset + 30 + local_name_length(data, local_offset) + local_extra_length(data, local_offset)


def unicode_path_extra(primary_bytes, unicode_value, correct_crc=True, version=1):
    if isinstance(unicode_value, str):
        encoded = unicode_value.encode("utf-8")
    else:
        encoded = bytes(unicode_value)
    checksum = crc32(primary_bytes) if correct_crc else (crc32(primary_bytes) + 1) & 0xFFFFFFFF
    payload = bytes([version]) + p32(checksum) + encoded
    return p16(0x7075) + p16(len(payload)) + payload


def unknown_extra(identifier=0xCAFE, payload=b"ok"):
    return p16(identifier) + p16(len(payload)) + payload


def finding_codes(report):
    return [finding.code for finding in report.findings]


def make_tree(root, names):
    for name in names:
        path = os.path.join(root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(name.encode("utf-8"))


class ZipCageTestCase(unittest.TestCase):
    def assertHasFinding(self, report, code):
        codes = finding_codes(report)
        self.assertIn(code, codes, "expected {} in {}".format(code, codes))
        return report.findings[codes.index(code)]

    def assertOnlyFindings(self, report, codes):
        self.assertEqual(list(codes), finding_codes(report))

    def assertError(self, code, func, *args, **kwargs):
        with self.assertRaises(ZipCageError) as caught:
            func(*args, **kwargs)
        self.assertEqual(
            code,
            caught.exception.code,
            "expected {}, got {}: {}".format(code, caught.exception.code, caught.exception),
        )
        return caught.exception

    def assertReadError(self, code, archive, name="ok.txt", policy=None):
        return self.assertError(code, pyzipcage.read_zip_entry, archive, name, policy)
