# pyzipcage

pyzipcage is a zero-dependency Python library for structural ZIP security inspection, bounded entry reading, and conservative filesystem extraction. It targets Python 3.9 through 3.13 and uses only the standard library at runtime.

It is a companion to the zipcage npm package. The Python implementation independently parses local headers, central directory entries, extra fields, and end records instead of delegating safety decisions to `zipfile`.

## Security posture

- CWE-22 Zip-Slip defenses reject dot segments, absolute paths, backslashes, Windows drive letters, UNC paths, NUL and C0 or C1 controls, colons used for drive or alternate-stream confusion, Windows reserved device names, trailing dots or spaces, overlong paths, and excessive depth.
- CWE-409 zip-bomb defenses enforce entry count, per-entry bytes, aggregate bytes, archive bytes, and compression-ratio limits. Overlapping compressed ranges and aliased empty ranges are rejected.
- Deflate reading uses `zlib.decompressobj(wbits=-15)` with a hard output allocation cap of at most 64 KiB per call. A stream that produces more than its declared size is aborted at that declared size rather than allocating attacker-claimed gigabytes.
- Stored and deflate entries are read only after exact uncompressed-size and CRC-32 verification.
- Local file headers must agree with central directory filenames, flags, methods, versions, CRC values, and sizes. Data descriptors are checked in signed and unsigned forms.
- Ambiguous or forged end-of-central-directory candidates fail closed. Prepended bytes, trailing bytes, interior gaps, multi-disk archives, ZIP64 sentinels, ZIP64 extra fields, encrypted entries, unsupported methods, and unsupported flags are rejected by default.
- Info-ZIP `0x7075` Unicode Path extra fields are parsed in both central and local headers. They must be version 1, valid UTF-8, match the primary filename checksum, and decode to exactly the primary filename.
- Duplicate paths, Unicode normalization duplicates, case-insensitive duplicates, file-versus-directory collisions, and file-as-ancestor collisions are rejected before extraction.
- Unix symlinks, FIFOs, sockets, devices, unknown special file types, setuid bits, and setgid bits are rejected by default. Extraction never writes them even if inspection is explicitly relaxed.
- Extraction uses a realpath-resolved existing target directory, refuses symlink traversal and symlink overwrite, writes through random exclusive temporary siblings, and hardens files to `0o644` and directories to `0o755`.

## Supported scope

pyzipcage supports classic single-disk ZIP archives using Store method 0 or Deflate method 8. ZIP64, encrypted entries, multi-disk archives, and other compression methods are intentionally outside the supported extraction scope. They may be reported structurally when an explicit inspection policy allows encrypted entries, but encrypted content is never decrypted, read, or extracted.

The API accepts the complete archive in memory. Configured archive and output caps bound work performed by pyzipcage, but they cannot undo allocation already performed by the caller before invoking the library.

`inspect_zip_bytes` is structural inspection. It does not decompress every entry. Content CRC, exact size, deflate correctness, and trailing compressed data are verified when `read_zip_entry` or extraction processes an entry. Extraction still refuses the entire archive if structural inspection has any finding.

Extraction is designed for a private empty directory owned by the caller. A hostile local process racing filesystem operations is outside the stronger portable threat model. Within that model, pyzipcage never follows symlinks in the destination tree and uses atomic same-directory installation for file contents.

## Installation

```bash
python3 -m pip install pyzipcage
```

## Inspection

```python
from pyzipcage import inspect_zip_bytes

report = inspect_zip_bytes(archive_bytes)
if not report.safe:
    for finding in report.findings:
        print(finding.code, finding.entry_name, finding.message)
```

Use `assert_safe_zip_bytes` when unsafe input should raise immediately:

```python
from pyzipcage import ZipCageError, assert_safe_zip_bytes

try:
    report = assert_safe_zip_bytes(archive_bytes)
except ZipCageError as exc:
    print(exc.code)
    print(len(exc.findings))
```

Branch on `exc.code`, not the human-readable message. The complete stable list is exported as `ERROR_CODES`.

## Reading one entry

```python
from pyzipcage import read_zip_entry

data = read_zip_entry(archive_bytes, "docs/readme.txt")
```

Reading first performs full structural inspection. If any entry in the archive is hostile, the read is refused. The selected entry must be a regular file, not a directory, symlink, device, FIFO, socket, or encrypted entry.

## Extraction

```python
from pyzipcage import extract_zip_bytes, extract_zip_file

result = extract_zip_bytes(archive_bytes, "private-empty-directory")
# or
result = extract_zip_file("archive.zip", "private-empty-directory")
```

Existing files are not overwritten by default. Explicit overwrite mode only replaces existing regular files and still refuses symlinks, directories, and special filesystem objects:

```python
from pyzipcage import ZipPolicy, extract_zip_bytes

policy = ZipPolicy(overwrite=True)
result = extract_zip_bytes(archive_bytes, "private-empty-directory", policy)
```

## Policy

`ZipPolicy` is immutable and validated at construction time:

```python
from pyzipcage import ZipPolicy

policy = ZipPolicy(
    max_entries=1000,
    max_entry_bytes=50 * 1024 * 1024,
    max_total_bytes=200 * 1024 * 1024,
    max_compression_ratio=100.0,
    max_archive_bytes=512 * 1024 * 1024,
    max_depth=20,
    max_path_length=512,
)
```

The allow flags are deliberately narrow. `allow_symlinks`, `allow_special_files`, `allow_suid_sgid`, and `allow_encrypted` affect inspection only. Extraction still never writes symlinks or special files and never decrypts encrypted content. `reject_polyglot=False` is for forensic inspection of self-extracting or otherwise container-wrapped archives, not for normal untrusted input.

A reusable configured guard is available:

```python
from pyzipcage import ZipGuard, ZipPolicy

guard = ZipGuard(ZipPolicy(max_entries=100))
report = guard.inspect(archive_bytes)
data = guard.read_entry(archive_bytes, "safe.txt")
```

## Command line inspection

The command line interface is inspect-only. It never extracts files:

```bash
python3 -m pyzipcage inspect archive.zip
pyzipcage inspect archive.zip --max-entries 500
```

It prints a JSON report. The exit code is 0 when the report is safe and 3 when the archive is unsafe or cannot be read.

## Deterministic test builder

`create_zip_bytes` builds deterministic classic Store or Deflate archives with fixed DOS date fields. It exists for tests and for callers that need small canonical fixtures:

```python
from pyzipcage import create_zip_bytes

archive = create_zip_bytes([
    {"name": "hello.txt", "data": b"hello", "method": "deflate"},
])
```

Advanced override keys are intentionally available so the test suite can construct exact malformed parser-differential fixtures. Production callers should use only ordinary names, data, methods, comments, and modes.

## Error handling

```python
from pyzipcage import ZipCageError, extract_zip_bytes

try:
    extract_zip_bytes(archive_bytes, target_dir)
except ZipCageError as exc:
    if exc.code == "ERR_ZIPCAGE_EXTRACTION_OVERWRITE":
        choose_another_directory()
    else:
        reject_archive()
```

Every expected validation, parsing, decompression, and extraction failure uses `ZipCageError` with a stable machine-readable code.

## Test evidence and development

The offline unittest suite currently contains 487 real tests covering path traversal, zip-bomb limits, overlap primitives, header parser differentials, forged EOCD shapes, Unicode path differentials, ZIP64 sentinels, Unix special files, bounded decompression, extraction confinement, CLI behavior, typing, packaging, and repository hygiene. All 487 tests passed in the local verification run for this commit.

Run the suite with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

The project has no runtime dependencies and no third-party test dependencies.
