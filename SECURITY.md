# Security Policy

## Supported versions

Version 1.x receives security fixes.

## Reporting a vulnerability

Please use GitHub's private security advisory form on the repository. Do not open a public issue for an undisclosed vulnerability.

Include the affected version, a minimal archive or code reproduction, the expected behavior, and the observed behavior. Do not include secrets, private keys, personal data, or archives containing sensitive content. Reports are acknowledged within seven days. Fixes are released as patch versions with a changelog entry.

## In scope

- Zip-Slip or path-confusion bypasses, including Windows-specific path behavior
- Zip-bomb limit, compression-ratio, overlapping-range, or aliased-range bypasses
- Deflate output growth beyond the documented hard caps
- CRC-32 or exact-size verification bypasses
- Local-header versus central-directory parser differentials
- End-of-central-directory ambiguity or polyglot parser confusion
- Info-ZIP Unicode Path extra-field parser differentials
- ZIP64 sentinel or multi-disk confusion in the classic-ZIP parser
- Symlink traversal, symlink overwrite, unsafe permissions, or special-file creation during extraction
- Temporary-file collision, reuse, or cleanup failures
- Practical denial of service within documented size and entry-count limits

## Out of scope

- Vulnerabilities in applications using this library
- ZIP64, encryption, multi-disk archives, and compression methods other than Store or Deflate
- A hostile local process racing extraction in a directory it can already modify
- Inputs above documented archive, entry-count, or uncompressed-size limits
- Use of explicit relaxed inspection options outside a deliberate application profile
- Social engineering or physical access

## Design notes

pyzipcage is defensive only. It performs no network access, browser interaction, subprocess execution, or remote resource fetching. The CLI is inspect-only and never extracts.

The parser intentionally does not use `zipfile` for safety decisions. It independently verifies local and central metadata before any entry is read or written.
