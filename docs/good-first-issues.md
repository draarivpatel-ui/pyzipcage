# Good first issues

Ten modular starter tasks for new contributors. Each is scoped to one file or one focused behavior. Every task must preserve the zero runtime dependency rule and Python 3.9 compatibility.

1. **Design ZIP64 support** in a new `docs/zip64-design.md`, covering sentinel validation, 64-bit extra-field ordering, size caps, and why support must remain explicit. Do not implement it in the same change.
2. **Add a central-directory mutation matrix** in `tests/test_parser_differentials.py` that flips every fixed offset in one valid central header and asserts a deterministic finding or exact acceptance reason.
3. **Add a data-descriptor matrix** covering signed and unsigned forms, matching nonzero local placeholders, truncated descriptors, and descriptors that begin with the signature value as a real CRC edge case.
4. **Add a deflate chunk-boundary corpus** in `tests/test_zipbombs.py` with outputs around 65535, 65536, and 65537 bytes to prove that the hard `max_length` cap never depends on declared size.
5. **Add Windows path edge fixtures** in `tests/test_paths.py` for mixed separators, alternate data stream shapes, reserved names with padding, and Unicode case variants.
6. **Write `docs/threat-model.md`** describing attacker capabilities, trusted and untrusted filesystem boundaries, race assumptions, memory limits, and application responsibilities.
7. **Add extraction race documentation and tests** for destination appearance between the first check and atomic installation, using only stdlib synchronization primitives.
8. **Add package build verification** in CI using `python -m build` in an isolated job while keeping the main test job dependency free.
9. **Add a benchmark script** under `scripts/` using only stdlib `timeit` for inspection throughput, with clear instructions that it is not a security test.
10. **Improve error documentation** in `README.md` with a table grouping every `ERROR_CODES` value by input, structure, path, size, encoding, integrity, and extraction failure.

Before starting one, open an issue or comment on the existing issue so work is not duplicated. Add tests with every code change.
