# Contributing

Thanks for helping improve pyzipcage. The project has zero runtime dependencies and targets Python 3.9 through 3.13.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Running tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Every change must keep the suite green using Python 3.9 syntax. No third-party test packages are required.

## Security invariants

- Keep `dependencies = []` in `pyproject.toml`.
- Never delegate safety decisions to `zipfile` or a platform ZIP parser.
- Fail closed on ambiguous local headers, central headers, extra fields, EOCD records, or parser differentials.
- Never follow symlinks inside an extraction target.
- Never write symlinks, devices, FIFOs, sockets, setuid files, or setgid files.
- Keep output allocation bounded independently of attacker-controlled declared sizes.
- Verify exact uncompressed size and CRC-32 before content is returned or installed.
- Use random exclusive temporary files and clean them after partial failures.
- Add regression tests for every validation rule or bug fix.
- Prefer explicit opt-in for unsafe compatibility behavior.
- Do not add em dashes or en dashes to source, docs, tests, or workflow files.

## Code guidelines

- Use only the Python standard library at runtime.
- Use type annotations on public functions.
- Preserve Python 3.9 compatibility.
- Raise `ZipCageError` with a stable machine-readable code for every expected failure.
- Keep error messages free of secrets and unnecessary attacker-controlled content.
- Keep structural validation deterministic and bounded.

## Pull requests

1. Fork the repository and create a focused branch.
2. Describe the security impact of the change.
3. Add or update regression tests.
4. Run the full suite and paste the exact result.
5. Keep commits small and self-contained.

## Good first issues

See [docs/good-first-issues.md](docs/good-first-issues.md) for ten modular starter tasks.
