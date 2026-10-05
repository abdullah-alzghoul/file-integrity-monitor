# File Integrity Monitor

A Python command-line tool for detecting unauthorized file changes through cryptographic hashing and baseline comparison. Built for security auditing, incident response, and continuous monitoring of critical directories.

## Features

- **Cryptographic hashing:** SHA-256 or SHA-512 file integrity verification
- **HMAC-signed baselines:** Tamper-evident baseline storage prevents silent modification
- **Change detection:** Identifies added, deleted, modified, moved, and permission-changed files
- **Multiple output formats:** Console, JSON, CSV, and HTML reports
- **Pattern-based filtering:** Exclude transient files via `.gitignore`-style rules
- **Audit logging:** Append-only JSON Lines log of all operations
- **Parallel scanning:** Multi-threaded hashing for large directories
- **Standard library only:** Zero runtime dependencies

## Installation

### Requirements

- Python 3.9 or higher

### Setup

Clone the repository and navigate to the project directory:

```powershell
cd C:\dev\file-integrity-monitor
```

Optional: create a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

No package installation is required -- the tool uses only the Python standard library.

## Usage

### Creating a Baseline

A baseline is a snapshot of all files in a directory at a point in time.

```powershell
# Basic baseline
python -m fim baseline C:\path\to\monitor -o baseline.json

# Signed baseline (recommended for production)
python -m fim baseline C:\path\to\monitor -o baseline.json --key-file key.txt

# With exclude rules
python -m fim baseline C:\path\to\monitor -o baseline.json -r rules.txt
```

### Scanning for Changes

Compare the current directory state against a baseline:

```powershell
# Console output
python -m fim scan C:\path\to\monitor -b baseline.json

# JSON report
python -m fim scan C:\path\to\monitor -b baseline.json -f json -o report.json

# HTML report
python -m fim scan C:\path\to\monitor -b baseline.json -f html -o report.html

# Verify signed baseline
python -m fim scan C:\path\to\monitor -b baseline.json --key-file key.txt
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (baseline created, or scan with no changes) |
| 1 | Scan completed with changes detected |
| 2 | Error (invalid path, missing baseline, signature failure, etc.) |

## Configuration

Configuration can be provided via:

1. **Command-line arguments** (highest priority)
2. **Environment variables** (`FIM_ALGORITHM`, `FIM_THREADS`, `FIM_KEY`, etc.)
3. **JSON config file** (lowest priority)

Example `config.json`:

```json
{
  "algorithm": "sha512",
  "threads": 8,
  "exclude": ["*.tmp", "*.log", ".git/"]
}
```

Usage with config file:

```powershell
python -m fim baseline . -o baseline.json --config config.json
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `FIM_BASELINE` | Default baseline path |
| `FIM_OUTPUT` | Default report output path |
| `FIM_FORMAT` | Default output format (`console`, `json`, `csv`, `html`) |
| `FIM_ALGORITHM` | Hash algorithm (`sha256` or `sha512`) |
| `FIM_THREADS` | Number of parallel hashing threads |
| `FIM_KEY` | HMAC key (prefer `--key-file` for security) |
| `FIM_RULES` | Path to exclude rules file |
| `FIM_AUDIT_LOG` | Path to audit log file |
| `FIM_CONFIG` | Path to JSON config file |

## Exclude Rules

Rules files use `.gitignore`-style patterns, one per line. Blank lines and lines starting with `#` are ignored.

Example `rules.txt`:

```text
# Temporary files
*.tmp
*.log

# Version control
.git/
.gitignore

# Build artifacts
__pycache__/
*.pyc
```

## Security Considerations

- **HMAC key exposure:** Passing `-k` on the command line exposes the key in shell history. Use `--key-file` or the `FIM_KEY` environment variable instead.
- **Baseline rollback:** A signed baseline prevents content tampering, but an attacker with filesystem access could replace it with an older signed version. The audit log provides partial mitigation.
- **Symlinks:** Symbolic links inside the scan directory are skipped to prevent information disclosure.
- **CSV injection:** File paths starting with `=`, `+`, `-`, or `@` are sanitized in CSV output to prevent formula injection.

## Project Structure

```
file-integrity-monitor/
├── fim/
│   ├── __init__.py         # Package version
│   ├── __main__.py         # Entry point for `python -m fim`
│   ├── cli.py              # Command-line interface
│   ├── config.py           # Configuration loading and validation
│   ├── models.py           # Core data models
│   ├── hasher.py           # Cryptographic file hashing
│   ├── monitor.py          # Scanning and change detection
│   ├── reporter.py         # Output formatting (console, JSON, CSV, HTML)
│   ├── storage.py          # Baseline JSON persistence with HMAC signing
│   ├── crypto.py           # HMAC signing and verification
│   ├── audit.py            # Append-only audit logging
│   ├── rules.py            # Pattern-based file filtering
│   └── diff.py             # Unified diff preview generation
├── tests/                  # Comprehensive test suite (120+ tests)
├── .github/workflows/      # CI/CD with pytest, coverage, ruff, pip-audit
├── demo.py                 # Standalone demonstration script
├── pyproject.toml          # Project metadata and tool configuration
├── SECURITY.md             # Security policy and threat model
└── LICENSE                 # MIT License
```

## Development

### Running Tests

```powershell
python -m pytest tests\ -q
```

### Coverage

```powershell
python -m pytest --cov=fim --cov-report=term-missing --cov-branch tests
```

### Linting

```powershell
python -m ruff check .
```

### Demo

```powershell
python demo.py
```

## License

MIT License. See [LICENSE](LICENSE) for details.
