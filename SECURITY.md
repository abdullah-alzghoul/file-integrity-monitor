# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Threat Model

This tool is designed for local file integrity monitoring on systems under your control. It is NOT designed to detect attacks from a privileged adversary with kernel-level access.

### What This Tool Protects Against

- Unauthorized file modifications by non-privileged users
- Accidental file changes
- Baseline tampering (via HMAC-signed baselines)

### What This Tool Does NOT Protect Against

- Kernel-level rootkits that intercept filesystem calls
- Attacks that modify the tool itself or its Python environment
- Rollback attacks where an attacker replaces the baseline with an older signed version
- Key extraction if the HMAC key is stored in plaintext on the same system

## Known Limitations

- **Baseline rollback:** An attacker with filesystem access can replace the baseline with an older signed copy. The audit log provides partial mitigation.
- **Audit log interleaving:** Multiple simultaneous CLI invocations may interleave JSON Lines in the audit log.
- **Windows ACLs:** `os.chmod` on Windows only affects the read-only flag, not full POSIX permissions.
- **Symlinks:** Symbolic links inside the scan directory are skipped to prevent information disclosure.

## Reporting a Vulnerability

Please report security vulnerabilities by opening a GitHub issue with the label `security`. Do not include exploit details in public issues; instead, provide a summary and request private disclosure.

## Responsible Use

This tool is intended for authorized file integrity monitoring only. Do not use it to monitor systems you do not own or have explicit permission to monitor.