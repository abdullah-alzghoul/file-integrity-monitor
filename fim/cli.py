"""Command-line interface for the file integrity monitor."""

from __future__ import annotations

import argparse
import sys

from fim.audit import AuditLogger
from fim.config import load_config
from fim.monitor import create_baseline, scan_directory
from fim.reporter import report
from fim.rules import RuleSet, load_rules

__all__ = ["main", "run"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="File Integrity Monitor — detect unauthorized file changes.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # baseline subcommand
    baseline_parser = subparsers.add_parser("baseline", help="Create a new baseline")
    baseline_parser.add_argument(
        "scan_path", nargs="?", default=".", help="Directory to scan (default: .)"
    )
    baseline_parser.add_argument(
        "-o", "--output", required=True, help="Baseline output file path"
    )
    baseline_parser.add_argument(
        "-a", "--algorithm", choices=["sha256", "sha512"], help="Hash algorithm"
    )
    baseline_parser.add_argument(
        "-t", "--threads", type=int, help="Number of parallel threads"
    )
    baseline_parser.add_argument(
        "-k", "--key", help="HMAC signing key (exposes key in shell history; prefer --key-file or FIM_KEY)"
    )
    baseline_parser.add_argument(
        "--key-file", help="Path to file containing HMAC signing key"
    )
    baseline_parser.add_argument(
        "-r", "--rules", help="Path to exclude rules file"
    )
    baseline_parser.add_argument(
        "--config", help="Path to JSON config file"
    )
    baseline_parser.add_argument(
        "--audit-log", help="Path to audit log file"
    )

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan directory against baseline")
    scan_parser.add_argument(
        "scan_path", nargs="?", default=".", help="Directory to scan (default: .)"
    )
    scan_parser.add_argument(
        "-b", "--baseline", required=True, help="Baseline file path"
    )
    scan_parser.add_argument(
        "-f", "--format", choices=["console", "json", "csv", "html"], help="Output format"
    )
    scan_parser.add_argument(
        "-o", "--output", help="Report output file path"
    )
    scan_parser.add_argument(
        "-a", "--algorithm", choices=["sha256", "sha512"], help="Hash algorithm"
    )
    scan_parser.add_argument(
        "-t", "--threads", type=int, help="Number of parallel threads"
    )
    scan_parser.add_argument(
        "-k", "--key", help="HMAC verification key (exposes key in shell history; prefer --key-file or FIM_KEY)"
    )
    scan_parser.add_argument(
        "--key-file", help="Path to file containing HMAC verification key"
    )
    scan_parser.add_argument(
        "-r", "--rules", help="Path to exclude rules file"
    )
    scan_parser.add_argument(
        "--config", help="Path to JSON config file"
    )
    scan_parser.add_argument(
        "--audit-log", help="Path to audit log file"
    )

    return parser


def _config_from_args(args) -> dict:
    """Map argparse Namespace to load_config kwargs.

    Only includes values that were explicitly provided (not None).
    """
    mapping = {
        "scan_path": "scan_path",
        "baseline": "baseline_path",
        "output": "output_path",
        "format": "format",
        "algorithm": "algorithm",
        "threads": "threads",
        "key": "key",
        "key_file": "key",
        "rules": "rules_path",
        "config": "config_path",
        "audit_log": "audit_log",
    }
    return {
        v: getattr(args, k)
        for k, v in mapping.items()
        if hasattr(args, k) and getattr(args, k) is not None
    }


def run(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    config_kwargs = _config_from_args(args)
    config = load_config(**config_kwargs)
    rules = load_rules(config.rules_path)
    if config.exclude:
        inline = RuleSet(config.exclude)
        combined = list(dict.fromkeys(inline.excludes + rules.excludes))
        rules = RuleSet(combined)
    audit = AuditLogger(config.audit_log)

    if hasattr(args, "key") and args.key is not None:
        print("Warning: passing keys via -k exposes them in shell history. Consider --key-file or FIM_KEY.", file=sys.stderr)

    try:
        if args.command == "baseline":
            create_baseline(
                scan_path=args.scan_path,
                baseline_path=args.output,
                rules=rules,
                algorithm=config.algorithm,
                threads=config.threads,
                key=config.key,
                audit_logger=audit,
            )
            print(f"Baseline created: {args.output}")
            return 0

        elif args.command == "scan":
            result = scan_directory(
                scan_path=args.scan_path,
                baseline_path=args.baseline,
                rules=rules,
                algorithm=config.algorithm,
                threads=config.threads,
                key=config.key,
                audit_logger=audit,
            )
            report(result, config.format, output_path=config.output_path)
            return 1 if result.changes else 0

    except (FileNotFoundError, NotADirectoryError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 2


def main() -> None:
    sys.exit(run())
