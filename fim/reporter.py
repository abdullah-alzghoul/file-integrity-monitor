"""Output formatting for file integrity monitoring reports."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from fim.models import Change, ChangeType, ScanResult

__all__ = ["report"]


def _to_dict(obj):
    """Recursively convert dataclasses, enums, and paths to JSON-serializable types."""
    if obj is None:
        return None
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if is_dataclass(obj):
        return {f.name: _to_dict(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, list):
        return [_to_dict(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    return obj


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"


def _format_permissions(mode: int) -> str:
    return oct(mode)[-3:]


def _truncate_hash(hash_str: str, length: int = 16) -> str:
    if len(hash_str) <= length:
        return hash_str
    return hash_str[:length] + "..."


def _escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _console_report(result: ScanResult) -> str:
    lines = []
    lines.append("=" * 80)
    lines.append("File Integrity Monitor Report")
    lines.append("=" * 80)
    lines.append(f"Scan Path:     {result.scan_path}")
    lines.append(f"Baseline:      {result.baseline_path or 'None'}")
    lines.append(f"Timestamp:     {result.timestamp}")
    lines.append(f"Files Scanned: {result.files_scanned}")
    lines.append("")

    if not result.changes:
        lines.append("No changes detected.")
    else:
        lines.append(f"Changes Detected: {len(result.changes)}")
        lines.append("")

        for change in result.changes:
            ct = change.change_type
            record = change.record
            prev = change.previous_record

            if ct == ChangeType.ADDED:
                lines.append(f"  [ADDED]              {record.path if record else 'Unknown'}")
                if record:
                    lines.append(f"                       Size: {_format_size(record.size)} | Hash: {_truncate_hash(record.hash)}")

            elif ct == ChangeType.DELETED:
                lines.append(f"  [DELETED]            {prev.path if prev else 'Unknown'}")
                if prev:
                    lines.append(f"                       Was: {_format_size(prev.size)} | Hash: {_truncate_hash(prev.hash)}")

            elif ct == ChangeType.MODIFIED:
                lines.append(f"  [MODIFIED]           {record.path if record else 'Unknown'}")
                if record and prev:
                    lines.append(f"                       Size: {_format_size(prev.size)} -> {_format_size(record.size)}")
                    lines.append(f"                       Hash: {_truncate_hash(prev.hash)} -> {_truncate_hash(record.hash)}")
                if change.diff_preview:
                    lines.append("                       Diff preview:")
                    for diff_line in change.diff_preview.split("\n")[:5]:
                        lines.append(f"                         {diff_line}")
                    if len(change.diff_preview.split("\n")) > 5:
                        lines.append("                         ...")

            elif ct == ChangeType.MOVED:
                old_path = prev.path if prev else "Unknown"
                new_path = record.path if record else "Unknown"
                lines.append(f"  [MOVED]              {old_path} -> {new_path}")
                if record:
                    lines.append(f"                       Hash: {_truncate_hash(record.hash)} (unchanged)")

            elif ct == ChangeType.PERMISSION_CHANGED:
                lines.append(f"  [PERMISSION_CHANGED] {record.path if record else 'Unknown'}")
                if record and prev:
                    lines.append(f"                       Permissions: {_format_permissions(prev.permissions)} -> {_format_permissions(record.permissions)}")

            lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def _json_report(result: ScanResult) -> str:
    return json.dumps(_to_dict(result), indent=2)


def _csv_report(result: ScanResult) -> str:
    output = io.StringIO()
    fieldnames = [
        "timestamp", "scan_path", "baseline_path", "files_scanned",
        "change_type", "path", "hash", "size", "permissions", "mtime", "algorithm",
        "previous_path", "previous_hash", "previous_size", "previous_permissions",
        "previous_mtime", "previous_algorithm", "diff_preview",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for change in result.changes:
        record = change.record
        prev = change.previous_record

        row = {
            "timestamp": result.timestamp,
            "scan_path": result.scan_path,
            "baseline_path": result.baseline_path or "",
            "files_scanned": result.files_scanned,
            "change_type": change.change_type.value,
            "path": record.path if record else "",
            "hash": record.hash if record else "",
            "size": record.size if record else "",
            "permissions": record.permissions if record else "",
            "mtime": record.mtime if record else "",
            "algorithm": record.algorithm if record else "",
            "previous_path": prev.path if prev else "",
            "previous_hash": prev.hash if prev else "",
            "previous_size": prev.size if prev else "",
            "previous_permissions": prev.permissions if prev else "",
            "previous_mtime": prev.mtime if prev else "",
            "previous_algorithm": prev.algorithm if prev else "",
            "diff_preview": change.diff_preview or "",
        }
        writer.writerow(row)

    if not result.changes:
        writer.writerow({
            "timestamp": result.timestamp,
            "scan_path": result.scan_path,
            "baseline_path": result.baseline_path or "",
            "files_scanned": result.files_scanned,
            "change_type": "none",
        })

    return output.getvalue()


def _html_report(result: ScanResult) -> str:
    rows = []
    for change in result.changes:
        ct = change.change_type.value.upper()
        record = change.record
        prev = change.previous_record

        if change.change_type == ChangeType.ADDED:
            detail = f"Size: {_format_size(record.size)} | Hash: {_truncate_hash(record.hash)}"
        elif change.change_type == ChangeType.DELETED:
            detail = f"Was: {_format_size(prev.size)} | Hash: {_truncate_hash(prev.hash)}"
        elif change.change_type == ChangeType.MODIFIED:
            detail = f"Size: {_format_size(prev.size)} -> {_format_size(record.size)}<br>Hash: {_truncate_hash(prev.hash)} -> {_truncate_hash(record.hash)}"
        elif change.change_type == ChangeType.MOVED:
            detail = f"{_escape_html(prev.path)} -> {_escape_html(record.path)}<br>Hash: {_truncate_hash(record.hash)} (unchanged)"
        elif change.change_type == ChangeType.PERMISSION_CHANGED:
            detail = f"Permissions: {_format_permissions(prev.permissions)} -> {_format_permissions(record.permissions)}"
        else:
            detail = ""

        diff_html = ""
        if change.diff_preview:
            diff_escaped = _escape_html(change.diff_preview)
            diff_html = f"<pre>{diff_escaped}</pre>"

        path_display = _escape_html(record.path if record else (prev.path if prev else "N/A"))

        rows.append(f"""
        <tr>
            <td>{ct}</td>
            <td>{path_display}</td>
            <td>{detail}</td>
            <td>{diff_html}</td>
        </tr>
        """)

    if not result.changes:
        rows.append('<tr><td colspan="4">No changes detected.</td></tr>')

    changes_html = "\n".join(rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>File Integrity Monitor Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        pre {{ background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }}
        .meta {{ margin-bottom: 20px; }}
        .meta p {{ margin: 4px 0; }}
    </style>
</head>
<body>
    <h1>File Integrity Monitor Report</h1>
    <div class="meta">
        <p><strong>Scan Path:</strong> {_escape_html(result.scan_path)}</p>
        <p><strong>Baseline:</strong> {_escape_html(result.baseline_path or 'None')}</p>
        <p><strong>Timestamp:</strong> {_escape_html(result.timestamp)}</p>
        <p><strong>Files Scanned:</strong> {result.files_scanned}</p>
        <p><strong>Changes Detected:</strong> {len(result.changes)}</p>
    </div>
    <table>
        <thead>
            <tr>
                <th>Type</th>
                <th>Path</th>
                <th>Details</th>
                <th>Diff Preview</th>
            </tr>
        </thead>
        <tbody>
            {changes_html}
        </tbody>
    </table>
</body>
</html>"""


def report(result: ScanResult, format: str, output_path: Optional[str] = None) -> str:
    """Generate a report from a ScanResult.

    Supported formats: console, json, csv, html.
    If output_path is provided, the report is written to that file.
    Returns the report string.
    """
    if format == "console":
        content = _console_report(result)
    elif format == "json":
        content = _json_report(result)
    elif format == "csv":
        content = _csv_report(result)
    elif format == "html":
        content = _html_report(result)
    else:
        raise ValueError(f"unsupported format: {format}")

    if output_path is not None:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    return content