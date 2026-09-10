from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable

from models.results import DnsEnumerationResult, ScanReport


def save_report(
    targets: list[str],
    hosts: Iterable,
    duration_seconds: float,
    scanned_at: datetime,
    output_path: Path,
    dns_results: Iterable[DnsEnumerationResult] = (),
) -> list[Path]:
    report = ScanReport(
        targets=targets,
        scanned_at=scanned_at,
        duration_seconds=duration_seconds,
        hosts=list(hosts),
        dns_results=list(dns_results),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    suffix = output_path.suffix.lower()
    if suffix == ".json":
        return [_write_report_file(output_path, report.to_json())]

    if suffix == ".txt":
        return [_write_report_file(output_path, report.to_text())]

    json_path = _write_report_file(output_path.with_suffix(".json"), report.to_json())
    txt_path = _write_report_file(output_path.with_suffix(".txt"), report.to_text())
    return [json_path, txt_path]


def _write_report_file(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path
