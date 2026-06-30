from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from models.results import ScanReport


def save_report(
    target: str,
    ip: str,
    results,
    output_path: Path,
) -> list[Path]:
    report = ScanReport(
        target=target,
        ip=ip,
        scanned_at=datetime.now(timezone.utc),
        results=list(results),
    )

    if output_path.suffix.lower() == ".json":
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report.to_json(), encoding="utf-8")
        return [output_path]

    if output_path.suffix.lower() == ".txt":
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report.to_text(), encoding="utf-8")
        return [output_path]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    json_path = output_path.with_suffix(".json")
    txt_path = output_path.with_suffix(".txt")
    json_path.write_text(report.to_json(), encoding="utf-8")
    txt_path.write_text(report.to_text(), encoding="utf-8")
    return [json_path, txt_path]
