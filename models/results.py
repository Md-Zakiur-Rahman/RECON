from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import json


@dataclass(slots=True)
class PortScanResult:
    port: int
    is_open: bool
    service_name: str
    banner: str | None = None


@dataclass(slots=True)
class ScanReport:
    target: str
    ip: str
    scanned_at: datetime
    results: list[PortScanResult]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "ip": self.ip,
            "scanned_at": self.scanned_at.isoformat(),
            "results": [asdict(result) for result in self.results],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_text(self) -> str:
        lines = [
            f"Target: {self.target}",
            f"Resolved IP: {self.ip}",
            f"Scanned At (UTC): {self.scanned_at.isoformat()}",
            "",
            "Results:",
        ]

        for result in sorted(self.results, key=lambda item: item.port):
            state = "open" if result.is_open else "closed"
            line = f"- {result.port}/tcp {state} service={result.service_name}"
            if result.banner:
                line += f' banner="{result.banner}"'
            lines.append(line)

        return "\n".join(lines) + "\n"
