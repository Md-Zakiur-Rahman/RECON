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
    targets: list[str]
    scanned_at: datetime
    duration_seconds: float
    hosts: list["HostScanResult"]

    def to_dict(self) -> dict:
        return {
            "targets": self.targets,
            "scanned_at": self.scanned_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "summary": self.summary.to_dict(),
            "hosts": [host.to_dict() for host in self.hosts],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_text(self) -> str:
        summary = self.summary
        lines = [
            "RECON Scan Report",
            f"Targets: {', '.join(self.targets)}",
            f"Scanned At (UTC): {self.scanned_at.isoformat()}",
            f"Duration (seconds): {self.duration_seconds:.2f}",
            f"Hosts Scanned: {summary.total_hosts_scanned}",
            f"Hosts Alive: {summary.total_hosts_alive}",
            f"Hosts Unresponsive: {summary.total_hosts_unresponsive}",
            f"Total Open Ports: {summary.total_open_ports}",
            f"Total Closed Ports: {summary.total_closed_ports}",
            f"Average Open Ports Per Alive Host: {summary.average_open_ports_per_alive_host:.2f}",
            "",
            "Hosts:",
        ]

        for host in self.hosts:
            status = "alive" if host.is_alive else "unresponsive"
            host_ip = host.ip if host.ip is not None else "unresolved"
            lines.append("")
            lines.append(f"{host.target} ({host_ip})")
            lines.append(f"  Status: {status}")
            lines.append(f"  Open Ports: {host.open_port_count}")

            if host.error:
                lines.append(f"  Error: {host.error}")

            for result in sorted(host.results, key=lambda item: item.port):
                state = "open" if result.is_open else "closed"
                line = f"  - {result.port}/tcp {state} service={result.service_name}"
                if result.banner:
                    line += f' banner="{result.banner}"'
                lines.append(line)

        return "\n".join(lines) + "\n"

    @property
    def summary(self) -> "ScanSummary":
        total_hosts_scanned = len(self.hosts)
        total_hosts_alive = sum(1 for host in self.hosts if host.is_alive)
        total_open_ports = sum(getattr(host, "open_port_count", 0) for host in self.hosts)
        total_closed_ports = sum(getattr(host, "closed_port_count", 0) for host in self.hosts)
        total_hosts_unresponsive = total_hosts_scanned - total_hosts_alive
        average_open_ports = (
            total_open_ports / total_hosts_alive if total_hosts_alive else 0.0
        )
        return ScanSummary(
            total_hosts_scanned=total_hosts_scanned,
            total_hosts_alive=total_hosts_alive,
            total_hosts_unresponsive=total_hosts_unresponsive,
            total_open_ports=total_open_ports,
            total_closed_ports=total_closed_ports,
            average_open_ports_per_alive_host=average_open_ports,
        )


@dataclass(slots=True)
class HostScanResult:
    target: str
    ip: str | None
    is_alive: bool
    results: list[PortScanResult]
    error: str | None = None

    @property
    def open_port_count(self) -> int:
        return sum(1 for result in self.results if result.is_open)

    @property
    def closed_port_count(self) -> int:
        return sum(1 for result in self.results if not result.is_open)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "ip": self.ip,
            "is_alive": self.is_alive,
            "open_port_count": self.open_port_count,
            "closed_port_count": self.closed_port_count,
            "error": self.error,
            "results": [asdict(result) for result in self.results],
        }


@dataclass(slots=True)
class ScanSummary:
    total_hosts_scanned: int
    total_hosts_alive: int
    total_hosts_unresponsive: int
    total_open_ports: int
    total_closed_ports: int
    average_open_ports_per_alive_host: float

    def to_dict(self) -> dict:
        return asdict(self)
