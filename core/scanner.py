from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

from core.banner import grab_banner
from core.services import identify_service
from models.results import PortScanResult
from utils.config import DEFAULT_MAX_WORKERS


def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Returns True if port is open.
    Returns False if port is closed.
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)

        result = sock.connect_ex((ip, port))

        return result == 0


def parse_ports(ports_value: str) -> list[int]:
    ports: set[int] = set()

    for chunk in ports_value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue

        if "-" in chunk:
            start_text, end_text = chunk.split("-", maxsplit=1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                raise ValueError(f"Invalid port range: {chunk}")
            for port in range(start, end + 1):
                _validate_port(port)
                ports.add(port)
            continue

        port = int(chunk)
        _validate_port(port)
        ports.add(port)

    if not ports:
        raise ValueError("No valid ports provided.")

    return sorted(ports)


def scan_ports(
    ip: str,
    ports: Iterable[int],
    timeout: float = 1.0,
    max_workers: int = DEFAULT_MAX_WORKERS,
    logger=None,
) -> list[PortScanResult]:
    port_list = sorted(set(ports))
    if not port_list:
        return []

    worker_count = min(max_workers, len(port_list))
    results: list[PortScanResult] = []

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(scan_port_details, ip, port, timeout): port for port in port_list
        }

        try:
            for future in as_completed(future_map):
                result = future.result()
                results.append(result)
        except KeyboardInterrupt:
            if logger is not None:
                logger.warning("Stopping worker threads...")
            for future in future_map:
                future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            raise

    return sorted(results, key=lambda item: item.port)


def scan_port_details(ip: str, port: int, timeout: float = 1.0) -> PortScanResult:
    is_open = scan_port(ip=ip, port=port, timeout=timeout)
    service_name = identify_service(port)
    banner = grab_banner(ip=ip, port=port, timeout=timeout) if is_open else None
    return PortScanResult(
        port=port,
        is_open=is_open,
        service_name=service_name,
        banner=banner,
    )


def _validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ValueError(f"Port out of range: {port}")
