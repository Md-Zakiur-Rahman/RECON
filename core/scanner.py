from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import time
from typing import Iterable

from core.banner import grab_banner
from core.exceptions import ResolutionError
from core.services import identify_service
from models.results import HostScanResult, PortScanResult, ScanReport
from utils.config import DEFAULT_MAX_WORKERS
from utils.resolver import TargetCandidate, expand_targets, resolve_target


def scan_port(
    ip: str,
    port: int,
    timeout: float = 1.0,
    delay: float = 0.0,
) -> bool:
    if delay > 0:
        time.sleep(delay)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((ip, port))
        except OSError:
            return False

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
    delay: float = 0.0,
    logger=None,
) -> list[PortScanResult]:
    port_list = sorted(set(ports))
    if not port_list:
        return []

    worker_count = min(max_workers, len(port_list))
    results: list[PortScanResult] = []
    progress_label = ip

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(scan_port_details, ip, port, timeout, delay): port
            for port in port_list
        }

        try:
            completed = 0
            total_ports = len(port_list)
            for future in as_completed(future_map):
                result = future.result()
                results.append(result)
                completed += 1
                if logger is not None and _should_log_progress(completed, total_ports):
                    logger.info(
                        "Progress %s: %s/%s ports checked",
                        progress_label,
                        completed,
                        total_ports,
                    )
        except KeyboardInterrupt:
            if logger is not None:
                logger.warning("Stopping worker threads...")
            for future in future_map:
                future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            raise

    return sorted(results, key=lambda item: item.port)


def scan_port_details(
    ip: str,
    port: int,
    timeout: float = 1.0,
    delay: float = 0.0,
) -> PortScanResult:
    is_open = scan_port(ip=ip, port=port, timeout=timeout, delay=delay)
    service_name = identify_service(port)
    banner = grab_banner(ip=ip, port=port, timeout=timeout) if is_open else None
    return PortScanResult(
        port=port,
        is_open=is_open,
        service_name=service_name,
        banner=banner,
    )


def scan_targets(
    targets: list[str],
    ports: Iterable[int],
    timeout: float = 1.0,
    max_workers: int = DEFAULT_MAX_WORKERS,
    delay: float = 0.0,
    logger=None,
) -> ScanReport:
    target_queue: Queue[TargetCandidate] = Queue()
    candidates = expand_targets(targets)
    for candidate in candidates:
        target_queue.put(candidate)

    if logger is not None:
        logger.info("Queued %s targets for scanning.", target_queue.qsize())

    host_results: list[HostScanResult] = []
    started_at = time.monotonic()
    total_targets = len(candidates)
    completed_targets = 0
    port_list = sorted(set(ports))

    while not target_queue.empty():
        candidate = target_queue.get()
        completed_targets += 1

        if logger is not None:
            logger.info(
                "Scanning target %s/%s: %s",
                completed_targets,
                total_targets,
                candidate.target,
            )

        host_result = scan_target(
            candidate=candidate,
            ports=port_list,
            timeout=timeout,
            max_workers=max_workers,
            delay=delay,
            logger=logger,
        )
        host_results.append(host_result)

        if logger is not None:
            logger.info(
                "Completed %s: alive=%s open_ports=%s",
                host_result.target,
                host_result.is_alive,
                host_result.open_port_count,
            )

    duration_seconds = time.monotonic() - started_at
    return ScanReport(
        targets=targets,
        scanned_at=time_to_utc_datetime(),
        duration_seconds=duration_seconds,
        hosts=host_results,
    )


def scan_target(
    candidate: TargetCandidate,
    ports: list[int],
    timeout: float,
    max_workers: int,
    delay: float,
    logger=None,
) -> HostScanResult:
    try:
        ip = resolve_target(candidate.target)
    except ResolutionError as error:
        if logger is not None:
            logger.warning("Skipping %s: %s", candidate.target, error)
        return HostScanResult(
            target=candidate.target,
            ip=None,
            is_alive=False,
            results=[],
            error=str(error),
        )

    if candidate.from_cidr and not discover_host(ip=ip, ports=ports, timeout=timeout, delay=delay):
        if logger is not None:
            logger.info("Skipping %s: no response during host discovery", candidate.target)
        return HostScanResult(
            target=candidate.target,
            ip=ip,
            is_alive=False,
            results=[],
            error="No response during host discovery.",
        )

    results = scan_ports(
        ip=ip,
        ports=ports,
        timeout=timeout,
        max_workers=max_workers,
        delay=delay,
        logger=logger,
    )
    is_alive = any(result.is_open for result in results)
    return HostScanResult(
        target=candidate.target,
        ip=ip,
        is_alive=is_alive,
        results=results,
    )


def discover_host(
    ip: str,
    ports: Iterable[int],
    timeout: float = 1.0,
    delay: float = 0.0,
) -> bool:
    discovery_ports = list(ports)[:10]
    for port in discovery_ports:
        if scan_port(ip=ip, port=port, timeout=timeout, delay=delay):
            return True
    return False


def time_to_utc_datetime():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


def _validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ValueError(f"Port out of range: {port}")


def _should_log_progress(completed: int, total: int) -> bool:
    if completed == total:
        return True

    interval = max(1, total // 4)
    return completed == 1 or completed % interval == 0
