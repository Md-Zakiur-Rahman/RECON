import argparse
from pathlib import Path

from core.dns import enumerate_dns_targets
from core.report import save_report
from core.scanner import parse_ports, scan_targets
from utils.config import (
    DEFAULT_MAX_WORKERS,
    DEFAULT_PORTS,
    DEFAULT_SCAN_DELAY,
    DEFAULT_TIMEOUT,
)
from utils.logger import setup_logger


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RECON - Reconnaissance, Enumeration and Connectivity Toolkit"
    )
    parser.add_argument("command", choices=["scan"], help="Command to run")
    parser.add_argument(
        "targets",
        nargs="+",
        help="One or more hostnames, IP addresses, or a CIDR range",
    )
    parser.add_argument(
        "--ports",
        default=DEFAULT_PORTS,
        help="Ports to scan, for example 22,80,443 or 1-1024",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Socket timeout in seconds",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help="Maximum concurrent port scan threads per host",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_SCAN_DELAY,
        help="Optional delay before each port probe in seconds",
    )
    parser.add_argument(
        "--save",
        help="Optional report output path without extension or with .json/.txt",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--dns",
        action="store_true",
        help="Enumerate DNS records and reverse DNS only",
    )
    return parser


def resolve_output_path(save_value: str | None) -> Path | None:
    if not save_value:
        return None

    return Path(save_value)


def log_dns_results(logger, report) -> None:
    for result in report.dns_results:
        logger.info("DNS result: %s", result.target)
        for record_type, values in result.records.items():
            logger.info("%s: %s", record_type, ", ".join(values))
        for address, names in result.reverse_dns.items():
            logger.info("PTR %s: %s", address, ", ".join(names))
        for error in result.errors:
            logger.warning("DNS lookup issue for %s: %s", result.target, error)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    logger = setup_logger(args.verbose)

    try:
        validate_scan_args(args)
        ports = parse_ports(args.ports)

        log_scan_start(logger, args)
        if args.dns:
            report = enumerate_dns_targets(args.targets, timeout=args.timeout)
            log_dns_results(logger, report)
        else:
            report = scan_targets(
                targets=args.targets,
                ports=ports,
                timeout=args.timeout,
                max_workers=args.threads,
                delay=args.delay,
                logger=logger,
            )

            for host in report.hosts:
                log_host_result(logger, host)

        log_scan_summary(logger, report)
        save_scan_report(args, report, logger)
    except ValueError as error:
        logger.error(str(error))
        raise SystemExit(1) from error
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
        raise SystemExit(130)


def validate_scan_args(args: argparse.Namespace) -> None:
    if args.timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")
    if args.threads <= 0:
        raise ValueError("Threads must be greater than 0.")
    if args.delay < 0:
        raise ValueError("Delay cannot be negative.")


def log_scan_start(logger, args: argparse.Namespace) -> None:
    logger.info("Starting scan")
    logger.info("Targets: %s", ", ".join(args.targets))
    logger.info(
        "Ports: %s | Threads: %s | Timeout: %.2fs | Delay: %.2fs",
        args.ports,
        args.threads,
        args.timeout,
        args.delay,
    )


def log_host_result(logger, host) -> None:
    status = "alive" if host.is_alive else "unresponsive"
    ip_value = host.ip if host.ip is not None else "unresolved"

    logger.info("")
    logger.info("Host: %s (%s)", host.target, ip_value)
    logger.info("Status: %s | Open ports: %s", status, host.open_port_count)

    if host.error:
        logger.warning("Note: %s", host.error)

    for result in host.results:
        if result.is_open:
            message = f"  {result.port}/tcp open {result.service_name}"
            if result.banner:
                message += f' | banner="{result.banner}"'
            logger.info(message)
        else:
            logger.debug("  %s/tcp closed", result.port)


def log_scan_summary(logger, report) -> None:
    logger.info("")
    logger.info(
        "Summary: scanned=%s alive=%s unresponsive=%s open=%s closed=%s duration=%.2fs avg_open_alive=%.2f",
        report.summary.total_hosts_scanned,
        report.summary.total_hosts_alive,
        report.summary.total_hosts_unresponsive,
        report.summary.total_open_ports,
        report.summary.total_closed_ports,
        report.duration_seconds,
        report.summary.average_open_ports_per_alive_host,
    )


def save_scan_report(args: argparse.Namespace, report, logger) -> None:
    output_path = resolve_output_path(args.save)
    if output_path is None:
        return

    try:
        saved_files = save_report(
            targets=args.targets,
            hosts=report.hosts,
            duration_seconds=report.duration_seconds,
            scanned_at=report.scanned_at,
            output_path=output_path,
            dns_results=report.dns_results,
        )
    except OSError as error:
        logger.error("Failed to save report: %s", error)
        raise SystemExit(1) from error

    logger.info("Saved reports: %s", ", ".join(str(path) for path in saved_files))


if __name__ == "__main__":
    main()
