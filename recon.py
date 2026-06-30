import argparse
from pathlib import Path

from core.exceptions import ResolutionError
from core.report import save_report
from core.scanner import parse_ports, scan_ports
from utils.config import DEFAULT_PORTS, DEFAULT_TIMEOUT
from utils.logger import setup_logger
from utils.resolver import resolve_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RECON - Reconnaissance, Enumeration and Connectivity Toolkit"
    )
    parser.add_argument("command", choices=["scan"], help="Command to execute")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "--ports",
        default=DEFAULT_PORTS,
        help="Ports to scan, for example: 22,80,443 or 1-1024",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Socket timeout in seconds",
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
    return parser


def resolve_output_path(save_value: str | None) -> Path | None:
    if not save_value:
        return None

    return Path(save_value)


def main():
    parser = build_parser()
    args = parser.parse_args()
    logger = setup_logger(args.verbose)

    try:
        ip = resolve_target(args.target)
        ports = parse_ports(args.ports)

        logger.info(f"Target: {args.target}")
        logger.info(f"Resolved IP: {ip}")
        results = scan_ports(ip=ip, ports=ports, timeout=args.timeout, logger=logger)

        for result in results:
            state = "open" if result.is_open else "closed"
            if result.is_open:
                message = (
                    f"Port {result.port}/tcp {state}"
                    f" service={result.service_name}"
                )
                if result.banner:
                    message += f' banner="{result.banner}"'
                logger.info(message)
            else:
                logger.debug(f"Port {result.port}/tcp {state}")

        output_path = resolve_output_path(args.save)
        if output_path is not None:
            saved_files = save_report(
                target=args.target,
                ip=ip,
                results=results,
                output_path=output_path,
            )
            logger.info(f"Saved reports: {', '.join(str(path) for path in saved_files)}")

    except ResolutionError as e:
        logger.error(str(e))
        raise SystemExit(1) from e
    except ValueError as e:
        logger.error(str(e))
        raise SystemExit(1) from e
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
