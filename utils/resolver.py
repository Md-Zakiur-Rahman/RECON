from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket

from core.exceptions import ResolutionError


@dataclass(slots=True)
class TargetCandidate:
    target: str
    source: str
    from_cidr: bool = False


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)

    except socket.gaierror as e:
        raise ResolutionError(
            f"Failed to resolve target: {target}"
        ) from e


def expand_targets(targets: list[str]) -> list[TargetCandidate]:
    expanded_targets: list[TargetCandidate] = []
    seen_targets: set[str] = set()

    for target in targets:
        normalized_target = target.strip()
        if not normalized_target:
            continue

        if _is_cidr_range(normalized_target):
            for host in ipaddress.ip_network(normalized_target, strict=False).hosts():
                host_ip = str(host)
                if host_ip in seen_targets:
                    continue
                seen_targets.add(host_ip)
                expanded_targets.append(
                    TargetCandidate(
                        target=host_ip,
                        source=normalized_target,
                        from_cidr=True,
                    )
                )
            continue

        if normalized_target in seen_targets:
            continue

        seen_targets.add(normalized_target)
        expanded_targets.append(
            TargetCandidate(
                target=normalized_target,
                source=normalized_target,
            )
        )

    if not expanded_targets:
        raise ResolutionError("No valid targets provided.")

    return expanded_targets


def _is_cidr_range(target: str) -> bool:
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False

    return "/" in target
