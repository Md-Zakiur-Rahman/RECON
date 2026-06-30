import socket

from core.exceptions import ResolutionError


def resolve_target(target: str) -> str:
    """
    Resolve a hostname or IP address to an IPv4 address.
    """

    try:
        return socket.gethostbyname(target)

    except socket.gaierror as e:
        raise ResolutionError(
            f"Failed to resolve target: {target}"
        ) from e