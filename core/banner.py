import socket

HTTP_BANNER_PORTS = {80, 8000, 8080}
TLS_PORTS = {443}
MAX_BANNER_LENGTH = 240


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str | None:
    if port in TLS_PORTS:
        return None

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            if port in HTTP_BANNER_PORTS:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

            data = sock.recv(1024)
            if not data:
                return None

            banner = _normalize_banner(data.decode("utf-8", errors="replace"))
            return banner or None
    except (socket.timeout, OSError):
        return None


def _normalize_banner(banner: str) -> str:
    normalized = " | ".join(line.strip() for line in banner.splitlines() if line.strip())
    if len(normalized) <= MAX_BANNER_LENGTH:
        return normalized

    return normalized[: MAX_BANNER_LENGTH - 3].rstrip() + "..."
