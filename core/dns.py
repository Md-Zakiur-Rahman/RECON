from __future__ import annotations

from datetime import datetime, timezone
import os
import random
import socket
import struct
import time
from typing import Iterable

from models.results import DnsEnumerationResult, ScanReport

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")
DNS_TYPE_CODES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}
DEFAULT_DNS_SERVER = "8.8.8.8"
DNS_PORT = 53
MAX_DNS_PACKET_SIZE = 4096


def enumerate_dns(target: str, timeout: float = 1.0) -> DnsEnumerationResult:
    """Collect common DNS records and reverse DNS names for a target."""

    result = DnsEnumerationResult(target=target)
    for record_type in DNS_RECORD_TYPES:
        try:
            values = query_dns(target, record_type, timeout)
        except (OSError, ValueError) as error:
            result.errors.append(f"{record_type}: {error}")
            continue
        if values:
            result.records[record_type] = values

    addresses = result.records.get("A", []) + result.records.get("AAAA", [])
    for address in addresses:
        try:
            names = reverse_dns(address, timeout)
        except OSError as error:
            result.errors.append(f"PTR {address}: {error}")
            continue
        if names:
            result.reverse_dns[address] = names

    return result


def enumerate_dns_targets(
    targets: Iterable[str],
    timeout: float = 1.0,
) -> ScanReport:
    """Enumerate DNS data for each target and return a report."""

    target_list = list(targets)
    started_at = time.monotonic()
    results = [enumerate_dns(target, timeout) for target in target_list]
    return ScanReport(
        targets=target_list,
        scanned_at=datetime.now(timezone.utc),
        duration_seconds=time.monotonic() - started_at,
        hosts=[],
        dns_results=results,
    )


def query_dns(target: str, record_type: str, timeout: float = 1.0) -> list[str]:
    """Query one DNS record type using a small UDP DNS client."""

    if record_type not in DNS_TYPE_CODES:
        raise ValueError(f"Unsupported DNS record type: {record_type}")

    transaction_id = random.randint(0, 65535)
    packet = _build_query(target, transaction_id, DNS_TYPE_CODES[record_type])
    server = os.environ.get("RECON_DNS_SERVER", DEFAULT_DNS_SERVER)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, DNS_PORT))
        response, _ = sock.recvfrom(MAX_DNS_PACKET_SIZE)

    return _parse_response(response, transaction_id, record_type)


def reverse_dns(address: str, timeout: float = 1.0) -> list[str]:
    """Return reverse DNS names for an IPv4 or IPv6 address."""

    del timeout
    try:
        hostname, aliases, _ = socket.gethostbyaddr(address)
    except (socket.gaierror, socket.herror) as error:
        raise OSError(f"Reverse lookup failed for {address}") from error

    return _unique_values([hostname, *aliases])


def _build_query(target: str, transaction_id: int, record_code: int) -> bytes:
    labels = target.rstrip(".").split(".")
    question = b"".join(bytes([len(label)]) + label.encode("idna") for label in labels)
    question += b"\x00" + struct.pack("!HH", record_code, 1)
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + question


def _parse_response(data: bytes, transaction_id: int, record_type: str) -> list[str]:
    if len(data) < 12:
        raise ValueError("DNS response is too short")

    response_id, flags, question_count, answer_count, _, _ = struct.unpack(
        "!HHHHHH", data[:12]
    )
    if response_id != transaction_id:
        raise ValueError("DNS response ID did not match request")
    if flags & 0x000F:
        return []

    offset = 12
    for _ in range(question_count):
        _, offset = _read_name(data, offset)
        offset += 4

    values: list[str] = []
    for _ in range(answer_count):
        _, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("DNS answer is truncated")
        answer_type, _, _, data_length = struct.unpack(
            "!HHIH", data[offset : offset + 10]
        )
        offset += 10
        rdata_offset = offset
        offset += data_length
        if offset > len(data):
            raise ValueError("DNS record data is truncated")
        if answer_type != DNS_TYPE_CODES[record_type]:
            continue
        values.append(_parse_record_data(data, rdata_offset, data_length, answer_type))

    return _unique_values(values)


def _parse_record_data(data: bytes, offset: int, length: int, record_type: int) -> str:
    record_data = data[offset : offset + length]
    if record_type == 1:
        return socket.inet_ntop(socket.AF_INET, record_data)
    if record_type == 28:
        return socket.inet_ntop(socket.AF_INET6, record_data)
    if record_type in {2, 5}:
        return _read_name(data, offset)[0]
    if record_type == 15:
        if length < 3:
            raise ValueError("MX record is truncated")
        return _read_name(data, offset + 2)[0]
    if record_type == 16:
        values: list[str] = []
        cursor = 0
        while cursor < len(record_data):
            text_length = record_data[cursor]
            cursor += 1
            values.append(
                record_data[cursor : cursor + text_length].decode("utf-8", "replace")
            )
            cursor += text_length
        return "".join(values)
    raise ValueError(f"Unsupported DNS record code: {record_type}")


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    original_offset = offset
    jumped = False
    while True:
        if offset >= len(data):
            raise ValueError("DNS name is truncated")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("DNS pointer is truncated")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            label, _ = _read_name(data, pointer)
            labels.append(label)
            offset += 2
            jumped = True
            break
        offset += 1
        end = offset + length
        if end > len(data):
            raise ValueError("DNS label is truncated")
        labels.append(data[offset:end].decode("idna", "replace"))
        offset = end
    next_offset = original_offset + 2 if jumped else offset
    return ".".join(labels), next_offset


def _unique_values(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
