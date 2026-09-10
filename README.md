# RECON

RECON is a small Python network enumeration tool for learning and portfolio work. It can scan a single host, a few targets, or a CIDR range while staying focused on safe information gathering.

## Features

- Hostname and IPv4 target resolution
- TCP port scanning
- Multiple target scanning
- CIDR subnet expansion
- Basic host discovery
- Service identification
- Banner grabbing on open ports
- JSON and TXT reports
- Configurable timeout, threads, and delay
- Unit tests
- DNS enumeration and reverse DNS

## Usage

```bash
python recon.py scan localhost
```

Common examples:

```bash
python recon.py scan 192.168.1.10 192.168.1.20 example.com --ports 22,80,443
python recon.py scan 192.168.1.0/24 --ports 22,80,443 --threads 100 --timeout 2
python recon.py scan scanme.nmap.org --ports 22,80,443 --save reports/scanme_test
python recon.py scan example.com --dns --save reports/example_dns
python recon.py scan google.com --dns --save reports/google_dns --timeout 2
python recon.py scan badssl.com --dns --save reports/badssl_dns --timeout 2
```

## CLI Options

- `scan`: run a scan
- `targets`: one or more hosts, IPs, or a CIDR range
- `--ports`: Comma-separated ports and ranges
- `--timeout`: Socket timeout in seconds
- `--threads`: Maximum worker threads per host
- `--delay`: Delay before each port probe
- `--save`: Save report to `.json`, `.txt`, or both when no extension is provided
- `--verbose`: Enable debug logging
- `--dns`: Enumerate A, AAAA, CNAME, MX, NS, TXT, and reverse DNS records

`scanme.nmap.org` and `badssl.com` are useful public testing targets. Only scan
systems you own or have permission to test.

## Project Structure

```text
RECON/
|-- recon.py
|-- core/
|-- models/
|-- utils/
|-- reports/
`-- tests/
```

## Scope

RECON is only for information gathering and enumeration. It does not do vulnerability scanning, exploitation, brute forcing, malware behavior, or packet-level attack work.

## Testing

```bash
python -m unittest discover -s tests
```
