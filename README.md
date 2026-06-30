# RECON

RECON (Reconnaissance, Enumeration and Connectivity Toolkit) is a safe Python-based reconnaissance project built to demonstrate networking fundamentals, service enumeration, banner grabbing, reporting, testing, and maintainable software design.

## Features

- Hostname to IPv4 resolution
- Single and multi-port TCP scanning
- Multithreaded scanning with `ThreadPoolExecutor`
- Common service identification
- Safe banner grabbing for open ports
- JSON and TXT report generation
- Verbose logging and graceful `Ctrl+C` handling
- Unit tests for core behavior

## Usage

```bash
python recon.py scan localhost --ports 22,80,443,8000-8002 --timeout 1.5 --save reports/localhost_scan --verbose
```

For a second controlled target, use a lab machine or a host you own on your local network:

```bash
python recon.py scan 192.168.1.10 --ports 22,80,443,3389 --save reports/lab_scan --verbose
```

## CLI Options

- `scan`: Run a TCP reconnaissance scan
- `target`: Hostname or IPv4 target
- `--ports`: Comma-separated ports and/or ranges
- `--timeout`: Socket timeout in seconds
- `--save`: Save report to `.json`, `.txt`, or both when no extension is provided
- `--verbose`: Enable debug logging

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

## Safety Scope

This project is intentionally limited to safe reconnaissance and enumeration. It does not perform vulnerability scanning, exploitation, brute forcing, malware behavior, packet injection, or OSINT collection.

## Testing

```bash
python -m unittest discover -s tests -v
```
