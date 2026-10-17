#!/usr/bin/env python3
"""PortSpy - a fast, dependency-free TCP port scanner.

Only scan systems you own or have explicit written permission to test.
"""
import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

__version__ = "0.2.0"

# Used by --fast
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443,
]
HTTP_PORTS = {80, 8000, 8008, 8080, 8888}


def parse_ports(spec):
    """Turn '22,80,100-200' into a sorted list of port numbers."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    valid = sorted(p for p in ports if 1 <= p <= 65535)
    if not valid:
        raise ValueError("no valid ports in range 1-65535")
    return valid


def service_name(port):
    """Look up the standard service name for a port."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def clean(text):
    """Keep the first line only, and only printable characters."""
    lines = text.splitlines()
    first = lines[0] if lines else ""
    return "".join(ch for ch in first if ch.isprintable()).strip()[:70]


def grab_banner(sock, host, port):
    """Try to read a short banner from an open port."""
    try:
        sock.settimeout(1.0)
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            reply = sock.recv(1024).decode(errors="ignore")
            for line in reply.splitlines():
                if line.lower().startswith("server:"):
                    return clean(line[7:])
            return clean(reply)
        return clean(sock.recv(256).decode(errors="ignore"))
    except OSError:
        return ""


def scan_port(host, port, timeout):
    """Return a result dict if the port is open, otherwise None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return {
                "port": port,
                "service": service_name(port),
                "banner": grab_banner(s, host, port),
            }
    except OSError:
        return None


def build_parser():
    ap = argparse.ArgumentParser(
        prog="portspy",
        description="A fast, dependency-free TCP port scanner. "
                    "Only scan systems you own or have permission to test.",
    )
    ap.add_argument("target", nargs="?", default="127.0.0.1",
                    help="IP address or hostname (default: 127.0.0.1)")
    ap.add_argument("-p", "--ports", default="1-1024",
                    help="ports to scan, e.g. 1-1024 or 22,80,443 (default: 1-1024)")
    ap.add_argument("-F", "--fast", action="store_true",
                    help="scan only the most common ports")
    ap.add_argument("-t", "--timeout", type=float, default=0.5,
                    help="connection timeout in seconds (default: 0.5)")
    ap.add_argument("-w", "--workers", type=int, default=200,
                    help="number of parallel threads (default: 200)")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="save results to a JSON file")
    ap.add_argument("-V", "--version", action="version", version=f"PortSpy {__version__}")
    return ap


def main():
    args = build_parser().parse_args()

    try:
        ports = COMMON_PORTS if args.fast else parse_ports(args.ports)
    except ValueError as e:
        sys.exit(f"Invalid port specification: {e}")

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        sys.exit(f"Could not resolve host: {args.target}")

    print(f"PortSpy {__version__} - only scan systems you are allowed to test.")
    print(f"Scanning {args.target} ({ip}), {len(ports)} ports...\n")
    start = time.time()

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = pool.map(lambda p: scan_port(ip, p, args.timeout), ports)
            open_ports = [r for r in results if r]
    except KeyboardInterrupt:
        sys.exit("\nScan cancelled.")

    duration = time.time() - start

    if open_ports:
        print(f"{'PORT':<10}{'STATE':<8}{'SERVICE':<14}BANNER")
        for r in open_ports:
            print(f"{str(r['port']) + '/tcp':<10}{'open':<8}{r['service']:<14}{r['banner']}")
    else:
        print("No open ports found.")

    print(f"\nDone: {len(open_ports)} open port(s) in {duration:.1f}s.")

    if args.output:
        report = {
            "target": args.target,
            "ip": ip,
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_seconds": round(duration, 2),
            "ports_scanned": len(ports),
            "open_ports": open_ports,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
