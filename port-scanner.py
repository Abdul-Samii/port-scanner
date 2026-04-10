#!/usr/bin/env python3
"""
TCP port scanner — educational/defensive use
Scan your own systems or authorised targets only
"""

import socket
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── COMMON PORTS WITH SERVICE NAMES ───────────────────────────
COMMON_PORTS = {
    21:   'FTP',
    22:   'SSH',
    23:   'Telnet',
    25:   'SMTP',
    53:   'DNS',
    80:   'HTTP',
    110:  'POP3',
    143:  'IMAP',
    443:  'HTTPS',
    445:  'SMB',
    993:  'IMAPS',
    995:  'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017:'MongoDB',
}

def check_port(host, port, timeout=1):
    """
    Try to connect to host:port.
    Returns (port, True, service) if open, (port, False, '') if closed.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        service = COMMON_PORTS.get(port, 'unknown')
        return (port, True, service)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return (port, False, '')
    finally:
        s.close()

def scan(host, ports=None, timeout=1, threads=100):
    """
    Scan a host for open ports.
    Uses a thread pool so multiple ports are checked simultaneously.
    """
    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Cannot resolve host: {host}")
        sys.exit(1)

    if ports is None:
        ports = list(COMMON_PORTS.keys())   # scan common ports only

    print(f"\nScanning {host} ({ip})")
    print(f"Ports: {len(ports)}   Threads: {threads}")
    print(f"Started: {datetime.now():%H:%M:%S}")
    print('-' * 50)

    open_ports = []

    # ThreadPoolExecutor runs check_port() on many ports in parallel
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_port, ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))

    open_ports.sort()       # show in ascending port order

    if open_ports:
        print(f"{'PORT':<8} {'STATE':<10} {'SERVICE'}")
        for port, service in open_ports:
            print(f"{port:<8} {'open':<10} {service}")
    else:
        print("No open ports found.")

    print(f"\nDone: {datetime.now():%H:%M:%S}")
    return open_ports

# ── USAGE ──────────────────────────────────────────────────────
if __name__ == '__main__':
    target = "localhost"
    print(f"Scanning target: {target}")
    scan(target)