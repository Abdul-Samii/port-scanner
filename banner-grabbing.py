#!/usr/bin/env python3
"""
Banner grabber — identifies service versions on open ports.
"""

import socket
import re

# HTTP requires sending a request first — other protocols send
# the banner automatically on connect
HTTP_PROBE = b'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n'

def grab_banner(host, port, timeout=3):
    """
    Connect to host:port and read the initial banner.
    For HTTP/HTTPS sends a HEAD request to get the Server header.
    Returns the banner string or None.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = None

    try:
        s.connect((host, port))

        # HTTP needs a probe — all others respond automatically
        if port in (80, 8080, 8000, 8443):
            probe = HTTP_PROBE.replace(b'{host}', host.encode())
            s.send(probe)

        # recv() waits for data — 1024 bytes is enough for a banner
        raw = s.recv(1024)
        banner = raw.decode('utf-8', errors='ignore').strip()

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    finally:
        s.close()

    return banner

def parse_banner(port, banner):
    """
    Extract useful version info from a raw banner string.
    Returns a short summary string.
    """
    if not banner:
        return None

    # Keep only the first meaningful line
    first_line = banner.split('\n')[0].strip()

    # SSH:  SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
    if 'SSH' in first_line:
        m = re.search(r'SSH-[\d.]+-(\S+)', first_line)
        return f"SSH  {m.group(1) if m else first_line}"

    # FTP:  220 (vsFTPd 3.0.5)
    if first_line.startswith('220') and port == 21:
        return f"FTP  {first_line[4:]}"

    # SMTP: 220 mail.example.com ESMTP Postfix
    if first_line.startswith('220') and port == 25:
        return f"SMTP {first_line[4:]}"

    # HTTP: extract Server header from response
    m = re.search(r'Server:\s*(.+)', banner, re.IGNORECASE)
    if m:
        return f"HTTP Server: {m.group(1).strip()}"

    # Anything else — return cleaned first line
    return first_line[:80]

def scan_with_banners(host, ports=None, timeout=2, threads=50):
    """Full scan: check ports then grab banners on open ones."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Cannot resolve: {host}")
        return

    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443,
                 445, 993, 3306, 3389, 5432, 8080]

    print(f"\n  Target : {host} ({ip})")
    print(f"  Ports  : {len(ports)}")
    print(f"\n  {'PORT':<7} {'SERVICE':<12} {'BANNER / VERSION'}")
    print(f"  {'-'*58}")

    def probe(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            s.close()
            return port, True
        except:
            s.close()
            return port, False

    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for port, is_open in ex.map(lambda p: probe(p), ports):
            if is_open:
                open_ports.append(port)

    open_ports.sort()

    # Now grab banners on open ports
    for port in open_ports:
        banner  = grab_banner(ip, port, timeout)
        summary = parse_banner(port, banner) or '(no banner)'
        from socket import getservbyport
        try:
            svc = getservbyport(port)
        except:
            svc = 'unknown'
        print(f"  {port:<7} {svc:<12} {summary}")

    print()

# ── RUN ────────────────────────────────────────────────────────
if __name__ == '__main__':
    import sys
    target = 'localhost'
    scan_with_banners(target)