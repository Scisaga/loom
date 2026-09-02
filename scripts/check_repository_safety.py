#!/usr/bin/env python3
"""Reject credentials and deployment metadata from tracked repository files.

This check deliberately reports only the category and location of a match. It
never prints a suspected secret or endpoint value into CI logs.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]

SECRET_PATTERNS = {
    "private key": re.compile(
        rb"-----BEGIN " rb"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    "AWS access key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "GitHub token": re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),
    "Slack token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "Enrollment invitation": re.compile(
        rb"loom://enroll" rb"#[A-Za-z0-9_-]{20,}"
    ),
    "credentialed URL": re.compile(rb"https?://[^/@\s]+:[^/@\s]+@"),
}

IPV4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
APPROVED_PUBLIC_IPS = {
    "1.1.1.1",       # Cloudflare DNS, used as an explicit resolver example.
    "8.8.4.4",       # Google DNS, used by resolver tests.
    "8.8.8.8",       # Google DNS, used by resolver tests and design notes.
    "9.9.9.9",       # Quad9 DNS, used by resolver tests.
    "119.29.29.29",  # DNSPod resolver explicitly selected by example SSOT.
    "140.82.112.0",  # Published GitHub service range used in a UI example.
    "223.5.5.5",     # AliDNS resolver explicitly selected by example SSOT.
}

DOMAIN = re.compile(
    r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9-]+\.)+"
    r"(?:cc|cn|com|dev|io|net|org)(?![A-Za-z0-9-])",
    re.IGNORECASE,
)
APPROVED_DOMAIN_BASES = {
    "aliyun.com",
    "baidu.com",
    "docker.com",
    "github.com",
    "golang.org",
    "google.com",
    "gstatic.com",
    "ipify.org",
    "oaistatic.com",
    "openai.com",
    "sagernet.org",
    "w3.org",
    "wireguard.com",
    "zlib.com",
}
EXAMPLE_DOMAIN_SUFFIXES = (
    ".example",
    ".example.com",
    ".example.net",
    ".example.org",
)

SITE_LIKE_ID = re.compile(
    r"(?<![A-Za-z0-9-])[a-z]{2}[0-9]{2}(?![A-Za-z0-9-])", re.IGNORECASE
)
APPROVED_SITE_EXAMPLES = {"gw01", "sh01"}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    paths = [ROOT / value.decode() for value in result.stdout.split(b"\0") if value]
    # Include this new checker before its first commit as well as after it is tracked.
    checker = Path(__file__).resolve()
    if checker not in paths:
        paths.append(checker)
    return paths


def approved_domain(value: str) -> bool:
    value = value.lower().lstrip(".")
    if value in {"example.com", "example.net", "example.org"}:
        return True
    if value.endswith(EXAMPLE_DOMAIN_SUFFIXES):
        return True
    return any(value == base or value.endswith("." + base) for base in APPROVED_DOMAIN_BASES)


def approved_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        # Invalid addresses belong to validation tests and cannot identify a host.
        return True
    if any(address in network for network in DOCUMENTATION_NETWORKS):
        return True
    if not address.is_global:
        return True
    return value in APPROVED_PUBLIC_IPS


def line_number(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, offset) + 1


def main() -> int:
    failures: list[tuple[str, int, str]] = []
    for path in tracked_files():
        if not path.is_file() or path.stat().st_size > 5_000_000:
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        relative = path.relative_to(ROOT).as_posix()

        for category, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(data):
                failures.append((relative, line_number(data, match.start()), category))

        text = data.decode("utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), 1):
            for match in IPV4.finditer(line):
                if not approved_ip(match.group(0)):
                    failures.append((relative, line_no, "unapproved public IPv4 address"))
            for match in DOMAIN.finditer(line):
                if not approved_domain(match.group(0)):
                    failures.append((relative, line_no, "unapproved public domain"))
            for match in SITE_LIKE_ID.finditer(line):
                if match.group(0).lower() not in APPROVED_SITE_EXAMPLES:
                    failures.append((relative, line_no, "site-like device identifier"))

    if not failures:
        print("repository safety check passed")
        return 0

    print("repository safety check failed:", file=sys.stderr)
    for path, line, category in sorted(set(failures)):
        print(f"  {path}:{line}: {category}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
