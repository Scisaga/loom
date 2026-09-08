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
    "android.com",  # Official Android XML schema namespace.
    "anthropic.com",
    "apache.org",  # Apache-2.0 license text and upstream licensing reference.
    "baidu.com",
    "cloudflare.com",
    "docker.com",
    "github.com",
    "golang.org",
    "google.com",
    "gradle.org",  # Official Gradle wrapper distribution host.
    "gstatic.com",
    "gnu.org",  # GPL license text and canonical license reference.
    "ipify.org",
    "microsoft.com",  # Windows manifest schema namespaces.
    "oaistatic.com",
    "openai.com",
    "qq.com",  # Independent regional HTTPS endpoint used by Android TUN health checks.
    "sagernet.org",
    "signpath.io",  # Official release signing service.
    "signpath.org",  # Open-source signing foundation.
    "w3.org",
    "wireguard.com",
    "wintun.net",  # Official Wintun component download and license.
    "wixtoolset.org",  # WiX installer XML schema namespace.
    "zlib.com",
    "zx2c4.com",  # Upstream WireGuard source repository.
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
IPV6_NETWORK_LITERAL = re.compile(
    r"(?<![\w:./%\[\]@-])[0-9A-Fa-f:]+/[0-9]{1,3}(?![\w:./%\[\]@-])"
)


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


def broad_ipv6_network_spans(line: str) -> list[tuple[int, int]]:
    """Recognize standard/broad network literals, never host/URL fragments or IDs."""
    spans = []
    for match in IPV6_NETWORK_LITERAL.finditer(line):
        try:
            interface = ipaddress.IPv6Interface(match.group(0))
        except ValueError:
            continue
        # §12：只允许前 16 位非零且前缀不超过 16 位的宽网段；容纳边界测试的
        # 更宽掩码，但不豁免部署子网或含具体主机位的地址。
        if interface.network.prefixlen <= 16 and interface.ip.packed[2:] == bytes(14):
            spans.append(match.span())
    return spans


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
            # Manifest assembly versions have four parts but are not endpoints.
            ip_line = line
            if path.suffix == ".manifest":
                ip_line = re.sub(r'\bversion="[0-9]+(?:\.[0-9]+){3}"', "", line)
            for match in IPV4.finditer(ip_line):
                if not approved_ip(match.group(0)):
                    failures.append((relative, line_no, "unapproved public IPv4 address"))
            # Java/Kotlin package and import names commonly end in `.io` or
            # `.net`; they are identifiers, not deployment endpoints. String
            # literals cannot be part of these declarations, so skipping the
            # whole declaration does not weaken the endpoint boundary.
            domain_line = line
            if re.match(r"^\s*(?:package|import)\s+[A-Za-z0-9_.*]+\s*;?\s*$", line):
                domain_line = ""
            for match in DOMAIN.finditer(domain_line):
                value = match.group(0)
                followed_by_member = (
                    match.end() + 1 < len(domain_line)
                    and domain_line[match.end()] == "."
                    and domain_line[match.end() + 1].isupper()
                )
                inside_double_quotes = domain_line[:match.start()].count('"') % 2 == 1
                source_identifier = path.suffix in {".cs", ".go", ".java", ".kt", ".py"} and not inside_double_quotes
                android_component = "android:name=" in domain_line and followed_by_member
                if (source_identifier and any(character.isupper() for character in value)) or \
                        (followed_by_member and (source_identifier or android_component)):
                    continue
                if not approved_domain(value):
                    failures.append((relative, line_no, "unapproved public domain"))
            network_spans = broad_ipv6_network_spans(line)
            for match in SITE_LIKE_ID.finditer(line):
                in_network = any(start <= match.start() and match.end() <= end
                                 for start, end in network_spans)
                if match.group(0).lower() not in APPROVED_SITE_EXAMPLES and not in_network:
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
