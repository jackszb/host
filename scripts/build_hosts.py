#!/usr/bin/env python3
"""Build hosts.json (sing-box domain_suffix ruleset) from the StevenBlack
hosts file.

Source:
  https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

Ignored line types (documented per project convention -- never silently
widen or narrow what a rule matches):
  - Comment lines ("#...") and blank lines.
  - Any line whose first token isn't the "0.0.0.0" or "127.0.0.1"
    blackhole address (e.g. IPv6 loopback/multicast lines are skipped).
  - Reserved / template hostnames that StevenBlack's file always includes
    for local-machine bookkeeping, not for blocking (see RESERVED below).
  - Scoped-ID addresses containing "%" (e.g. "fe80::1%lo0").
  - Any second token that doesn't look like a real domain name.

Output semantics note: sing-box's "domain_suffix" matches the domain
itself AND all of its subdomains. The hosts file only lists exact
domains, so this intentionally treats every extracted domain as blocking
its subdomains too -- the normal, expected behavior for an ad/tracker
blocklist. If that's ever unwanted, switch the output key to "domain"
instead of "domain_suffix".
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request

SOURCE_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
OUTPUT_PATH = "hosts.json"

RESERVED = {
    "0.0.0.0",
    "local",
    "localhost",
    "localhost.localdomain",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
}

BLACKHOLE_IPS = {"0.0.0.0", "127.0.0.1"}

DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "hosts-json-builder"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def extract_domains(text: str) -> list[str]:
    domains: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        ip, host = parts[0], parts[1].lower()
        if ip not in BLACKHOLE_IPS:
            continue
        if host in RESERVED:
            continue
        if "%" in host:
            continue
        if not DOMAIN_RE.match(host):
            continue

        domains.add(host)

    return sorted(domains)


def main() -> None:
    text = fetch(SOURCE_URL)
    domains = extract_domains(text)

    if not domains:
        print("No domains extracted -- aborting without writing output.", file=sys.stderr)
        sys.exit(1)

    output = {
        "version": 5,
        "rules": [
            {
                "domain_suffix": domains,
            }
        ],
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print(f"Wrote {len(domains)} domains to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
