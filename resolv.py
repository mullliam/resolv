#!/usr/bin/env python3

"""
resolv.py

Resolve a hostname, follow any CNAME chain, retrieve all A records,
perform PTR lookups on each IP, run WHOIS lookups, and group IPs that
share the same WHOIS information.

For direct IP input, perform PTR and WHOIS lookups only.

WHOIS fields extracted (adaptive):
    - OrgName
    - Organization
    - owner
    - org-name
    - org
    - descr
    - netname
    - route
    - origin
    - OriginAS
    - CIDR
    - country

Requirements:
    - Python 3
    - dig command available
    - whois command available

Usage:
    ./resolv.py <hostname_or_ip>
"""

import ipaddress
import shutil
import subprocess
import sys
import textwrap
from collections import defaultdict

WHOIS_COLUMN_DEFS = (
    ("OrgName", ("orgname",)),
    ("Organization", ("organization",)),
    ("owner", ("owner",)),
    ("org-name", ("org-name",)),
    ("org", ("org",)),
    ("descr", ("descr",)),
    ("netname", ("netname",)),
    ("route", ("route",)),
    ("origin", ("origin",)),
    ("OriginAS", ("originas", "origin-as")),
    ("CIDR", ("cidr",)),
    ("country", ("country",)),
)

WHOIS_HEADERS = tuple(label for label, _ in WHOIS_COLUMN_DEFS)


def normalize_whois_key(key):
    """Normalize WHOIS keys for matching across registry formats."""
    return "".join(ch for ch in key.lower() if ch.isalnum())


def run_dig(*args):
    """Run dig command and return cleaned output lines."""
    result = subprocess.run(
        ["dig", "+short", *args],
        capture_output=True,
        text=True,
        check=False,
    )

    return [
        line.rstrip(".")
        for line in result.stdout.strip().splitlines()
        if line.strip()
    ]


def resolve_cname_chain(hostname):
    """Follow CNAME chain until final hostname."""
    current = hostname
    chain = []

    while True:
        cname = run_dig(current, "CNAME")

        if not cname:
            break

        target = cname[0]
        chain.append(f"{current} -> {target}")
        current = target

    return chain, current


def get_a_records(hostname):
    """Return all A records."""
    return run_dig(hostname, "A")


def get_ptr(ip):
    """Return PTR record."""
    ptr = run_dig("-x", ip)
    return ptr[0] if ptr else "No PTR Record"


def get_whois(ip):
    """Run whois and extract desired fields."""
    result = subprocess.run(
        ["whois", ip],
        capture_output=True,
        text=True,
        check=False,
    )

    alias_to_label = {}

    for label, aliases in WHOIS_COLUMN_DEFS:
        for alias in aliases:
            alias_to_label[normalize_whois_key(alias)] = label

    values = {field: "" for field in WHOIS_HEADERS}

    for line in result.stdout.splitlines():
        line = line.strip()

        if ":" not in line:
            continue

        raw_key, raw_value = line.split(":", 1)
        normalized_key = normalize_whois_key(raw_key)
        label = alias_to_label.get(normalized_key)

        if not label:
            continue

        value = raw_value.strip()

        # Keep first occurrence
        if value and not values[label]:
            values[label] = value

    return values


def build_rows(hostname):
    """Build grouped output rows."""
    cname_chain, final_host = resolve_cname_chain(hostname)
    ips = get_a_records(final_host)

    grouped = defaultdict(
        lambda: {
            "ips": [],
            "ptrs": [],
        }
    )

    for ip in ips:
        ptr = get_ptr(ip)
        whois = get_whois(ip)

        key = tuple(whois[field] for field in WHOIS_HEADERS)

        grouped[key]["ips"].append(ip)
        grouped[key]["ptrs"].append(ptr)

    active_whois_fields = [
        field
        for idx, field in enumerate(WHOIS_HEADERS)
        if any(key[idx] for key in grouped)
    ]
    field_index = {field: idx for idx, field in enumerate(WHOIS_HEADERS)}

    rows = []

    for key, data in grouped.items():
        row = []

        if cname_chain:
            row.append(" ; ".join(cname_chain))

        row.extend([
            ", ".join(data["ips"]),
            ", ".join(data["ptrs"]),
        ])

        row.extend(key[field_index[field]] for field in active_whois_fields)

        rows.append(row)

    return cname_chain, active_whois_fields, rows


def build_rows_for_ip(ip):
    """Build output rows for direct IP lookup (PTR + WHOIS only)."""
    ptr = get_ptr(ip)
    whois = get_whois(ip)

    key = tuple(whois[field] for field in WHOIS_HEADERS)

    active_whois_fields = [
        field
        for idx, field in enumerate(WHOIS_HEADERS)
        if key[idx]
    ]
    field_index = {field: idx for idx, field in enumerate(WHOIS_HEADERS)}

    row = [ip, ptr]
    row.extend(key[field_index[field]] for field in active_whois_fields)

    return active_whois_fields, [row]


def is_ip_address(value):
    """Return True if value is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def print_table(headers, rows):
    """Render ASCII table with text wrapping to fit terminal width."""
    term_width = shutil.get_terminal_size().columns
    n = len(headers)

    natural_widths = [
        max(len(str(item)) for item in column)
        for column in zip(headers, *rows)
    ]

    # Total table width = left border (1) + each column (w + 2) + separators (n)
    def total_width(widths):
        return 1 + 3 * n + sum(widths)

    widths = natural_widths[:]

    if total_width(widths) > term_width:
        available = term_width - 1 - 3 * n
        if available > 0:
            natural_sum = sum(natural_widths)
            widths = [
                max(1, int(w * available / natural_sum))
                for w in natural_widths
            ]

    def wrap_cell(text, width):
        text = str(text)
        if len(text) <= width:
            return [text]
        return textwrap.wrap(text, width) or [text[:width]]

    def border():
        print(
            "+" +
            "+".join("-" * (w + 2) for w in widths) +
            "+"
        )

    def row(items):
        wrapped = [wrap_cell(str(item), widths[i]) for i, item in enumerate(items)]
        height = max(len(lines) for lines in wrapped)
        for line_idx in range(height):
            print(
                "|" +
                "|".join(
                    f" {(wrapped[i][line_idx] if line_idx < len(wrapped[i]) else ''):<{widths[i]}} "
                    for i in range(len(items))
                ) +
                "|"
            )

    border()
    row(headers)
    border()

    for r in rows:
        row(r)

    border()


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <hostname_or_ip>")
        sys.exit(1)

    if not shutil.which("dig"):
        print("Error: dig command not found")
        sys.exit(1)

    if not shutil.which("whois"):
        print("Error: whois command not found")
        sys.exit(1)

    target = sys.argv[1]

    if is_ip_address(target):
        active_whois_fields, rows = build_rows_for_ip(target)
        headers = [
            "IP(s)",
            "PTR Hostname(s)",
        ]
    else:
        cname_chain, active_whois_fields, rows = build_rows(target)

        if not rows:
            print("No A records found")
            sys.exit(1)

        if cname_chain:
            headers = [
                "CNAME Relationship",
                "IP(s)",
                "PTR Hostname(s)",
            ]
        else:
            headers = [
                "IP(s)",
                "PTR Hostname(s)",
            ]

    headers.extend(active_whois_fields)

    print_table(headers, rows)


if __name__ == "__main__":
    main()
