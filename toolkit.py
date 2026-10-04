#!/usr/bin/env python3
"""Defensive utilities for the DEVIL X local authentication lab.

Only the headers command performs HTTP requests, and it refuses non-loopback
hosts. No credentials are collected or transmitted by this toolkit.
"""
from __future__ import annotations

import argparse
import collections
import getpass
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener

SECURITY_HEADERS = {
    "content-security-policy": "Restricts the sources a page can load",
    "x-content-type-options": "Prevents MIME-type sniffing",
    "x-frame-options": "Reduces clickjacking risk in older browsers",
    "strict-transport-security": "Enforces HTTPS when deployed behind HTTPS",
    "referrer-policy": "Controls referrer information sent by browsers",
    "permissions-policy": "Restricts access to browser features",
}
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}


def password_feedback(password: str) -> dict:
    """Return basic password-policy feedback without storing the password."""
    checks = {
        "length_12_plus": len(password) >= 12,
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digit": any(c.isdigit() for c in password),
        "symbol": any(not c.isalnum() and not c.isspace() for c in password),
        "not_common_placeholder": password.lower() not in {
            "", "password", "password123", "123456789012", "qwerty123456"
        },
    }
    score = sum(checks.values())
    if len(password) < 8:
        rating = "weak"
    elif score >= 6 and len(password) >= 14:
        rating = "stronger policy fit"
    elif score >= 4:
        rating = "moderate policy fit"
    else:
        rating = "needs improvement"
    return {"rating": rating, "score": score, "checks": checks,
            "note": "This is a simple policy check, not a crack-time estimate. Prefer long unique passphrases and a password manager."}


def is_loopback_url(url: str) -> bool:
    """Allow HTTP(S) requests only to explicit loopback hostnames/IPs."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in {"http", "https"} and (parsed.hostname or "").lower() in LOOPBACK_NAMES
    except (ValueError, AttributeError):
        return False


def check_local_headers(url: str, timeout: float = 3.0) -> dict:
    """Fetch headers from a loopback-only URL and report common security headers."""
    if not is_loopback_url(url):
        raise ValueError("Refusing network requests to non-loopback hosts. Use localhost, 127.0.0.1, or ::1.")
    opener = build_opener(ProxyHandler({}))
    request = Request(url, headers={"User-Agent": "DEVIL-X-Local-Header-Check/1.0"}, method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            status = response.status
    except HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()}
        status = exc.code
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Could not reach local service: {exc}") from exc
    results = {
        name: {"present": name in headers, "description": description,
               "value": headers.get(name, "")}
        for name, description in SECURITY_HEADERS.items()
    }
    return {"url": url, "status": status, "headers": results,
            "missing": [name for name, result in results.items() if not result["present"]],
            "note": "A missing header is a review item, not automatically a vulnerability. HSTS is relevant when using HTTPS."}


def summarize_audit(path: str) -> dict:
    """Summarize the lab's JSON audit array without changing the source file."""
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read a valid JSON audit file: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("Expected a JSON array of audit records.")
    events = collections.Counter()
    users = set()
    for record in data:
        if not isinstance(record, dict):
            continue
        event = record.get("event")
        username = record.get("username")
        if isinstance(event, str):
            events[event] += 1
        if isinstance(username, str):
            users.add(username)
    return {"records": len(data), "events": dict(sorted(events.items())),
            "distinct_usernames": len(users)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Defensive utilities for the DEVIL X local authentication lab."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("password-policy", help="interactively check a password against basic policy")
    headers_parser = sub.add_parser("headers", help="check common headers on a loopback-only service")
    headers_parser.add_argument("url", help="URL such as http://127.0.0.1:8080/")
    audit_parser = sub.add_parser("audit-summary", help="summarize an exported JSON audit array")
    audit_parser.add_argument("json_file", help="path to a JSON file containing audit records")
    args = parser.parse_args(argv)

    try:
        if args.command == "password-policy":
            password = getpass.getpass("Password to check (not saved): ")
            result = password_feedback(password)
        elif args.command == "headers":
            result = check_local_headers(args.url)
        else:
            result = summarize_audit(args.json_file)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
