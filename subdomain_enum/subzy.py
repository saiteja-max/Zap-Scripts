#!/usr/bin/env python3
"""
subzy_py_takeover_checker.py

Usage: place a file named `subdomains.txt` (one subdomain per line) in the same
folder and run the script with Python 3 (no arguments).

Output:
 - Prints progress to stdout
 - Writes takeover candidates to `subdomain_takeover.txt`

This script attempts HTTPS then HTTP requests, looks for known takeover
fingerprints (provider-specific error pages / messages) and optionally tries to
resolve DNS CNAMEs if the `dnspython` package is installed.

It's written to be resilient (timeouts, exception handling) and easy to extend
— add or refine fingerprints in the FINGERPRINTS dict.
"""

from __future__ import annotations
import sys
import os
import socket
import ssl
import time

try:
    import requests
except Exception:
    print("\nERROR: requests library is required. Install with: pip install requests\n")
    sys.exit(1)

# Optional dependency to get CNAME records (used for more accurate detection)
try:
    import dns.resolver  # type: ignore
    DNSpresent = True
except Exception:
    DNSpresent = False

INPUT_FILE = "subdomains.txt"
OUTPUT_FILE = "subdomain_takeover.txt"
TIMEOUT = 10
HEADERS = {"User-Agent": "subzy-py/1.0 (+https://github.com/yourname)"}

# Known error-page fingerprints mapped to provider name. Keep them short and
# case-insensitive checks are used. These are not exhaustive but cover many
# common takeover signatures. Add more entries as you find them.
FINGERPRINTS = {
    "GitHub Pages": [
        "there isn't a github pages site here",
        "project not found",
        "github.io site for this project does not exist",
    ],
    "AWS S3": [
        "no such bucket",
        "the specified bucket does not exist",
        "<Error> NoSuchBucket </Error>",
    ],
    "Azure / Blob Storage": [
        "error code: containernotfound",
        "the specified container does not exist",
    ],
    "Heroku": [
        "no such app",
        "heroku | no such app",
    ],
    "Fastly": [
        "fastly error: unknown domain",
        "the service is not available",
    ],
    "Shopify": [
        "sorry, this shop is currently unavailable",
        "do you want to buy",
    ],
    "Surge.sh": [
        "project not found",
        "surge.sh",
    ],
    "Cloudfront": [
        "the request could not be satisfied",
    ],
    "GitLab Pages": [
        "404 page not found",
        "there is no project here",
    ],
    "Render": [
        "the page you were looking for could not be found",
        "render.com",
    ],
    # Generic catch-alls (lower priority) — keep these brief to avoid false-positives
    "Generic - Not Found": [
        "no such domain",
        "host not found",
        "there's nothing here",
        "this domain is not configured",
    ],
}


def normalize(s: str) -> str:
    return s.lower()


def check_response_for_fingerprints(text: str) -> list[str]:
    """Return list of provider names whose fingerprints matched the response text."""
    matches = []
    lower = normalize(text)
    for provider, pats in FINGERPRINTS.items():
        for p in pats:
            if p.lower() in lower:
                matches.append(provider)
                break
    return matches


def try_request(host: str) -> tuple[int | None, str | None, str | None]:
    """Try HTTPS then HTTP. Returns (status_code, final_url, body) or (None,None,None)
    on network errors.
    """
    schemes = ["https://", "http://"]
    for scheme in schemes:
        url = scheme + host
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True, verify=True)
            body = r.text or ""
            return r.status_code, r.url, body
        except requests.exceptions.SSLError:
            # try again without certificate verification for HTTPS
            if scheme == "https://":
                try:
                    r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True, verify=False)
                    body = r.text or ""
                    return r.status_code, r.url, body
                except Exception:
                    continue
            continue
        except Exception:
            continue
    return None, None, None


def try_resolve_cname(host: str) -> list[str]:
    """Return list of CNAME targets (may be empty). Requires dnspython; if not
    present, returns an empty list.
    """
    if not DNSpresent:
        return []
    try:
        answers = dns.resolver.resolve(host, 'CNAME')
        return [str(r.target).rstrip('.') for r in answers]
    except Exception:
        return []


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"Input file '{INPUT_FILE}' not found. Put your subdomains (one per line) there.")
        sys.exit(1)

    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    subdomains = []
    for l in lines:
        # strip schema if present
        if l.startswith('http://') or l.startswith('https://'):
            l = l.split('://', 1)[1]
        subdomains.append(l.rstrip('/'))

    print(f"Loaded {len(subdomains)} subdomains from {INPUT_FILE}\n")

    results = []

    for i, host in enumerate(subdomains, 1):
        print(f"[{i}/{len(subdomains)}] Checking {host} ...", end=' ')
        sys.stdout.flush()

        # Attempt DNS CNAME resolution (optional)
        cnames = try_resolve_cname(host)
        if cnames:
            print(f"(CNAME -> {', '.join(cnames)})", end=' ')

        status, final_url, body = try_request(host)
        if status is None:
            print("[no-response]")
            continue

        # Check response body for fingerprints
        matches = []
        if body:
            matches = check_response_for_fingerprints(body)

        # If nothing in body, try final_url or hostname text for clues
        if not matches and final_url:
            matches = check_response_for_fingerprints(final_url)

        if matches:
            providers = ", ".join(sorted(set(matches)))
            print(f"TAKEOVER? -> {providers}")
            results.append((host, providers, status, final_url or ""))
        else:
            print(f"OK ({status})")

        # be a bit polite
        time.sleep(0.08)

    # Write results
    if results:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as out:
            out.write("# Detected potential subdomain takeovers\n")
            out.write(f"# Generated: {time.ctime()}\n\n")
            for host, providers, status, final_url in results:
                out.write(f"{host}\t{providers}\t{status}\t{final_url}\n")
        print(f"\nWrote {len(results)} takeover candidates to {OUTPUT_FILE}")
    else:
        print("\nNo takeover fingerprints found.")


if __name__ == '__main__':
    main()
