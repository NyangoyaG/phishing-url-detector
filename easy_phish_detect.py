#!/usr/bin/env python3
"""easy_phish_detect.py - simple phishing indicator checker (educational).

Examples:
  ./easy_phish_detect.py http://192.168.1.10/login.html
  ./easy_phish_detect.py example.com my-bank.com
  ./easy_phish_detect.py -f urls.txt
  ./easy_phish_detect.py -r 192.168.56.0/30        (only ranges you own)
  ./easy_phish_detect.py --no-whois --no-fetch http://127.0.0.1:8000/test.html
"""

import argparse
import ipaddress
import shutil
import subprocess
import sys
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

MAX_RANGE_HOSTS = 256


# ---------- helpers ----------

def normalize(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def get_host(url):
    try:
        return urlparse(url).hostname or ""
    except ValueError:          # e.g. invalid IPv6 or bad port
        return ""


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------- indicator checks ----------

def check_ip_in_url(host):
    return is_ip(host)


def check_at_symbol(url):
    return "@" in url


def check_url_length(url):
    return len(url) > 75


def check_hyphen(host):
    return "-" in host


def check_https(url):
    return url.startswith("https://")


def check_domain_age(host, timeout=10):
    if not host:
        return "Invalid host"
    if is_ip(host):
        return "N/A (IP address)"
    if host.startswith("-"):
        return "Invalid host"
    if not shutil.which("whois"):
        return "WHOIS not installed"
    try:
        result = subprocess.run(["whois", host], capture_output=True,
                                text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "WHOIS timed out"
    except OSError:
        return "WHOIS failed"
    out = result.stdout.lower()
    if "creation date" in out or "created:" in out:
        return "Registered (creation date found)"
    return "Unknown (no creation date; WHOIS may hide it)"


def check_mailto_form(url, timeout=5):
    """Returns True, False, or a short error string."""
    try:
        resp = requests.get(url, timeout=timeout,
                            headers={"User-Agent": "easy-phish-detect/1.0"})
    except requests.exceptions.Timeout:
        return "Page load timed out"
    except requests.exceptions.ConnectionError:
        return "Host unreachable"
    except requests.exceptions.RequestException as exc:
        return f"Request failed ({type(exc).__name__})"
    soup = BeautifulSoup(resp.text, "html.parser")
    for form in soup.find_all("form"):
        if form.get("action", "").strip().lower().startswith("mailto:"):
            return True
    return False


# ---------- scanning ----------

def yes_no(flag):
    return "YES" if flag else "NO"


def run_checks(url, do_whois=True, do_fetch=True, timeout=5):
    url = normalize(url)
    host = get_host(url)
    if not host:
        print(f"\nSkipping invalid URL: {url}\n")
        return None

    flags = {
        "IP in URL": check_ip_in_url(host),
        "@ symbol": check_at_symbol(url),
        "URL longer than 75": check_url_length(url),
        "Hyphen in domain": check_hyphen(host),
        "No HTTPS": not check_https(url),
    }

    print(f"\nScanning: {url}")
    print("=" * 40)
    print(f"1. Uses IP in URL:        {yes_no(flags['IP in URL'])}")
    print(f"2. Contains '@' symbol:   {yes_no(flags['@ symbol'])}")
    print(f"3. URL length > 75:       {yes_no(flags['URL longer than 75'])}")
    print(f"4. Hyphen in domain:      {yes_no(flags['Hyphen in domain'])}")
    print(f"5. Uses HTTPS:            {yes_no(not flags['No HTTPS'])}")

    if do_whois:
        print(f"6. Domain age:            {check_domain_age(host)}")
    else:
        print("6. Domain age:            skipped")

    if do_fetch:
        mailto = check_mailto_form(url, timeout)
        if isinstance(mailto, bool):
            flags["mailto: form"] = mailto
            print(f"7. Suspicious mailto form: {yes_no(mailto)}")
        else:
            print(f"7. Suspicious mailto form: could not check ({mailto})")
    else:
        print("7. Suspicious mailto form: skipped")

    score = sum(flags.values())
    verdict = ["No indicators", "Low", "Medium"][score] if score < 3 else "High"
    hit = [name for name, value in flags.items() if value]
    print("-" * 40)
    print(f"Indicators: {score}  ->  {verdict}" + (f"  ({', '.join(hit)})" if hit else ""))
    print("=" * 40)
    return score


def expand_range(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print(f"Invalid range skipped: {cidr}", file=sys.stderr)
        return []
    if net.num_addresses > MAX_RANGE_HOSTS:
        print(f"Range too large (max {MAX_RANGE_HOSTS} addresses): {cidr}", file=sys.stderr)
        return []
    return [f"http://{host}" for host in net.hosts()]


def main():
    parser = argparse.ArgumentParser(description="Simple phishing indicator checker")
    parser.add_argument("urls", nargs="*", help="URLs or domains to check")
    parser.add_argument("-f", "--file", help="text file with one URL per line")
    parser.add_argument("-r", "--range", action="append", default=[],
                        help="CIDR range to scan, e.g. 192.168.56.0/30 (own networks only)")
    parser.add_argument("--no-whois", action="store_true", help="skip the domain age lookup")
    parser.add_argument("--no-fetch", action="store_true", help="skip downloading the page")
    parser.add_argument("--timeout", type=int, default=5, help="page load timeout in seconds")
    args = parser.parse_args()

    targets = list(args.urls)
    if args.file:
        try:
            with open(args.file) as fh:
                targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            parser.error(f"cannot read {args.file}: {exc.strerror}")
    for cidr in args.range:
        targets += expand_range(cidr)

    targets = list(dict.fromkeys(targets))      # remove duplicates, keep order
    if not targets:
        parser.error("give at least one URL, a file (-f) or a range (-r)")

    for target in targets:
        try:
            run_checks(target, not args.no_whois, not args.no_fetch, args.timeout)
        except KeyboardInterrupt:
            print("\nStopped by user.")
            sys.exit(130)


if __name__ == "__main__":
    main()
