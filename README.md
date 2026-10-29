# Phishing URL Indicator Detector

A Python command-line tool that checks a URL for common phishing signs: an IP address instead of a domain, an `@` symbol, a very long URL, hyphens in the domain, no HTTPS, a `mailto:` form on the page, and a new or unregistered domain. It adds up the signs it finds and gives a risk level from none to high.

It handles timeouts, unreachable hosts and invalid URLs without stopping, and it can scan one URL, a list from a file, or an IP range.

It uses fixed rules, so a high score means "suspicious", not "proven malicious".

## Install

    sudo apt install whois
    pip install -r requirements.txt

## Usage

    chmod +x easy_phish_detect.py
    ./easy_phish_detect.py http://example.com/login
    ./easy_phish_detect.py -f urls.txt
    ./easy_phish_detect.py -r 192.168.56.0/30

Only scan networks you own or have permission to test.

## Testing

`urls.txt` holds harmless test URLs: local pages and reserved `.example` and `.test` domains.
