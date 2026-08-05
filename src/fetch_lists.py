"""Fetching of Hagezi domain blocklists."""

from __future__ import annotations

from typing import Dict, List

import requests

# Mapping of list name -> source URL.
BLOCKLISTS: Dict[str, str] = {
    "fake": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
    "popup-ads": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/popupads-onlydomains.txt",
    # "threat": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt",
    "threat-med": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt",
    # "nrd": "https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt",
    "nrd-dga": "https://raw.githubusercontent.com/hagezi/nrd/main/domains/dga7.txt",
    "encrypted-dns-resolver": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-onlydomains.txt",
    "dynamic-dns": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
    "url-shortener": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/urlshortener-onlydomains.txt",
    "piracy": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
    "gambling": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/gambling-onlydomains.txt",
    "social-networks": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
    "nsfw": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
}


def fetch_domain_list(url: str) -> List[str]:
    """Download a plain-text list of domains (one per line)."""
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    domains = []
    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domains.append(line.lower())
    return domains


def fetch_all_lists() -> Dict[str, List[str]]:
    """Download every configured blocklist. Returns {name: [domains]}."""
    result: Dict[str, List[str]] = {}
    for name, url in BLOCKLISTS.items():
        result[name] = fetch_domain_list(url)
    return result

