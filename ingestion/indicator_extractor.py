"""
indicator_extractor.py

Pulls structured "indicators" (URLs, domains, IPs, email addresses,
attachment hashes) out of a ParsedEmail. These indicators are what
the LinkMirror engine, intelligence layer, and correlation engine
all operate on downstream.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List
import re
import urllib.parse

from ingestion.eml_parser import ParsedEmail

URL_REGEX = re.compile(r'https?://[^\s<>"\'\)\]]+', re.IGNORECASE)
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_REGEX = re.compile(r'[\w\.\+\-]+@[\w\-]+\.[\w\.\-]+')


@dataclass
class IndicatorSet:
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    attachment_hashes: List[str] = field(default_factory=list)


def extract_indicators(parsed: ParsedEmail) -> IndicatorSet:
    combined_text = f"{parsed.body_text}\n{parsed.body_html}"

    urls = sorted(set(URL_REGEX.findall(combined_text)))
    domains = sorted({_domain_from_url(u) for u in urls if _domain_from_url(u)})
    ips = sorted(set(IP_REGEX.findall(combined_text)))

    email_addresses = sorted(set(EMAIL_REGEX.findall(combined_text)))
    if parsed.from_address:
        email_addresses = sorted(set(email_addresses + [parsed.from_address]))

    attachment_hashes = [a.sha256 for a in parsed.attachments]

    return IndicatorSet(
        urls=urls,
        domains=domains,
        ips=ips,
        email_addresses=email_addresses,
        attachment_hashes=attachment_hashes,
    )


def _domain_from_url(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except Exception:
        return ""


if __name__ == "__main__":
    import sys
    import json
    from ingestion.eml_parser import parse_eml_file

    if len(sys.argv) != 2:
        print("Usage: python indicator_extractor.py <path_to.eml>")
        sys.exit(1)

    parsed = parse_eml_file(sys.argv[1])
    indicators = extract_indicators(parsed)
    print(json.dumps(indicators.__dict__, indent=2))
