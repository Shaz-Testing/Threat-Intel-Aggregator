"""
IOC (Indicator of Compromise) extraction from raw threat text.
Extracts IPs, domains, file hashes, URLs, and CVE IDs using regex.
"""
import re
from typing import NamedTuple


class IOCResult(NamedTuple):
    ioc_type: str
    value: str
    context: str


# Regex patterns
_PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|info|biz|xyz|top|onion)\b",
        re.IGNORECASE,
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
}

# Private IP ranges to exclude
_PRIVATE_IP = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.0\.0\.0|255\.255\.255\.255)"
)

# Common false-positive domains to skip
_SKIP_DOMAINS = {
    "example.com", "test.com", "localhost", "nvd.nist.gov",
    "cve.mitre.org", "exploit-db.com", "github.com",
}


def extract_iocs(text: str, title: str = "") -> list[IOCResult]:
    """
    Parse threat text and return a deduplicated list of IOCResult objects.
    """
    iocs: list[IOCResult] = []
    seen: set[str] = set()

    def _add(ioc_type: str, value: str, ctx: str = ""):
        key = f"{ioc_type}:{value.lower()}"
        if key not in seen:
            seen.add(key)
            iocs.append(IOCResult(ioc_type=ioc_type, value=value, context=ctx))

    # URLs first (before domain matching picks up parts of URLs)
    for match in _PATTERNS["url"].finditer(text):
        url = match.group()
        if not any(skip in url for skip in _SKIP_DOMAINS):
            _add("url", url, "extracted from description")

    # IPs
    for match in _PATTERNS["ipv4"].finditer(text):
        ip = match.group()
        if not _PRIVATE_IP.match(ip):
            _add("ip", ip, "extracted from description")

    # Domains (skip if already captured as part of a URL)
    url_values = {i.value for i in iocs if i.ioc_type == "url"}
    for match in _PATTERNS["domain"].finditer(text):
        domain = match.group().lower()
        if domain not in _SKIP_DOMAINS and not any(domain in u for u in url_values):
            _add("domain", domain, "extracted from description")

    # Hashes (longest first to avoid partial matches)
    for hash_type in ("sha256", "sha1", "md5"):
        for match in _PATTERNS[hash_type].finditer(text):
            _add("hash", match.group(), hash_type)

    # CVE IDs
    for match in _PATTERNS["cve"].finditer(text + " " + title):
        _add("cve", match.group().upper(), "referenced CVE")

    return iocs
