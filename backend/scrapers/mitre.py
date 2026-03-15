"""
MITRE ATT&CK scraper.
Fetches recently updated techniques from the MITRE ATT&CK STIX data.
Uses the public GitHub releases — no API key needed.
"""
import logging
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)

MITRE_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


async def fetch_recent_techniques(max_results: int = 30) -> list[dict]:
    """
    Fetch MITRE ATT&CK techniques. Returns normalized threat dicts.
    Note: This is a large file (~30MB). In production, cache it locally.
    """
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(MITRE_ENTERPRISE_URL)
            resp.raise_for_status()
            bundle = resp.json()
    except httpx.HTTPError as e:
        logger.error(f"MITRE ATT&CK fetch error: {e}")
        return []

    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False):
            continue

        technique = _parse_technique(obj)
        if technique:
            techniques.append(technique)

        if len(techniques) >= max_results:
            break

    logger.info(f"MITRE ATT&CK: loaded {len(techniques)} techniques")
    return techniques


def _parse_technique(obj: dict) -> dict | None:
    ext_refs = obj.get("external_references", [])
    mitre_ref = next((r for r in ext_refs if r.get("source_name") == "mitre-attack"), None)
    if not mitre_ref:
        return None

    technique_id = mitre_ref.get("external_id", "")
    url = mitre_ref.get("url", "")
    name = obj.get("name", "")
    description = obj.get("description", "")

    if not technique_id or not name:
        return None

    # Extract platforms
    platforms = obj.get("x_mitre_platforms", [])
    tags = list(obj.get("x_mitre_data_sources", [])) + platforms

    modified = obj.get("modified", "")
    try:
        published_at = datetime.fromisoformat(modified.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        published_at = None

    return {
        "source": "mitre",
        "source_id": f"mitre:{technique_id}",
        "title": f"{technique_id}: {name}",
        "description": description[:2000],  # MITRE descriptions can be very long
        "url": url,
        "cvss_score": 0.0,
        "risk_score": 5.0,
        "severity": "MEDIUM",
        "cve_id": "",
        "cwe_ids": [],
        "published_at": published_at,
        "_mitre_techniques": [technique_id],
        "_tags": tags,
    }
