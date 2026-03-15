"""
AlienVault OTX (Open Threat Exchange) scraper.
Fetches recent threat pulses from the OTX API.
https://otx.alienvault.com/api
"""
import logging
from datetime import datetime, timedelta, timezone

import httpx

from core.config import settings
from core.risk_scorer import compute_risk_score

logger = logging.getLogger(__name__)

OTX_BASE = "https://otx.alienvault.com/api/v1"


async def fetch_recent_pulses(hours_back: int = 24, max_results: int = 50) -> list[dict]:
    """
    Fetch recent OTX pulses. Returns normalized threat dicts.
    Requires OTX_API_KEY in settings.
    """
    if not settings.OTX_API_KEY:
        logger.info("OTX_API_KEY not set — skipping OTX scraper")
        return []

    since = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}
    params = {
        "modified_since": since.strftime("%Y-%m-%dT%H:%M:%S"),
        "limit": max_results,
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{OTX_BASE}/pulses/subscribed", headers=headers, params=params
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        logger.error(f"OTX fetch error: {e}")
        return []

    threats = []
    for pulse in data.get("results", []):
        threat = _parse_pulse(pulse)
        if threat:
            threats.append(threat)

    logger.info(f"OTX: fetched {len(threats)} pulses")
    return threats


def _parse_pulse(pulse: dict) -> dict | None:
    pulse_id = pulse.get("id", "")
    name = pulse.get("name", "")
    description = pulse.get("description", "") or name

    if not pulse_id or not name:
        return None

    # Extract CVE references
    cve_ids = [
        ref["reference"]
        for ref in pulse.get("references", [])
        if "CVE-" in ref.get("reference", "")
    ]
    cve_id = cve_ids[0] if cve_ids else ""

    # Threat level from OTX (1-4) → map to CVSS-like score
    tlp = pulse.get("tlp", "white")
    adversary = pulse.get("adversary", "")
    tags = pulse.get("tags", [])

    # Heuristic score based on pulse metadata
    base_score = 5.0
    if adversary:
        base_score += 2.0
    if any(t in str(tags).lower() for t in ["ransomware", "apt", "critical"]):
        base_score += 1.5

    risk_score, severity = compute_risk_score(base_score)

    created = pulse.get("created", "")
    try:
        published_at = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        published_at = None

    return {
        "source": "otx",
        "source_id": f"otx:{pulse_id}",
        "title": name,
        "description": description,
        "url": f"https://otx.alienvault.com/pulse/{pulse_id}",
        "cvss_score": base_score,
        "risk_score": risk_score,
        "severity": severity,
        "cve_id": cve_id,
        "cwe_ids": [],
        "published_at": published_at,
    }
