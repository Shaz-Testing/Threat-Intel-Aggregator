"""
NVD (National Vulnerability Database) scraper.
Fetches recent CVEs from the NVD REST API v2.
https://nvd.nist.gov/developers/vulnerabilities
"""
import logging
from datetime import datetime, timedelta, timezone

import httpx

from core.config import settings
from core.risk_scorer import cvss_from_nvd, compute_risk_score

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}


async def fetch_recent_cves(hours_back: int = 24, max_results: int = 100) -> list[dict]:
    """
    Fetch CVEs published in the last `hours_back` hours from NVD.
    Returns a list of normalized threat dicts ready for DB insertion.
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours_back)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(max_results, 2000),
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(NVD_BASE, params=params, headers=HEADERS)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        logger.error(f"NVD fetch error: {e}")
        return []

    threats = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        threat = _parse_cve(cve)
        if threat:
            threats.append(threat)

    logger.info(f"NVD: fetched {len(threats)} CVEs")
    return threats


def _parse_cve(cve: dict) -> dict | None:
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # Get English description
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available.",
    )

    # CVSS score
    metrics = cve.get("metrics", {})
    cvss = cvss_from_nvd(metrics)
    risk_score, severity = compute_risk_score(cvss)

    # CWE IDs
    weaknesses = cve.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    # Published date
    published_str = cve.get("published", "")
    try:
        published_at = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        published_at = None

    return {
        "source": "nvd",
        "source_id": f"nvd:{cve_id}",
        "title": cve_id,
        "description": description,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "cvss_score": cvss,
        "risk_score": risk_score,
        "severity": severity,
        "cve_id": cve_id,
        "cwe_ids": cwe_ids,
        "published_at": published_at,
    }
