"""
AI enrichment using the Anthropic Claude API.
Takes raw threat data and returns structured, analyst-ready intelligence.
"""
import json
import logging
from datetime import datetime

import anthropic

from core.config import settings

logger = logging.getLogger(__name__)

client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

ENRICHMENT_PROMPT = """You are a cybersecurity threat intelligence analyst. Analyze the following threat advisory and return ONLY a JSON object (no markdown, no explanation).

Threat Title: {title}
Threat Description: {description}
Source: {source}
CVE ID (if any): {cve_id}

Return this exact JSON structure:
{{
  "summary": "2-3 sentence plain-English summary of what this threat is and why it matters",
  "tags": ["array", "of", "threat", "category", "tags"],
  "affected_products": ["list", "of", "affected", "software/hardware"],
  "mitre_techniques": ["T1xxx", "T1xxx"],
  "remediation_priority": "PATCH_NOW|MONITOR|LOW_PRIORITY",
  "remediation_note": "one sentence on what defenders should do"
}}

Tags should be from: RCE, SQLi, XSS, CSRF, LFI, RFI, SSRF, XXE, Deserialization, PrivEsc, AuthBypass, InfoDisclosure, DoS, Ransomware, Phishing, SupplyChain, Cryptojacking, Backdoor, Rootkit, Worm, Other

Remediation priority rules:
- PATCH_NOW: CVSS >= 9.0 or actively exploited
- MONITOR: CVSS 7.0-8.9 or PoC exists
- LOW_PRIORITY: CVSS < 7.0 and no known exploit
"""


async def enrich_threat(
    title: str,
    description: str,
    source: str,
    cve_id: str = "",
) -> dict:
    """
    Call Claude to enrich a raw threat with AI-generated insights.
    Returns a dict with summary, tags, affected_products, etc.
    Falls back to empty values on error.
    """
    if not settings.ANTHROPIC_API_KEY:
        logger.warning("ANTHROPIC_API_KEY not set — skipping AI enrichment")
        return _empty_enrichment()

    prompt = ENRICHMENT_PROMPT.format(
        title=title,
        description=description[:3000],  # Truncate very long descriptions
        source=source,
        cve_id=cve_id or "N/A",
    )

    try:
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text.strip()

        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        data = json.loads(raw)
        return {
            "ai_summary": data.get("summary", ""),
            "ai_tags": data.get("tags", []),
            "ai_affected_products": data.get("affected_products", []),
            "ai_mitre_techniques": data.get("mitre_techniques", []),
            "ai_remediation_priority": data.get("remediation_priority", ""),
            "enriched_at": datetime.utcnow(),
        }

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse AI response as JSON: {e}")
        return _empty_enrichment()
    except anthropic.APIError as e:
        logger.error(f"Anthropic API error: {e}")
        return _empty_enrichment()


def _empty_enrichment() -> dict:
    return {
        "ai_summary": "",
        "ai_tags": [],
        "ai_affected_products": [],
        "ai_mitre_techniques": [],
        "ai_remediation_priority": "",
        "enriched_at": None,
    }
