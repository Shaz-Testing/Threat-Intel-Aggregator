"""
Alerting — sends Slack notifications for critical threats.
"""
import logging
import httpx
from core.config import settings

logger = logging.getLogger(__name__)


async def maybe_send_alert(threat) -> None:
    """Send a Slack alert if the threat exceeds the critical threshold."""
    if not settings.SLACK_WEBHOOK_URL:
        return
    if threat.risk_score < settings.CRITICAL_SEVERITY_THRESHOLD:
        return

    message = _build_slack_message(threat)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(settings.SLACK_WEBHOOK_URL, json=message)
            resp.raise_for_status()
        logger.info(f"Slack alert sent for {threat.source_id}")
    except httpx.HTTPError as e:
        logger.error(f"Slack alert failed: {e}")


def _build_slack_message(threat) -> dict:
    cve_text = f" ({threat.cve_id})" if threat.cve_id else ""
    summary = threat.ai_summary or threat.description[:200]
    priority = threat.ai_remediation_priority or "UNKNOWN"

    return {
        "text": f"🚨 *CRITICAL THREAT DETECTED*",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 Critical Threat Alert"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Threat:*\n{threat.title}{cve_text}"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n{threat.risk_score}/10"},
                    {"type": "mrkdwn", "text": f"*Source:*\n{threat.source.upper()}"},
                    {"type": "mrkdwn", "text": f"*Priority:*\n{priority}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*AI Summary:*\n{summary}"},
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Details"},
                        "url": threat.url,
                        "style": "danger",
                    }
                ],
            },
        ],
    }
