"""
Risk scoring engine.
Combines CVSS base score with exploitability signals to produce
a composite risk_score (0–10) and severity label.
"""


def compute_risk_score(
    cvss_score: float,
    has_public_exploit: bool = False,
    is_actively_exploited: bool = False,
    exploit_count: int = 0,
) -> tuple[float, str]:
    """
    Returns (risk_score, severity_label).

    Scoring logic:
    - Start with CVSS score as base (0–10)
    - +1.0 if a public PoC/exploit exists
    - +0.5 for each additional exploit (capped at +2.0)
    - +1.5 if actively exploited in the wild
    - Clamp to 10.0 max
    """
    score = cvss_score
    if has_public_exploit:
        score += 1.0
    score += min(exploit_count * 0.5, 2.0)
    if is_actively_exploited:
        score += 1.5

    score = min(score, 10.0)
    severity = _severity_label(score)
    return round(score, 2), severity


def _severity_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


def cvss_from_nvd(metrics: dict) -> float:
    """Extract the highest CVSS score from NVD metrics dict."""
    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics_list = metrics.get(version, [])
        if metrics_list:
            return metrics_list[0].get("cvssData", {}).get("baseScore", 0.0)
    return 0.0
