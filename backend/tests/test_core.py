"""
Tests for core modules.
Run with: pytest tests/ -v
"""
import pytest
from core.ioc_extractor import extract_iocs
from core.risk_scorer import compute_risk_score, cvss_from_nvd


# ── IOC Extractor Tests ───────────────────────────────────────────────────────

def test_extract_ipv4():
    text = "The attacker used IP 203.0.113.42 to exfiltrate data."
    iocs = extract_iocs(text)
    ip_iocs = [i for i in iocs if i.ioc_type == "ip"]
    assert any(i.value == "203.0.113.42" for i in ip_iocs)


def test_skip_private_ips():
    text = "Internal server at 192.168.1.1 and 10.0.0.5"
    iocs = extract_iocs(text)
    ip_iocs = [i for i in iocs if i.ioc_type == "ip"]
    assert len(ip_iocs) == 0


def test_extract_cve():
    text = "This exploits CVE-2024-12345 on Windows systems."
    iocs = extract_iocs(text)
    cve_iocs = [i for i in iocs if i.ioc_type == "cve"]
    assert any(i.value == "CVE-2024-12345" for i in cve_iocs)


def test_extract_sha256():
    text = "Malware hash: a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"
    iocs = extract_iocs(text)
    hash_iocs = [i for i in iocs if i.ioc_type == "hash"]
    assert len(hash_iocs) > 0


def test_extract_domain():
    text = "C2 server at malicious-domain.xyz contacted the victim."
    iocs = extract_iocs(text)
    domain_iocs = [i for i in iocs if i.ioc_type == "domain"]
    assert any("malicious-domain.xyz" in i.value for i in domain_iocs)


def test_no_duplicate_iocs():
    text = "IP 203.0.113.42 and again 203.0.113.42"
    iocs = extract_iocs(text)
    ip_values = [i.value for i in iocs if i.ioc_type == "ip"]
    assert len(ip_values) == len(set(ip_values))


# ── Risk Scorer Tests ─────────────────────────────────────────────────────────

def test_critical_score():
    score, severity = compute_risk_score(9.8)
    assert severity == "CRITICAL"
    assert score >= 9.8


def test_exploit_increases_score():
    base_score, _ = compute_risk_score(7.0)
    exploit_score, _ = compute_risk_score(7.0, has_public_exploit=True)
    assert exploit_score > base_score


def test_active_exploitation_boost():
    score, severity = compute_risk_score(8.0, is_actively_exploited=True)
    assert score >= 9.0


def test_score_capped_at_10():
    score, _ = compute_risk_score(10.0, has_public_exploit=True, is_actively_exploited=True, exploit_count=10)
    assert score == 10.0


def test_zero_cvss():
    score, severity = compute_risk_score(0.0)
    assert severity == "NONE"


def test_cvss_from_nvd_v31():
    metrics = {
        "cvssMetricV31": [{"cvssData": {"baseScore": 8.5}}]
    }
    assert cvss_from_nvd(metrics) == 8.5


def test_cvss_from_nvd_empty():
    assert cvss_from_nvd({}) == 0.0
