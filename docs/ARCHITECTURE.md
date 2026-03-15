# Architecture

## Overview

The Threat Intel Aggregator is a three-layer system:

1. **Scraper Layer** — fetches raw threat data from external APIs on a schedule
2. **Enrichment Layer** — uses Claude AI to summarize, tag, and prioritize each threat
3. **Presentation Layer** — serves data via a REST API and React dashboard

## Data Flow

```
External APIs
    │
    ▼
Scrapers (nvd.py, exploitdb.py, otx.py, mitre.py)
    │  Raw dicts with title, description, cvss_score, etc.
    ▼
AI Enrichment (ai_enrichment.py)
    │  Adds: ai_summary, ai_tags, ai_affected_products,
    │        ai_mitre_techniques, ai_remediation_priority
    ▼
IOC Extractor (ioc_extractor.py)
    │  Adds: ip, domain, hash, url, cve IOCs
    ▼
Risk Scorer (risk_scorer.py)
    │  Produces: risk_score (0–10), severity label
    ▼
SQLite Database (via SQLAlchemy async)
    │  Tables: threats, iocs
    ▼
FastAPI REST API (/api/threats, /api/iocs, /api/cves)
    │
    ▼
React Dashboard (Vite + Tailwind + Recharts)
```

## Key Design Decisions

### Why SQLite?
Simple, zero-config, file-based. Easy to back up. For larger deployments, swapping to PostgreSQL requires only changing `DATABASE_URL`.

### Why APScheduler?
In-process scheduling keeps deployment simple (one process). For production scale, replace with Celery + Redis.

### Why async throughout?
FastAPI's async support lets us handle concurrent scraper runs and API requests without blocking. All DB calls use `aiosqlite`.

### AI Enrichment Prompt Design
The prompt is carefully structured to return JSON-only output, making parsing reliable. Key choices:
- Fixed tag taxonomy prevents hallucinated categories
- Priority rules are explicit (CVSS thresholds) to reduce variability
- Max 3000 chars of description passed to avoid token waste

## Extending

### Adding a new scraper
1. Create `backend/scrapers/your_source.py`
2. Implement `async def fetch_recent_X() -> list[dict]`
3. Return dicts with keys: `source`, `source_id`, `title`, `description`, `url`, `cvss_score`, `risk_score`, `severity`, `cve_id`, `cwe_ids`, `published_at`
4. Import and call from `utils/scheduler.py`

### Adding a new API endpoint
1. Create or extend a file in `backend/api/routes/`
2. Register the router in `backend/api/main.py`
