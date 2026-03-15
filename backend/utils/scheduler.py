"""
APScheduler setup — runs the scraper pipeline on a configurable interval.
"""
import asyncio
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from core.config import settings

logger = logging.getLogger(__name__)
_scheduler = BackgroundScheduler()


def start_scheduler():
    """Register and start the scrape job."""
    _scheduler.add_job(
        func=_run_scrape_pipeline,
        trigger=IntervalTrigger(minutes=settings.SCRAPE_INTERVAL_MINUTES),
        id="scrape_pipeline",
        name="Threat intel scrape",
        replace_existing=True,
        max_instances=1,
    )
    _scheduler.start()
    logger.info(
        f"Scheduler started — scraping every {settings.SCRAPE_INTERVAL_MINUTES} minutes"
    )


def shutdown_scheduler():
    if _scheduler.running:
        _scheduler.shutdown(wait=False)


def _run_scrape_pipeline():
    """Synchronous wrapper so APScheduler can call the async pipeline."""
    asyncio.run(_async_scrape_pipeline())


async def _async_scrape_pipeline():
    """Full scrape + enrich + store pipeline."""
    from scrapers.nvd import fetch_recent_cves
    from scrapers.exploitdb import fetch_recent_exploits
    from scrapers.otx import fetch_recent_pulses
    from core.ai_enrichment import enrich_threat
    from core.ioc_extractor import extract_iocs
    from core.database import AsyncSessionLocal
    from models.threat import Threat, IOC
    from utils.alerting import maybe_send_alert
    from sqlalchemy import select

    logger.info("Starting scrape pipeline...")

    scrapers = [
        fetch_recent_cves(hours_back=settings.SCRAPE_INTERVAL_MINUTES // 60 + 1),
        fetch_recent_exploits(max_results=settings.MAX_THREATS_PER_RUN),
        fetch_recent_pulses(hours_back=settings.SCRAPE_INTERVAL_MINUTES // 60 + 1),
    ]

    results = await asyncio.gather(*scrapers, return_exceptions=True)
    all_threats = []
    for r in results:
        if isinstance(r, list):
            all_threats.extend(r)

    logger.info(f"Scraped {len(all_threats)} raw threats, starting enrichment...")

    async with AsyncSessionLocal() as session:
        saved = 0
        for threat_data in all_threats[: settings.MAX_THREATS_PER_RUN]:
            # Skip duplicates
            existing = await session.execute(
                select(Threat).where(Threat.source_id == threat_data["source_id"])
            )
            if existing.scalar_one_or_none():
                continue

            # AI enrichment
            enrichment = await enrich_threat(
                title=threat_data["title"],
                description=threat_data["description"],
                source=threat_data["source"],
                cve_id=threat_data.get("cve_id", ""),
            )
            threat_data.update(enrichment)

            # Build ORM object
            threat = Threat(**{
                k: v for k, v in threat_data.items()
                if k in Threat.__table__.columns.keys()
            })
            session.add(threat)
            await session.flush()

            # Extract and store IOCs
            ioc_results = extract_iocs(
                threat_data["description"], threat_data["title"]
            )
            for ioc in ioc_results:
                session.add(IOC(
                    threat_id=threat.id,
                    ioc_type=ioc.ioc_type,
                    value=ioc.value,
                    context=ioc.context,
                ))

            # Alert on critical findings
            await maybe_send_alert(threat)
            saved += 1

        await session.commit()
        logger.info(f"Scrape pipeline complete — saved {saved} new threats")
