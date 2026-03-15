"""routes/scraper.py — manual scrape trigger endpoint"""
import asyncio
from fastapi import APIRouter, BackgroundTasks

router = APIRouter()


@router.post("/trigger")
async def trigger_scrape(background_tasks: BackgroundTasks):
    """Manually kick off a scrape pipeline run."""
    from utils.scheduler import _async_scrape_pipeline
    background_tasks.add_task(_async_scrape_pipeline)
    return {"status": "Scrape pipeline started in background"}
