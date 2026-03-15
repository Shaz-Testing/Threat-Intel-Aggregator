"""
AI-Powered Threat Intelligence Aggregator
FastAPI application entry point
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import threats, cves, iocs, scraper, health
from core.database import init_db
from utils.scheduler import start_scheduler, shutdown_scheduler
from core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    await init_db()
    start_scheduler()
    yield
    shutdown_scheduler()


app = FastAPI(
    title="Threat Intelligence Aggregator API",
    description="AI-powered threat intel collection and analysis",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, tags=["Health"])
app.include_router(threats.router, prefix="/api/threats", tags=["Threats"])
app.include_router(cves.router, prefix="/api/cves", tags=["CVEs"])
app.include_router(iocs.router, prefix="/api/iocs", tags=["IOCs"])
app.include_router(scraper.router, prefix="/api/scrape", tags=["Scraper"])
