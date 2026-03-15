"""routes/cves.py"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from core.database import get_db
from models.threat import Threat

router = APIRouter()


@router.get("/latest")
async def latest_cves(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    results = (
        await db.execute(
            select(Threat)
            .where(Threat.cve_id != "")
            .order_by(desc(Threat.published_at))
            .limit(limit)
        )
    ).scalars().all()
    return [t.to_dict() for t in results]
