from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, or_
from core.database import get_db
from models.threat import Threat

router = APIRouter()


@router.get("")
async def list_threats(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    severity: str = Query(None),
    source: str = Query(None),
    db: AsyncSession = Depends(get_db),
):
    query = select(Threat).order_by(desc(Threat.ingested_at))
    if severity:
        query = query.where(Threat.severity == severity.upper())
    if source:
        query = query.where(Threat.source == source.lower())

    total_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(total_q)).scalar()

    offset = (page - 1) * per_page
    results = (await db.execute(query.offset(offset).limit(per_page))).scalars().all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [t.to_dict() for t in results],
    }


@router.get("/search")
async def search_threats(
    q: str = Query(..., min_length=2),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(Threat)
        .where(
            or_(
                Threat.title.ilike(f"%{q}%"),
                Threat.description.ilike(f"%{q}%"),
                Threat.cve_id.ilike(f"%{q}%"),
                Threat.ai_summary.ilike(f"%{q}%"),
            )
        )
        .order_by(desc(Threat.risk_score))
        .limit(50)
    )
    results = (await db.execute(query)).scalars().all()
    return {"query": q, "items": [t.to_dict() for t in results]}


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count(Threat.id)))).scalar()

    severity_counts = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = (
            await db.execute(
                select(func.count(Threat.id)).where(Threat.severity == sev)
            )
        ).scalar()
        severity_counts[sev] = count

    source_counts = {}
    for src in ("nvd", "exploitdb", "otx", "mitre"):
        count = (
            await db.execute(
                select(func.count(Threat.id)).where(Threat.source == src)
            )
        ).scalar()
        source_counts[src] = count

    top_threats = (
        await db.execute(
            select(Threat).order_by(desc(Threat.risk_score)).limit(5)
        )
    ).scalars().all()

    return {
        "total_threats": total,
        "by_severity": severity_counts,
        "by_source": source_counts,
        "top_threats": [t.to_dict() for t in top_threats],
    }


@router.get("/{threat_id}")
async def get_threat(threat_id: int, db: AsyncSession = Depends(get_db)):
    threat = (
        await db.execute(select(Threat).where(Threat.id == threat_id))
    ).scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat.to_dict()
