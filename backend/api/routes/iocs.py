"""routes/iocs.py"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from core.database import get_db
from models.threat import IOC

router = APIRouter()


@router.get("")
async def list_iocs(
    ioc_type: str = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    query = select(IOC).order_by(desc(IOC.created_at))
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type.lower())

    total_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(total_q)).scalar()

    offset = (page - 1) * per_page
    results = (await db.execute(query.offset(offset).limit(per_page))).scalars().all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [i.to_dict() for i in results],
    }


@router.get("/search")
async def search_iocs(
    q: str = Query(..., min_length=2),
    db: AsyncSession = Depends(get_db),
):
    results = (
        await db.execute(
            select(IOC)
            .where(IOC.value.ilike(f"%{q}%"))
            .limit(100)
        )
    ).scalars().all()
    return [i.to_dict() for i in results]


@router.get("/stats")
async def ioc_stats(db: AsyncSession = Depends(get_db)):
    type_counts = {}
    for t in ("ip", "domain", "url", "hash", "cve"):
        count = (
            await db.execute(
                select(func.count(IOC.id)).where(IOC.ioc_type == t)
            )
        ).scalar()
        type_counts[t] = count
    return {"by_type": type_counts}
