from datetime import datetime
from sqlalchemy import String, Float, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from core.database import Base


class Threat(Base):
    __tablename__ = "threats"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    source: Mapped[str] = mapped_column(String(50))
    source_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    url: Mapped[str] = mapped_column(String(1000), default="")
    ai_summary: Mapped[str] = mapped_column(Text, default="")
    ai_tags: Mapped[list] = mapped_column(JSON, default=list)
    ai_affected_products: Mapped[list] = mapped_column(JSON, default=list)
    ai_mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    ai_remediation_priority: Mapped[str] = mapped_column(String(50), default="")
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(20), default="")
    cve_id: Mapped[str] = mapped_column(String(30), default="", index=True)
    cwe_ids: Mapped[list] = mapped_column(JSON, default=list)
    published_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    enriched_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    iocs: Mapped[list["IOC"]] = relationship("IOC", back_populates="threat", cascade="all, delete-orphan", lazy="noload")

    def to_dict(self, include_iocs=False):
        return {
            "id": self.id,
            "source": self.source,
            "source_id": self.source_id,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "ai_summary": self.ai_summary,
            "ai_tags": self.ai_tags,
            "ai_affected_products": self.ai_affected_products,
            "ai_mitre_techniques": self.ai_mitre_techniques,
            "ai_remediation_priority": self.ai_remediation_priority,
            "cvss_score": self.cvss_score,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "cve_id": self.cve_id,
            "cwe_ids": self.cwe_ids,
            "published_at": self.published_at.isoformat() if self.published_at else None,
            "ingested_at": self.ingested_at.isoformat() if self.ingested_at else None,
            "iocs": [],
        }


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    threat_id: Mapped[int] = mapped_column(ForeignKey("threats.id"))
    ioc_type: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(String(500), index=True)
    context: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    threat: Mapped["Threat"] = relationship("Threat", back_populates="iocs")

    def to_dict(self):
        return {
            "id": self.id,
            "threat_id": self.threat_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "context": self.context,
        }
