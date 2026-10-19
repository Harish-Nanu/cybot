from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class AlertRecord(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    source_alert_id: Mapped[str | None] = mapped_column(String(256))
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    severity_rank: Mapped[int] = mapped_column(Integer, index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    # Stored as naive UTC so SQLite comparisons are consistent.
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)

    indicators: Mapped[list["IndicatorRecord"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )


class IndicatorRecord(Base):
    __tablename__ = "alert_indicators"
    __table_args__ = (Index("ix_indicator_type_value", "type", "value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(1024))

    alert: Mapped[AlertRecord] = relationship(back_populates="indicators")


class AnalysisRecord(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(16))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class IntelCacheRecord(Base):
    __tablename__ = "intel_cache"
    __table_args__ = (UniqueConstraint("provider", "ioc_type", "value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(32))
    ioc_type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(1024))
    fetched_at: Mapped[datetime] = mapped_column(DateTime)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
