"""Persistence for normalized alerts and analysis results (SQLAlchemy)."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine, event, func, select, tuple_
from sqlalchemy.orm import Session, sessionmaker

from cybot.models import AlertCategory, AnalysisResult, NormalizedAlert, Severity
from cybot.storage.orm import AlertRecord, AnalysisRecord, Base, IndicatorRecord


def _naive_utc(dt: datetime) -> datetime:
    return dt.astimezone(UTC).replace(tzinfo=None)


class Database:
    def __init__(self, url: str) -> None:
        if url.startswith("sqlite:///") and not url.startswith("sqlite:///:memory:"):
            Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, connect_args=connect_args)
        if url.startswith("sqlite"):
            event.listen(self.engine, "connect", _enable_sqlite_fks)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self._sessions() as session, session.begin():
            yield session


def _enable_sqlite_fks(dbapi_conn, _record) -> None:
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class AlertRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # -- alerts -------------------------------------------------------------
    def add_alerts(self, alerts: Iterable[NormalizedAlert]) -> list[NormalizedAlert]:
        alerts = list(alerts)
        with self.db.session() as s:
            for alert in alerts:
                s.add(self._to_record(alert))
        return alerts

    def get_alert(self, alert_id: str) -> NormalizedAlert | None:
        with self.db.session() as s:
            record = s.get(AlertRecord, alert_id)
            return NormalizedAlert.model_validate(record.payload) if record else None

    def list_alerts(
        self,
        *,
        source: str | None = None,
        min_severity: Severity | None = None,
        category: AlertCategory | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[NormalizedAlert], int]:
        query = select(AlertRecord)
        if source:
            query = query.where(AlertRecord.source == source)
        if min_severity:
            query = query.where(AlertRecord.severity_rank >= min_severity.rank)
        if category:
            query = query.where(AlertRecord.category == category.value)
        with self.db.session() as s:
            total = s.scalar(select(func.count()).select_from(query.subquery())) or 0
            rows = s.scalars(
                query.order_by(AlertRecord.timestamp.desc()).limit(limit).offset(offset)
            ).all()
            return [NormalizedAlert.model_validate(r.payload) for r in rows], total

    def find_related(
        self, alert: NormalizedAlert, *, window_hours: int = 24, limit: int = 20
    ) -> list[NormalizedAlert]:
        """Other alerts within +/- window that share at least one indicator."""
        keys = {(i.type.value, i.value.lower()) for i in alert.indicators}
        if not keys:
            return []
        center = _naive_utc(alert.timestamp)
        window = timedelta(hours=window_hours)
        query = (
            select(AlertRecord)
            .join(IndicatorRecord)
            .where(
                tuple_(IndicatorRecord.type, IndicatorRecord.value).in_(list(keys)),
                AlertRecord.id != alert.id,
                AlertRecord.timestamp.between(center - window, center + window),
            )
            .distinct()
            .order_by(AlertRecord.timestamp)
            .limit(limit)
        )
        with self.db.session() as s:
            return [NormalizedAlert.model_validate(r.payload) for r in s.scalars(query).all()]

    # -- analyses -----------------------------------------------------------
    def save_analysis(self, result: AnalysisResult) -> AnalysisResult:
        with self.db.session() as s:
            s.add(
                AnalysisRecord(
                    id=result.id,
                    alert_id=result.alert_id,
                    created_at=_naive_utc(result.created_at),
                    risk_score=result.assessment.risk_score,
                    risk_level=result.assessment.risk_level.value,
                    payload=result.model_dump(mode="json"),
                )
            )
        return result

    def list_analyses(self, alert_id: str) -> list[AnalysisResult]:
        query = (
            select(AnalysisRecord)
            .where(AnalysisRecord.alert_id == alert_id)
            .order_by(AnalysisRecord.created_at.desc())
        )
        with self.db.session() as s:
            return [AnalysisResult.model_validate(r.payload) for r in s.scalars(query).all()]

    def latest_analysis(self, alert_id: str) -> AnalysisResult | None:
        analyses = self.list_analyses(alert_id)
        return analyses[0] if analyses else None

    def high_risk_analyses(self, min_score: int = 70, limit: int = 50) -> list[AnalysisResult]:
        query = (
            select(AnalysisRecord)
            .where(AnalysisRecord.risk_score >= min_score)
            .order_by(AnalysisRecord.risk_score.desc(), AnalysisRecord.created_at.desc())
            .limit(limit)
        )
        with self.db.session() as s:
            return [AnalysisResult.model_validate(r.payload) for r in s.scalars(query).all()]

    @staticmethod
    def _to_record(alert: NormalizedAlert) -> AlertRecord:
        return AlertRecord(
            id=alert.id,
            source=alert.source,
            source_alert_id=alert.source_alert_id,
            title=alert.title,
            severity=alert.severity.value,
            severity_rank=alert.severity.rank,
            category=alert.category.value,
            timestamp=_naive_utc(alert.timestamp),
            ingested_at=_naive_utc(alert.ingested_at),
            payload=alert.model_dump(mode="json"),
            indicators=[
                IndicatorRecord(type=i.type.value, value=i.value.lower()) for i in alert.indicators
            ],
        )
