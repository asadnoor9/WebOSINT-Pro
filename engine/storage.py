"""
Persistence layer.

SQLite is the default so the platform runs with zero setup; PostgreSQL and
MySQL are supported by pointing ``WEBOSINT_DATABASE_URL`` at a SQLAlchemy DSN.
SQLAlchemy is an optional dependency: if it is absent the engine degrades to
in-memory history rather than failing to start.

Stored entities: targets, scans, findings, assets, technologies, certificates,
DNS records, reports and risk-score history.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG = logging.getLogger(__name__)

DEFAULT_DB_ENV = "WEBOSINT_DATABASE_URL"

try:  # pragma: no cover - exercised by availability, not by branch
    from sqlalchemy import (
        Boolean,
        Column,
        DateTime,
        Float,
        ForeignKey,
        Integer,
        String,
        Text,
        create_engine,
        func,
        select,
    )
    from sqlalchemy.orm import DeclarativeBase, Session, relationship

    SQLALCHEMY_AVAILABLE = True
except ImportError:  # pragma: no cover
    SQLALCHEMY_AVAILABLE = False


def default_database_url() -> str:
    """SQLite in the runtime directory unless the operator overrides it."""
    configured = os.environ.get(DEFAULT_DB_ENV, "").strip()
    if configured:
        return configured
    runtime = Path(os.environ.get("WEBOSINT_RUNTIME_DIR", "")) or None
    base = runtime if runtime and str(runtime) != "." else Path.home() / ".webosint"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    return f"sqlite:///{base / 'webosint.db'}"


if SQLALCHEMY_AVAILABLE:

    class Base(DeclarativeBase):
        """Declarative base for every persisted entity."""

    def _now() -> datetime:
        return datetime.now(timezone.utc)

    class Target(Base):
        """A host the platform tracks over time."""

        __tablename__ = "targets"

        id = Column(Integer, primary_key=True)
        hostname = Column(String(253), unique=True, nullable=False, index=True)
        first_seen = Column(DateTime, default=_now, nullable=False)
        last_seen = Column(DateTime, default=_now, onupdate=_now, nullable=False)
        notes = Column(Text, default="")

        scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

    class Scan(Base):
        """One execution of the pipeline against one target."""

        __tablename__ = "scans"

        id = Column(Integer, primary_key=True)
        target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
        started_at = Column(DateTime, default=_now, nullable=False, index=True)
        duration_ms = Column(Integer, default=0)
        surface = Column(String(32), default="unknown")
        risk_score = Column(Float, default=0.0)
        critical = Column(Integer, default=0)
        high = Column(Integer, default=0)
        medium = Column(Integer, default=0)
        low = Column(Integer, default=0)
        info = Column(Integer, default=0)
        active_mode = Column(Boolean, default=False)
        errors = Column(Text, default="")

        target = relationship("Target", back_populates="scans")
        findings = relationship("FindingRow", back_populates="scan", cascade="all, delete-orphan")
        technologies = relationship(
            "TechnologyRow", back_populates="scan", cascade="all, delete-orphan"
        )
        assets = relationship("AssetRow", back_populates="scan", cascade="all, delete-orphan")
        reports = relationship("ReportRow", back_populates="scan", cascade="all, delete-orphan")

    class FindingRow(Base):
        """A scored finding, kept for trend and regression analysis."""

        __tablename__ = "findings"

        id = Column(Integer, primary_key=True)
        scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
        fingerprint = Column(String(32), index=True)
        plugin = Column(String(64), index=True)
        title = Column(String(255))
        severity = Column(String(16), index=True)
        confidence = Column(Float, default=0.0)
        risk_score = Column(Float, default=0.0)
        verified = Column(Boolean, default=False)
        suppressed = Column(Boolean, default=False)
        false_positive_probability = Column(Float, default=0.0)
        validation_method = Column(String(32))
        exploitability = Column(String(32))
        payload = Column(Text, default="{}")

        scan = relationship("Scan", back_populates="findings")

    class TechnologyRow(Base):
        """A fingerprinted technology, used to track stack drift."""

        __tablename__ = "technologies"

        id = Column(Integer, primary_key=True)
        scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
        name = Column(String(64), index=True)
        category = Column(String(32))
        version = Column(String(32), default="")
        confidence = Column(Float, default=0.0)

        scan = relationship("Scan", back_populates="technologies")

    class AssetRow(Base):
        """A discovered asset (host, IP, endpoint) in the inventory."""

        __tablename__ = "assets"

        id = Column(Integer, primary_key=True)
        scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
        identifier = Column(String(512), index=True)
        kind = Column(String(32), index=True)
        source = Column(String(64))
        attributes = Column(Text, default="{}")

        scan = relationship("Scan", back_populates="assets")

    class CertificateRow(Base):
        """An observed TLS certificate, keyed by fingerprint."""

        __tablename__ = "certificates"

        id = Column(Integer, primary_key=True)
        hostname = Column(String(253), index=True)
        fingerprint = Column(String(95), index=True)
        issuer = Column(String(255), default="")
        subject = Column(String(255), default="")
        not_before = Column(DateTime, nullable=True)
        not_after = Column(DateTime, nullable=True)
        observed_at = Column(DateTime, default=_now, nullable=False)

    class DnsRecordRow(Base):
        """A DNS record observation, for change detection."""

        __tablename__ = "dns_records"

        id = Column(Integer, primary_key=True)
        hostname = Column(String(253), index=True)
        record_type = Column(String(16), index=True)
        value = Column(String(1024))
        observed_at = Column(DateTime, default=_now, nullable=False)

    class ReportRow(Base):
        """A generated report artefact on disk."""

        __tablename__ = "reports"

        id = Column(Integer, primary_key=True)
        scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
        fmt = Column(String(16))
        audience = Column(String(32), default="technical")
        path = Column(String(1024))
        created_at = Column(DateTime, default=_now, nullable=False)

        scan = relationship("Scan", back_populates="reports")

    class RiskScoreRow(Base):
        """Risk score over time, powering the dashboard timeline."""

        __tablename__ = "risk_scores"

        id = Column(Integer, primary_key=True)
        hostname = Column(String(253), index=True)
        score = Column(Float, default=0.0)
        recorded_at = Column(DateTime, default=_now, nullable=False, index=True)


@dataclass(slots=True)
class InMemoryStore:
    """Fallback used when SQLAlchemy is unavailable.

    Keeps the API identical so callers never branch on storage availability.
    """

    scans: list[dict[str, Any]] = field(default_factory=list)

    def record_scan(self, result: Any, *, active: bool = False) -> int:
        payload = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        payload["active_mode"] = active
        self.scans.append(payload)
        return len(self.scans)

    def history(self, hostname: str = "", limit: int = 50) -> list[dict[str, Any]]:
        rows = [row for row in self.scans if not hostname or row.get("target") == hostname]
        return rows[-limit:][::-1]

    def risk_timeline(self, hostname: str, limit: int = 100) -> list[dict[str, Any]]:
        return [
            {"recorded_at": row.get("started_at"), "score": row.get("risk_score", 0.0)}
            for row in self.history(hostname, limit)
        ]

    def targets(self) -> list[dict[str, Any]]:
        seen: dict[str, dict[str, Any]] = {}
        for row in self.scans:
            seen[row.get("target", "")] = {
                "hostname": row.get("target", ""),
                "last_seen": row.get("started_at"),
                "risk_score": row.get("risk_score", 0.0),
            }
        return list(seen.values())

    def close(self) -> None:
        return None


class Storage:
    """Facade over the database. Safe to construct even without SQLAlchemy."""

    def __init__(self, url: str | None = None, *, echo: bool = False) -> None:
        self.url = url or default_database_url()
        self._lock = threading.Lock()
        self._fallback: InMemoryStore | None = None
        self.engine = None

        if not SQLALCHEMY_AVAILABLE:
            LOG.warning("SQLAlchemy is not installed; scan history will not persist.")
            self._fallback = InMemoryStore()
            return

        connect_args = {"check_same_thread": False} if self.url.startswith("sqlite") else {}
        try:
            self.engine = create_engine(self.url, echo=echo, future=True, connect_args=connect_args)
            Base.metadata.create_all(self.engine)
        except Exception as exc:
            LOG.error("Could not open the database at %s: %s", self.url, exc)
            self._fallback = InMemoryStore()
            self.engine = None

    @property
    def available(self) -> bool:
        return self.engine is not None

    # -- writes ------------------------------------------------------------

    def record_scan(self, result: Any, *, active: bool = False) -> int:
        """Persist a completed scan and return its row id."""
        if self._fallback is not None:
            return self._fallback.record_scan(result, active=active)

        counts = result.severity_counts()
        with self._lock, Session(self.engine) as session:
            target = session.scalar(select(Target).where(Target.hostname == result.target))
            if target is None:
                target = Target(hostname=result.target)
                session.add(target)
                session.flush()
            target.last_seen = datetime.now(timezone.utc)

            scan = Scan(
                target_id=target.id,
                duration_ms=result.duration_ms,
                surface=result.surface.value,
                risk_score=result.risk_score,
                critical=counts["critical"],
                high=counts["high"],
                medium=counts["medium"],
                low=counts["low"],
                info=counts["info"],
                active_mode=active,
                errors=json.dumps(result.errors[:20]),
            )
            session.add(scan)
            session.flush()

            for finding in result.findings:
                session.add(
                    FindingRow(
                        scan_id=scan.id,
                        fingerprint=finding.fingerprint,
                        plugin=finding.plugin,
                        title=finding.title[:255],
                        severity=finding.severity.value,
                        confidence=finding.confidence,
                        risk_score=finding.risk_score,
                        verified=finding.verified,
                        suppressed=finding.suppressed,
                        false_positive_probability=finding.false_positive_probability,
                        validation_method=finding.validation_method.value,
                        exploitability=finding.exploitability.value,
                        payload=json.dumps(finding.to_dict())[:1_000_000],
                    )
                )

            for tech in result.technologies:
                session.add(
                    TechnologyRow(
                        scan_id=scan.id,
                        name=tech.name,
                        category=tech.category,
                        version=tech.version or "",
                        confidence=tech.confidence,
                    )
                )

            session.add(RiskScoreRow(hostname=result.target, score=result.risk_score))
            session.commit()
            return int(scan.id)

    def record_report(self, scan_id: int, fmt: str, path: str, audience: str = "technical") -> None:
        if not self.available:
            return
        with self._lock, Session(self.engine) as session:
            session.add(ReportRow(scan_id=scan_id, fmt=fmt, path=path, audience=audience))
            session.commit()

    # -- reads -------------------------------------------------------------

    def history(self, hostname: str = "", limit: int = 50) -> list[dict[str, Any]]:
        """Recent scans, newest first."""
        if self._fallback is not None:
            return self._fallback.history(hostname, limit)

        with Session(self.engine) as session:
            statement = select(Scan, Target).join(Target, Scan.target_id == Target.id)
            if hostname:
                statement = statement.where(Target.hostname == hostname)
            statement = statement.order_by(Scan.started_at.desc()).limit(limit)
            return [
                {
                    "id": scan.id,
                    "target": target.hostname,
                    "started_at": scan.started_at.isoformat() if scan.started_at else "",
                    "duration_ms": scan.duration_ms,
                    "surface": scan.surface,
                    "risk_score": scan.risk_score,
                    "severity_counts": {
                        "critical": scan.critical,
                        "high": scan.high,
                        "medium": scan.medium,
                        "low": scan.low,
                        "info": scan.info,
                    },
                }
                for scan, target in session.execute(statement).all()
            ]

    def risk_timeline(self, hostname: str, limit: int = 100) -> list[dict[str, Any]]:
        if self._fallback is not None:
            return self._fallback.risk_timeline(hostname, limit)
        with Session(self.engine) as session:
            statement = (
                select(RiskScoreRow)
                .where(RiskScoreRow.hostname == hostname)
                .order_by(RiskScoreRow.recorded_at.desc())
                .limit(limit)
            )
            return [
                {"recorded_at": row.recorded_at.isoformat(), "score": row.score}
                for row in session.scalars(statement)
            ]

    def targets(self) -> list[dict[str, Any]]:
        """The target inventory with its latest risk score."""
        if self._fallback is not None:
            return self._fallback.targets()
        with Session(self.engine) as session:
            statement = (
                select(
                    Target.hostname,
                    Target.first_seen,
                    Target.last_seen,
                    func.count(Scan.id),
                )
                .outerjoin(Scan, Scan.target_id == Target.id)
                .group_by(Target.id)
            )
            return [
                {
                    "hostname": hostname,
                    "first_seen": first_seen.isoformat() if first_seen else "",
                    "last_seen": last_seen.isoformat() if last_seen else "",
                    "scan_count": count,
                }
                for hostname, first_seen, last_seen, count in session.execute(statement).all()
            ]

    def new_findings(self, hostname: str) -> list[str]:
        """Fingerprints present in the newest scan but not the one before it."""
        if not self.available:
            return []
        with Session(self.engine) as session:
            scans = session.scalars(
                select(Scan)
                .join(Target, Scan.target_id == Target.id)
                .where(Target.hostname == hostname)
                .order_by(Scan.started_at.desc())
                .limit(2)
            ).all()
            if len(scans) < 2:
                return []
            newest = {row.fingerprint for row in scans[0].findings if not row.suppressed}
            previous = {row.fingerprint for row in scans[1].findings if not row.suppressed}
            return sorted(newest - previous)

    def close(self) -> None:
        if self.engine is not None:
            self.engine.dispose()
