"""SQLAlchemy persistence models for scan history and asset intelligence."""

from __future__ import annotations

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    target_type: Mapped[str] = mapped_column(String(32), default="domain")
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scans: Mapped[list[Scan]] = relationship(back_populates="target")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    profile: Mapped[str] = mapped_column(String(64), default="medium")
    started_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), nullable=True)
    elapsed_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)

    target: Mapped[Target] = relationship(back_populates="scans")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    asset_type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)


class Technology(Base):
    __tablename__ = "technologies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str] = mapped_column(String(128), default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    source: Mapped[str] = mapped_column(String(128), default="")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    module: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(32), index=True, default="info")
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str] = mapped_column(Text, default="")

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    identifier: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[dict] = mapped_column(JSON, default=dict)


class Screenshot(Base):
    __tablename__ = "screenshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    url: Mapped[str] = mapped_column(String(1024))
    path: Mapped[str] = mapped_column(String(1024))
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
