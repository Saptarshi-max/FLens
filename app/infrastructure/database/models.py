from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base declarative model for SQLAlchemy tables."""


class FirmwareRecord(Base):
    __tablename__ = "firmware"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    architecture: Mapped[str] = mapped_column(String(128), nullable=False)
    filesystem_type: Mapped[str] = mapped_column(String(128), nullable=False)
    extracted_path: Mapped[str] = mapped_column(Text, nullable=False)
    kernel_information: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor_information: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    scans: Mapped[list[ScanRecord]] = relationship(back_populates="firmware")


class ScanRecord(Base):
    __tablename__ = "scan"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    firmware_id: Mapped[int] = mapped_column(ForeignKey("firmware.id"), nullable=False)
    risk_score: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    firmware: Mapped[FirmwareRecord] = relationship(back_populates="scans")
    components: Mapped[list[ComponentRecord]] = relationship(back_populates="scan")
    vulnerabilities: Mapped[list[VulnerabilityRecord]] = relationship(back_populates="scan")
    sboms: Mapped[list[SBOMRecord]] = relationship(back_populates="scan")


class ComponentRecord(Base):
    __tablename__ = "component"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="LOW")
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    scan: Mapped[ScanRecord] = relationship(back_populates="components")


class VulnerabilityRecord(Base):
    __tablename__ = "vulnerability"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id"), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    component_name: Mapped[str] = mapped_column(String(255), nullable=False, default="Unknown")
    component_version: Mapped[str] = mapped_column(String(64), nullable=False, default="Unknown")
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="LOW")
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    scan: Mapped[ScanRecord] = relationship(back_populates="vulnerabilities")


class SBOMRecord(Base):
    __tablename__ = "sbom"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id"), nullable=False)
    format: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped[ScanRecord] = relationship(back_populates="sboms")
