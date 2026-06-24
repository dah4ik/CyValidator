import os
import time
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, declarative_base, sessionmaker


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://cyvalidator:cyvalidator@postgres:5432/cyvalidator",
)

JWT_SECRET = os.getenv("JWT_SECRET", "change_me_in_production")
JWT_ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

security = HTTPBearer()


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    tenant_slug = Column(String(120), index=True, nullable=False)

    name = Column(String(150), nullable=False)
    hostname = Column(String(150), nullable=False)
    ip_address = Column(String(50), nullable=False)

    asset_type = Column(String(80), nullable=False)
    os_type = Column(String(80), nullable=False)
    environment = Column(String(80), nullable=False)

    network_zone = Column(String(120), nullable=False)
    business_owner = Column(String(150), nullable=False)
    technical_owner = Column(String(150), nullable=False)

    business_criticality = Column(Integer, nullable=False)
    exposure_level = Column(String(80), nullable=False)

    tags = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)

    status = Column(String(50), default="active", nullable=False)

    created_at = Column(DateTime)
    updated_at = Column(DateTime)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)

    tenant_slug = Column(String(120), index=True, nullable=False)

    asset_id = Column(Integer, nullable=False)
    asset_name = Column(String(150), nullable=False)
    asset_hostname = Column(String(150), nullable=False)
    network_zone = Column(String(120), nullable=False)

    title = Column(String(200), nullable=False)
    category = Column(String(120), nullable=False)
    severity = Column(String(50), nullable=False)
    risk_score = Column(Integer, nullable=False)

    status = Column(String(80), default="open", nullable=False)
    owner = Column(String(150), nullable=False)
    sla_days = Column(Integer, nullable=False)

    evidence = Column(Text, nullable=False)
    technical_details = Column(Text, nullable=False)
    business_impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)

    validation_pack = Column(String(150), nullable=True)
    control_id = Column(String(150), nullable=True)
    mitre_technique = Column(String(150), nullable=True)

    created_at = Column(DateTime)
    updated_at = Column(DateTime)


app = FastAPI(
    title="CyValidator Risk Engine",
    description="Enterprise risk scoring, security score and remediation priority engine for CyValidator",
    version="0.1.0",
)


def wait_for_database(max_attempts: int = 20, delay_seconds: int = 2) -> None:
    for attempt in range(1, max_attempts + 1):
        try:
            connection = engine.connect()
            connection.close()
            return
        except OperationalError:
            print(f"Database not ready. Attempt {attempt}/{max_attempts}")
            time.sleep(delay_seconds)

    raise RuntimeError("Database connection failed after multiple attempts")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


def get_current_identity(
        credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    payload = decode_access_token(credentials.credentials)

    required_fields = ["sub", "email", "tenant", "role"]

    for field in required_fields:
        if field not in payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )

    return payload


def severity_weight(severity: str) -> int:
    mapping = {
        "critical": 40,
        "high": 30,
        "medium": 15,
        "low": 5,
    }

    return mapping.get(severity.lower(), 10)


def exposure_weight(exposure_level: str) -> int:
    mapping = {
        "public": 20,
        "internet": 20,
        "external": 20,
        "internal": 10,
        "restricted": 4,
        "management": 12,
    }

    return mapping.get(exposure_level.lower(), 8)


def status_multiplier(finding_status: str) -> float:
    mapping = {
        "open": 1.0,
        "assigned": 0.95,
        "in_progress": 0.85,
        "waiting_for_approval": 0.75,
        "fixed": 0.15,
        "validated": 0.0,
        "risk_accepted": 0.35,
        "false_positive": 0.0,
    }

    return mapping.get(finding_status.lower(), 1.0)


def normalize_score(score: float) -> int:
    if score < 0:
        return 0

    if score > 100:
        return 100

    return round(score)


def get_asset_by_id(db: Session, tenant_slug: str, asset_id: int) -> Optional[Asset]:
    return (
        db.query(Asset)
        .filter(Asset.tenant_slug == tenant_slug)
        .filter(Asset.id == asset_id)
        .first()
    )


def calculate_finding_enterprise_risk(
        finding: Finding,
        asset: Optional[Asset],
) -> dict:
    base = severity_weight(finding.severity)

    asset_criticality_score = 0
    exposure_score = 0

    if asset:
        asset_criticality_score = asset.business_criticality * 6
        exposure_score = exposure_weight(asset.exposure_level)

    status_factor = status_multiplier(finding.status)

    raw_score = (
            base
            + asset_criticality_score
            + exposure_score
            + min(finding.risk_score * 0.25, 25)
    )

    final_score = normalize_score(raw_score * status_factor)

    return {
        "finding_id": finding.id,
        "title": finding.title,
        "asset_id": finding.asset_id,
        "asset_name": finding.asset_name,
        "asset_hostname": finding.asset_hostname,
        "network_zone": finding.network_zone,
        "severity": finding.severity,
        "status": finding.status,
        "original_risk_score": finding.risk_score,
        "enterprise_risk_score": final_score,
        "risk_components": {
            "severity_weight": base,
            "asset_criticality_score": asset_criticality_score,
            "exposure_score": exposure_score,
            "finding_score_component": round(min(finding.risk_score * 0.25, 25), 2),
            "status_multiplier": status_factor,
        },
        "owner": finding.owner,
        "sla_days": finding.sla_days,
        "remediation": finding.remediation,
    }


def calculate_security_score(findings: list[Finding]) -> int:
    if not findings:
        return 100

    active_findings = [
        finding for finding in findings
        if finding.status not in ["validated", "false_positive"]
    ]

    if not active_findings:
        return 100

    weighted_risk = 0

    for finding in active_findings:
        weighted_risk += finding.risk_score * status_multiplier(finding.status)

    average_risk = weighted_risk / len(active_findings)

    security_score = 100 - average_risk

    return normalize_score(security_score)


def risk_level(score: int) -> str:
    if score >= 81:
        return "Critical"
    if score >= 61:
        return "High"
    if score >= 31:
        return "Medium"
    return "Low"


@app.on_event("startup")
def on_startup():
    wait_for_database()


@app.get("/health")
def health_check():
    return {
        "service": "risk-engine",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/info")
def service_info():
    return {
        "name": "CyValidator Risk Engine",
        "role": "Calculates enterprise risk, security score, top priorities and remediation ROI",
        "version": "0.1.0",
    }


@app.get("/api/risk/summary")
def risk_summary(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    tenant_slug = identity["tenant"]

    assets = db.query(Asset).filter(Asset.tenant_slug == tenant_slug).all()
    findings = db.query(Finding).filter(Finding.tenant_slug == tenant_slug).all()

    total_assets = len(assets)
    total_findings = len(findings)

    active_findings = [
        finding for finding in findings
        if finding.status not in ["validated", "false_positive"]
    ]

    security_score = calculate_security_score(findings)

    critical_findings = len([
        finding for finding in active_findings
        if finding.severity.lower() == "critical"
    ])

    high_findings = len([
        finding for finding in active_findings
        if finding.severity.lower() == "high"
    ])

    open_findings = len([
        finding for finding in active_findings
        if finding.status == "open"
    ])

    public_assets = len([
        asset for asset in assets
        if asset.exposure_level.lower() == "public"
    ])

    critical_assets = len([
        asset for asset in assets
        if asset.business_criticality >= 5
    ])

    enterprise_risk_items = []

    for finding in findings:
        asset = get_asset_by_id(db, tenant_slug, finding.asset_id)
        enterprise_risk_items.append(
            calculate_finding_enterprise_risk(finding, asset)
        )

    average_enterprise_risk = 0

    if enterprise_risk_items:
        average_enterprise_risk = round(
            sum(item["enterprise_risk_score"] for item in enterprise_risk_items)
            / len(enterprise_risk_items),
            2,
            )

    return {
        "tenant": tenant_slug,
        "security_score": security_score,
        "security_level": risk_level(100 - security_score),
        "average_enterprise_risk": average_enterprise_risk,
        "total_assets": total_assets,
        "critical_assets": critical_assets,
        "public_assets": public_assets,
        "total_findings": total_findings,
        "active_findings": len(active_findings),
        "open_findings": open_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "risk_statement": "Security score is calculated from active findings, severity, exposure and remediation status.",
    }


@app.get("/api/risk/security-score")
def security_score(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    findings = (
        db.query(Finding)
        .filter(Finding.tenant_slug == identity["tenant"])
        .all()
    )

    score = calculate_security_score(findings)

    return {
        "tenant": identity["tenant"],
        "security_score": score,
        "risk_level": risk_level(100 - score),
        "explanation": "A higher score means fewer unresolved high-risk findings.",
    }


@app.get("/api/risk/priorities")
def remediation_priorities(
        limit: int = 5,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    tenant_slug = identity["tenant"]

    findings = (
        db.query(Finding)
        .filter(Finding.tenant_slug == tenant_slug)
        .all()
    )

    priority_items = []

    for finding in findings:
        if finding.status in ["validated", "false_positive"]:
            continue

        asset = get_asset_by_id(db, tenant_slug, finding.asset_id)
        item = calculate_finding_enterprise_risk(finding, asset)

        effort = "Medium"

        if finding.category in ["Linux Hardening", "Logging and Monitoring"]:
            effort = "Low"

        if finding.category in ["Network Segmentation", "Database Exposure"]:
            effort = "Medium"

        if finding.category in ["Container Security"]:
            effort = "Medium"

        risk_reduction = item["enterprise_risk_score"]

        if finding.status == "risk_accepted":
            risk_reduction = round(risk_reduction * 0.4)

        item["estimated_effort"] = effort
        item["estimated_risk_reduction"] = risk_reduction
        item["priority_reason"] = (
            f"{finding.severity} severity finding on {finding.asset_hostname} "
            f"with enterprise risk score {item['enterprise_risk_score']}."
        )

        priority_items.append(item)

    sorted_items = sorted(
        priority_items,
        key=lambda item: item["enterprise_risk_score"],
        reverse=True,
    )

    return {
        "tenant": tenant_slug,
        "priorities": sorted_items[:limit],
    }


@app.get("/api/risk/assets")
def risky_assets(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    tenant_slug = identity["tenant"]

    assets = db.query(Asset).filter(Asset.tenant_slug == tenant_slug).all()
    findings = db.query(Finding).filter(Finding.tenant_slug == tenant_slug).all()

    asset_map = {}

    for asset in assets:
        asset_map[asset.id] = {
            "asset_id": asset.id,
            "asset_name": asset.name,
            "hostname": asset.hostname,
            "network_zone": asset.network_zone,
            "business_criticality": asset.business_criticality,
            "exposure_level": asset.exposure_level,
            "findings_count": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "max_enterprise_risk": 0,
            "total_enterprise_risk": 0,
        }

    for finding in findings:
        if finding.status in ["validated", "false_positive"]:
            continue

        asset = get_asset_by_id(db, tenant_slug, finding.asset_id)
        risk_item = calculate_finding_enterprise_risk(finding, asset)

        if finding.asset_id not in asset_map:
            continue

        asset_map[finding.asset_id]["findings_count"] += 1
        asset_map[finding.asset_id]["max_enterprise_risk"] = max(
            asset_map[finding.asset_id]["max_enterprise_risk"],
            risk_item["enterprise_risk_score"],
        )
        asset_map[finding.asset_id]["total_enterprise_risk"] += risk_item["enterprise_risk_score"]

        if finding.severity.lower() == "critical":
            asset_map[finding.asset_id]["critical_findings"] += 1

        if finding.severity.lower() == "high":
            asset_map[finding.asset_id]["high_findings"] += 1

    sorted_assets = sorted(
        asset_map.values(),
        key=lambda item: item["total_enterprise_risk"],
        reverse=True,
    )

    return {
        "tenant": tenant_slug,
        "assets": sorted_assets,
    }


@app.get("/api/risk/remediation-roi")
def remediation_roi(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    tenant_slug = identity["tenant"]

    findings = (
        db.query(Finding)
        .filter(Finding.tenant_slug == tenant_slug)
        .all()
    )

    roi_items = []

    for finding in findings:
        if finding.status in ["validated", "false_positive", "fixed"]:
            continue

        asset = get_asset_by_id(db, tenant_slug, finding.asset_id)
        risk_item = calculate_finding_enterprise_risk(finding, asset)

        effort_score = 2

        if finding.category in ["Linux Hardening", "Logging and Monitoring"]:
            effort_score = 1
        elif finding.category in ["Network Segmentation", "Database Exposure"]:
            effort_score = 2
        elif finding.category in ["Container Security"]:
            effort_score = 2
        else:
            effort_score = 3

        roi_score = round(risk_item["enterprise_risk_score"] / effort_score, 2)

        roi_items.append({
            "finding_id": finding.id,
            "title": finding.title,
            "asset_hostname": finding.asset_hostname,
            "category": finding.category,
            "severity": finding.severity,
            "enterprise_risk_score": risk_item["enterprise_risk_score"],
            "estimated_effort_score": effort_score,
            "remediation_roi_score": roi_score,
            "recommended_action": finding.remediation,
        })

    sorted_items = sorted(
        roi_items,
        key=lambda item: item["remediation_roi_score"],
        reverse=True,
    )

    return {
        "tenant": tenant_slug,
        "message": "Higher ROI means higher risk reduction for lower remediation effort.",
        "items": sorted_items,
    }