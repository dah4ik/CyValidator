import os
import time
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
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

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class FindingCreateRequest(BaseModel):
    asset_id: int
    asset_name: str = Field(..., min_length=2, max_length=150)
    asset_hostname: str = Field(..., min_length=2, max_length=150)
    network_zone: str = Field(..., min_length=2, max_length=120)

    title: str = Field(..., min_length=3, max_length=200)
    category: str = Field(..., min_length=2, max_length=120)
    severity: str = Field(..., min_length=2, max_length=50)
    risk_score: int = Field(..., ge=0, le=100)

    owner: str = Field(..., min_length=2, max_length=150)
    sla_days: int = Field(..., ge=1, le=365)

    evidence: str = Field(..., min_length=3)
    technical_details: str = Field(..., min_length=3)
    business_impact: str = Field(..., min_length=3)
    remediation: str = Field(..., min_length=3)

    validation_pack: Optional[str] = None
    control_id: Optional[str] = None
    mitre_technique: Optional[str] = None


class FindingUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=200)
    category: Optional[str] = Field(None, min_length=2, max_length=120)
    severity: Optional[str] = Field(None, min_length=2, max_length=50)
    risk_score: Optional[int] = Field(None, ge=0, le=100)

    status: Optional[str] = Field(None, min_length=2, max_length=80)
    owner: Optional[str] = Field(None, min_length=2, max_length=150)
    sla_days: Optional[int] = Field(None, ge=1, le=365)

    evidence: Optional[str] = Field(None, min_length=3)
    technical_details: Optional[str] = Field(None, min_length=3)
    business_impact: Optional[str] = Field(None, min_length=3)
    remediation: Optional[str] = Field(None, min_length=3)

    validation_pack: Optional[str] = None
    control_id: Optional[str] = None
    mitre_technique: Optional[str] = None


class FindingStatusUpdateRequest(BaseModel):
    status: str = Field(..., min_length=2, max_length=80)


class FindingResponse(BaseModel):
    id: int
    tenant_slug: str

    asset_id: int
    asset_name: str
    asset_hostname: str
    network_zone: str

    title: str
    category: str
    severity: str
    risk_score: int

    status: str
    owner: str
    sla_days: int

    evidence: str
    technical_details: str
    business_impact: str
    remediation: str

    validation_pack: Optional[str]
    control_id: Optional[str]
    mitre_technique: Optional[str]

    created_at: datetime
    updated_at: datetime


app = FastAPI(
    title="CyValidator Findings Service",
    description="Findings, evidence, severity, remediation and status lifecycle management for CyValidator",
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


def require_finding_write_permission(identity: dict = Depends(get_current_identity)) -> dict:
    allowed_roles = [
        "Platform Admin",
        "Security Manager",
        "Security Analyst",
    ]

    if identity["role"] not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Finding write permission required",
        )

    return identity


def require_finding_delete_permission(identity: dict = Depends(get_current_identity)) -> dict:
    allowed_roles = [
        "Platform Admin",
        "Security Manager",
    ]

    if identity["role"] not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Finding delete permission required",
        )

    return identity


def calculate_sla_days(severity: str) -> int:
    severity_lower = severity.lower()

    if severity_lower == "critical":
        return 7
    if severity_lower == "high":
        return 14
    if severity_lower == "medium":
        return 30
    return 60


def seed_demo_findings(db: Session) -> None:
    existing = (
        db.query(Finding)
        .filter(Finding.tenant_slug == "demo-enterprise")
        .filter(Finding.title == "SSH root login is enabled")
        .first()
    )

    if existing:
        return

    demo_findings = [
        Finding(
            tenant_slug="demo-enterprise",
            asset_id=1,
            asset_name="Linux Web Server",
            asset_hostname="linux-web-01",
            network_zone="DMZ",
            title="SSH root login is enabled",
            category="Linux Hardening",
            severity="High",
            risk_score=82,
            status="open",
            owner="Infrastructure Team",
            sla_days=14,
            evidence="PermitRootLogin yes was detected in the simulated SSH configuration.",
            technical_details="The SSH service allows direct privileged login. This increases the risk of credential-based compromise and privileged access abuse.",
            business_impact="A compromised root account on a public-facing server may allow an attacker to control the server and pivot toward internal systems.",
            remediation="Disable SSH root login by setting PermitRootLogin no and restart the SSH service.",
            validation_pack="Linux Hardening Pack",
            control_id="LINUX-SSH-001",
            mitre_technique="T1021.004",
        ),
        Finding(
            tenant_slug="demo-enterprise",
            asset_id=2,
            asset_name="PostgreSQL Database",
            asset_hostname="db-postgres-01",
            network_zone="Database Zone",
            title="Database service is exposed outside the application network",
            category="Database Exposure",
            severity="Critical",
            risk_score=94,
            status="open",
            owner="Database Team",
            sla_days=7,
            evidence="PostgreSQL port 5432 is reachable from a non-application network segment in the lab topology.",
            technical_details="The database should only be reachable from approved application services or administrative jump hosts.",
            business_impact="Unauthorized access to the database may expose sensitive business data and create regulatory and operational risk.",
            remediation="Restrict database access using network segmentation and allow only approved application hosts.",
            validation_pack="Database Exposure Pack",
            control_id="DB-NET-001",
            mitre_technique="T1046",
        ),
        Finding(
            tenant_slug="demo-enterprise",
            asset_id=3,
            asset_name="Docker Runtime Host",
            asset_hostname="docker-host-01",
            network_zone="Server Zone",
            title="Privileged container execution is allowed",
            category="Container Security",
            severity="Critical",
            risk_score=91,
            status="open",
            owner="DevOps Team",
            sla_days=7,
            evidence="A simulated container was detected running with privileged mode enabled.",
            technical_details="Privileged containers have extended host-level capabilities and can weaken container isolation.",
            business_impact="Container isolation failure may allow compromise of the host and other workloads.",
            remediation="Avoid privileged containers, remove dangerous capabilities and enforce least privilege runtime policies.",
            validation_pack="Docker Security Pack",
            control_id="DOCKER-RUNTIME-001",
            mitre_technique="T1611",
        ),
        Finding(
            tenant_slug="demo-enterprise",
            asset_id=4,
            asset_name="Corporate Workstation",
            asset_hostname="win-client-01",
            network_zone="User Zone",
            title="Endpoint can communicate with database zone",
            category="Network Segmentation",
            severity="High",
            risk_score=78,
            status="in_progress",
            owner="Network Team",
            sla_days=14,
            evidence="User Zone to Database Zone connectivity was detected in the simulated segmentation matrix.",
            technical_details="Workstations should not have direct access to database services unless explicitly approved.",
            business_impact="Unnecessary lateral movement paths may increase the impact of compromised endpoints.",
            remediation="Block direct workstation access to the database zone and enforce application-mediated access.",
            validation_pack="Network Segmentation Pack",
            control_id="NET-SEG-001",
            mitre_technique="T1021",
        ),
        Finding(
            tenant_slug="demo-enterprise",
            asset_id=5,
            asset_name="Management Jump Server",
            asset_hostname="jump-mgmt-01",
            network_zone="Management Zone",
            title="Security audit logging is incomplete",
            category="Logging and Monitoring",
            severity="Medium",
            risk_score=55,
            status="open",
            owner="Security Operations",
            sla_days=30,
            evidence="Authentication and privileged command events are not marked as forwarded to the central monitoring layer.",
            technical_details="Missing audit events reduce investigation quality and weaken detection coverage.",
            business_impact="Security operations may not have sufficient evidence during incident response.",
            remediation="Enable authentication, authorization and privileged activity logs and forward them to the monitoring platform.",
            validation_pack="Logging and Monitoring Pack",
            control_id="LOG-AUDIT-001",
            mitre_technique="T1562.002",
        ),
    ]

    db.add_all(demo_findings)
    db.commit()


@app.on_event("startup")
def on_startup():
    wait_for_database()
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed_demo_findings(db)
    finally:
        db.close()


@app.get("/health")
def health_check():
    return {
        "service": "findings-service",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/info")
def service_info():
    return {
        "name": "CyValidator Findings Service",
        "role": "Manages security findings, evidence, severity, risk score, remediation and status lifecycle",
        "version": "0.1.0",
    }


@app.get("/api/findings", response_model=list[FindingResponse])
def list_findings(
        status_filter: Optional[str] = None,
        severity: Optional[str] = None,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    query = db.query(Finding).filter(Finding.tenant_slug == identity["tenant"])

    if status_filter:
        query = query.filter(Finding.status == status_filter)

    if severity:
        query = query.filter(Finding.severity == severity)

    findings = query.order_by(Finding.risk_score.desc(), Finding.id.asc()).all()

    return findings


@app.get("/api/findings/summary")
def findings_summary(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    findings = (
        db.query(Finding)
        .filter(Finding.tenant_slug == identity["tenant"])
        .all()
    )

    total = len(findings)
    open_findings = len([finding for finding in findings if finding.status == "open"])
    in_progress = len([finding for finding in findings if finding.status == "in_progress"])
    fixed = len([finding for finding in findings if finding.status == "fixed"])
    risk_accepted = len([finding for finding in findings if finding.status == "risk_accepted"])

    critical = len([finding for finding in findings if finding.severity.lower() == "critical"])
    high = len([finding for finding in findings if finding.severity.lower() == "high"])
    medium = len([finding for finding in findings if finding.severity.lower() == "medium"])
    low = len([finding for finding in findings if finding.severity.lower() == "low"])

    average_risk_score = 0

    if total > 0:
        average_risk_score = round(
            sum(finding.risk_score for finding in findings) / total,
            2,
            )

    top_risky_assets = {}

    for finding in findings:
        if finding.asset_hostname not in top_risky_assets:
            top_risky_assets[finding.asset_hostname] = {
                "asset_hostname": finding.asset_hostname,
                "asset_name": finding.asset_name,
                "findings_count": 0,
                "max_risk_score": 0,
            }

        top_risky_assets[finding.asset_hostname]["findings_count"] += 1
        top_risky_assets[finding.asset_hostname]["max_risk_score"] = max(
            top_risky_assets[finding.asset_hostname]["max_risk_score"],
            finding.risk_score,
        )

    sorted_top_assets = sorted(
        top_risky_assets.values(),
        key=lambda item: item["max_risk_score"],
        reverse=True,
    )

    return {
        "tenant": identity["tenant"],
        "total_findings": total,
        "open_findings": open_findings,
        "in_progress_findings": in_progress,
        "fixed_findings": fixed,
        "risk_accepted_findings": risk_accepted,
        "severity_breakdown": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "average_risk_score": average_risk_score,
        "top_risky_assets": sorted_top_assets[:5],
    }


@app.get("/api/findings/{finding_id}", response_model=FindingResponse)
def get_finding(
        finding_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .filter(Finding.tenant_slug == identity["tenant"])
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return finding


@app.post("/api/findings", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
def create_finding(
        payload: FindingCreateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_finding_write_permission),
):
    finding = Finding(
        tenant_slug=identity["tenant"],
        asset_id=payload.asset_id,
        asset_name=payload.asset_name,
        asset_hostname=payload.asset_hostname,
        network_zone=payload.network_zone,
        title=payload.title,
        category=payload.category,
        severity=payload.severity,
        risk_score=payload.risk_score,
        status="open",
        owner=payload.owner,
        sla_days=payload.sla_days,
        evidence=payload.evidence,
        technical_details=payload.technical_details,
        business_impact=payload.business_impact,
        remediation=payload.remediation,
        validation_pack=payload.validation_pack,
        control_id=payload.control_id,
        mitre_technique=payload.mitre_technique,
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    return finding


@app.put("/api/findings/{finding_id}", response_model=FindingResponse)
def update_finding(
        finding_id: int,
        payload: FindingUpdateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_finding_write_permission),
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .filter(Finding.tenant_slug == identity["tenant"])
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    update_data = payload.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(finding, field, value)

    finding.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(finding)

    return finding


@app.patch("/api/findings/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
        finding_id: int,
        payload: FindingStatusUpdateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_finding_write_permission),
):
    allowed_statuses = [
        "open",
        "assigned",
        "in_progress",
        "waiting_for_approval",
        "fixed",
        "validated",
        "risk_accepted",
        "false_positive",
    ]

    if payload.status not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Allowed values: {allowed_statuses}",
        )

    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .filter(Finding.tenant_slug == identity["tenant"])
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    finding.status = payload.status
    finding.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(finding)

    return finding


@app.delete("/api/findings/{finding_id}")
def delete_finding(
        finding_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_finding_delete_permission),
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .filter(Finding.tenant_slug == identity["tenant"])
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    db.delete(finding)
    db.commit()

    return {
        "message": "Finding deleted successfully",
        "finding_id": finding_id,
    }