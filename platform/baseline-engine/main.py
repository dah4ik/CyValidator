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


class BaselineControl(Base):
    __tablename__ = "baseline_controls"

    id = Column(Integer, primary_key=True, index=True)

    tenant_slug = Column(String(120), index=True, nullable=False)

    asset_id = Column(Integer, nullable=False)
    asset_name = Column(String(150), nullable=False)
    asset_hostname = Column(String(150), nullable=False)
    network_zone = Column(String(120), nullable=False)

    control_id = Column(String(150), nullable=False)
    control_name = Column(String(200), nullable=False)
    category = Column(String(120), nullable=False)

    desired_state = Column(String(255), nullable=False)
    actual_state = Column(String(255), nullable=False)

    status = Column(String(50), nullable=False)
    severity = Column(String(50), nullable=False)

    evidence = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)

    validation_pack = Column(String(150), nullable=True)
    framework = Column(String(150), nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class BaselineControlCreateRequest(BaseModel):
    asset_id: int
    asset_name: str = Field(..., min_length=2, max_length=150)
    asset_hostname: str = Field(..., min_length=2, max_length=150)
    network_zone: str = Field(..., min_length=2, max_length=120)

    control_id: str = Field(..., min_length=2, max_length=150)
    control_name: str = Field(..., min_length=2, max_length=200)
    category: str = Field(..., min_length=2, max_length=120)

    desired_state: str = Field(..., min_length=1, max_length=255)
    actual_state: str = Field(..., min_length=1, max_length=255)

    status: str = Field(..., min_length=2, max_length=50)
    severity: str = Field(..., min_length=2, max_length=50)

    evidence: str = Field(..., min_length=3)
    recommendation: str = Field(..., min_length=3)

    validation_pack: Optional[str] = None
    framework: Optional[str] = None


class BaselineControlUpdateRequest(BaseModel):
    desired_state: Optional[str] = Field(None, min_length=1, max_length=255)
    actual_state: Optional[str] = Field(None, min_length=1, max_length=255)
    status: Optional[str] = Field(None, min_length=2, max_length=50)
    severity: Optional[str] = Field(None, min_length=2, max_length=50)
    evidence: Optional[str] = Field(None, min_length=3)
    recommendation: Optional[str] = Field(None, min_length=3)


class BaselineControlResponse(BaseModel):
    id: int
    tenant_slug: str

    asset_id: int
    asset_name: str
    asset_hostname: str
    network_zone: str

    control_id: str
    control_name: str
    category: str

    desired_state: str
    actual_state: str

    status: str
    severity: str

    evidence: str
    recommendation: str

    validation_pack: Optional[str]
    framework: Optional[str]

    created_at: datetime
    updated_at: datetime


app = FastAPI(
    title="CyValidator Baseline Engine",
    description="Desired vs actual security control validation and compliance scoring for CyValidator",
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


def require_baseline_write_permission(identity: dict = Depends(get_current_identity)) -> dict:
    allowed_roles = [
        "Platform Admin",
        "Security Manager",
        "Security Analyst",
    ]

    if identity["role"] not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Baseline write permission required",
        )

    return identity


def seed_demo_baseline_controls(db: Session) -> None:
    existing = (
        db.query(BaselineControl)
        .filter(BaselineControl.tenant_slug == "demo-enterprise")
        .filter(BaselineControl.control_id == "LINUX-SSH-001")
        .first()
    )

    if existing:
        return

    demo_controls = [
        BaselineControl(
            tenant_slug="demo-enterprise",
            asset_id=1,
            asset_name="Linux Web Server",
            asset_hostname="linux-web-01",
            network_zone="DMZ",
            control_id="LINUX-SSH-001",
            control_name="SSH root login must be disabled",
            category="Linux Hardening",
            desired_state="PermitRootLogin no",
            actual_state="PermitRootLogin yes",
            status="failed",
            severity="High",
            evidence="Simulated SSH configuration shows direct root login is enabled.",
            recommendation="Disable SSH root login and restart the SSH service.",
            validation_pack="Linux Hardening Pack",
            framework="Internal Linux Baseline",
        ),
        BaselineControl(
            tenant_slug="demo-enterprise",
            asset_id=1,
            asset_name="Linux Web Server",
            asset_hostname="linux-web-01",
            network_zone="DMZ",
            control_id="LINUX-FW-001",
            control_name="Host firewall must be enabled",
            category="Linux Hardening",
            desired_state="Firewall enabled",
            actual_state="Firewall disabled",
            status="failed",
            severity="High",
            evidence="Host firewall state is marked as disabled in the simulated baseline state.",
            recommendation="Enable host firewall and allow only required inbound services.",
            validation_pack="Linux Hardening Pack",
            framework="Internal Linux Baseline",
        ),
        BaselineControl(
            tenant_slug="demo-enterprise",
            asset_id=2,
            asset_name="PostgreSQL Database",
            asset_hostname="db-postgres-01",
            network_zone="Database Zone",
            control_id="DB-NET-001",
            control_name="Database must be reachable only from application zone",
            category="Database Exposure",
            desired_state="Application Zone only",
            actual_state="Reachable from User Zone and Server Zone",
            status="failed",
            severity="Critical",
            evidence="Simulated network matrix allows non-application access to PostgreSQL.",
            recommendation="Restrict PostgreSQL network access to approved application hosts only.",
            validation_pack="Database Exposure Pack",
            framework="Internal Database Baseline",
        ),
        BaselineControl(
            tenant_slug="demo-enterprise",
            asset_id=3,
            asset_name="Docker Runtime Host",
            asset_hostname="docker-host-01",
            network_zone="Server Zone",
            control_id="DOCKER-RUNTIME-001",
            control_name="Privileged containers must be disabled",
            category="Docker Security",
            desired_state="Privileged mode disabled",
            actual_state="Privileged mode enabled",
            status="failed",
            severity="Critical",
            evidence="A simulated container runtime configuration allows privileged containers.",
            recommendation="Remove privileged mode and enforce least privilege container runtime policy.",
            validation_pack="Docker Security Pack",
            framework="Internal Container Security Baseline",
        ),
        BaselineControl(
            tenant_slug="demo-enterprise",
            asset_id=3,
            asset_name="Docker Runtime Host",
            asset_hostname="docker-host-01",
            network_zone="Server Zone",
            control_id="DOCKER-USER-001",
            control_name="Containers should not run as root",
            category="Docker Security",
            desired_state="Non-root user",
            actual_state="Root user",
            status="failed",
            severity="Medium",
            evidence="Simulated Dockerfile/runtime metadata shows container user is root.",
            recommendation="Define a non-root user in Dockerfile and enforce runtime user restrictions.",
            validation_pack="Docker Security Pack",
            framework="Internal Container Security Baseline",
        ),
        BaselineControl(
            tenant_slug="demo-enterprise",
            asset_id=4,
            asset_name="Corporate Workstation",
            asset_hostname="win-client-01",
            network_zone="User Zone",
            control_id="NET-SEG-001",
            control_name="User zone must not directly access database zone",
            category="Network Segmentation",
            desired_state="Blocked",
            actual_state="Allowed",
            status="failed",
            severity="High",
            evidence="Simulated segmentation matrix allows User Zone to Database Zone communication.",
            recommendation="Block direct workstation-to-database traffic and enforce application-mediated access.",
            validation_pack="Network Segmentation Pack",
            framework="Internal Network Segmentation Baseline",
        ),
        BaselineControl(
            tenant_slug="demo-enterprise",
            asset_id=5,
            asset_name="Management Jump Server",
            asset_hostname="jump-mgmt-01",
            network_zone="Management Zone",
            control_id="LOG-AUDIT-001",
            control_name="Privileged activity logging must be enabled",
            category="Logging and Monitoring",
            desired_state="Enabled and forwarded",
            actual_state="Partially enabled",
            status="failed",
            severity="Medium",
            evidence="Privileged command events are not marked as forwarded to central monitoring.",
            recommendation="Enable privileged activity logging and forward logs to the monitoring platform.",
            validation_pack="Logging and Monitoring Pack",
            framework="Internal Monitoring Baseline",
        ),
        BaselineControl(
            tenant_slug="demo-enterprise",
            asset_id=5,
            asset_name="Management Jump Server",
            asset_hostname="jump-mgmt-01",
            network_zone="Management Zone",
            control_id="MGMT-MFA-001",
            control_name="Management access must require MFA",
            category="Access Control",
            desired_state="MFA required",
            actual_state="MFA required",
            status="passed",
            severity="Low",
            evidence="Simulated access policy shows MFA is required for management zone access.",
            recommendation="Continue enforcing MFA for management access.",
            validation_pack="IAM Risk Pack",
            framework="Internal Access Control Baseline",
        ),
    ]

    db.add_all(demo_controls)
    db.commit()


def calculate_compliance_score(controls: list[BaselineControl]) -> int:
    if not controls:
        return 100

    passed = len([control for control in controls if control.status == "passed"])
    score = round((passed / len(controls)) * 100)

    return score


@app.on_event("startup")
def on_startup():
    wait_for_database()
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed_demo_baseline_controls(db)
    finally:
        db.close()


@app.get("/health")
def health_check():
    return {
        "service": "baseline-engine",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/info")
def service_info():
    return {
        "name": "CyValidator Baseline Engine",
        "role": "Validates desired vs actual security controls and calculates compliance score",
        "version": "0.1.0",
    }


@app.get("/api/baseline/controls", response_model=list[BaselineControlResponse])
def list_controls(
        status_filter: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    query = db.query(BaselineControl).filter(
        BaselineControl.tenant_slug == identity["tenant"]
    )

    if status_filter:
        query = query.filter(BaselineControl.status == status_filter)

    if severity:
        query = query.filter(BaselineControl.severity == severity)

    if category:
        query = query.filter(BaselineControl.category == category)

    controls = query.order_by(BaselineControl.id.asc()).all()

    return controls


@app.get("/api/baseline/summary")
def baseline_summary(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    controls = (
        db.query(BaselineControl)
        .filter(BaselineControl.tenant_slug == identity["tenant"])
        .all()
    )

    total_controls = len(controls)
    passed_controls = len([control for control in controls if control.status == "passed"])
    failed_controls = len([control for control in controls if control.status == "failed"])
    warning_controls = len([control for control in controls if control.status == "warning"])

    critical_failed = len([
        control for control in controls
        if control.status == "failed" and control.severity.lower() == "critical"
    ])

    high_failed = len([
        control for control in controls
        if control.status == "failed" and control.severity.lower() == "high"
    ])

    categories = {}

    for control in controls:
        if control.category not in categories:
            categories[control.category] = {
                "category": control.category,
                "total": 0,
                "passed": 0,
                "failed": 0,
                "warning": 0,
                "compliance_score": 0,
            }

        categories[control.category]["total"] += 1

        if control.status == "passed":
            categories[control.category]["passed"] += 1

        if control.status == "failed":
            categories[control.category]["failed"] += 1

        if control.status == "warning":
            categories[control.category]["warning"] += 1

    for category_name, data in categories.items():
        if data["total"] > 0:
            data["compliance_score"] = round((data["passed"] / data["total"]) * 100)

    return {
        "tenant": identity["tenant"],
        "compliance_score": calculate_compliance_score(controls),
        "total_controls": total_controls,
        "passed_controls": passed_controls,
        "failed_controls": failed_controls,
        "warning_controls": warning_controls,
        "critical_failed_controls": critical_failed,
        "high_failed_controls": high_failed,
        "categories": list(categories.values()),
    }


@app.get("/api/baseline/failed", response_model=list[BaselineControlResponse])
def failed_controls(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    controls = (
        db.query(BaselineControl)
        .filter(BaselineControl.tenant_slug == identity["tenant"])
        .filter(BaselineControl.status == "failed")
        .order_by(BaselineControl.id.asc())
        .all()
    )

    return controls


@app.get("/api/baseline/controls/{control_id}", response_model=BaselineControlResponse)
def get_control(
        control_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    control = (
        db.query(BaselineControl)
        .filter(BaselineControl.id == control_id)
        .filter(BaselineControl.tenant_slug == identity["tenant"])
        .first()
    )

    if not control:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Baseline control not found",
        )

    return control


@app.post(
    "/api/baseline/controls",
    response_model=BaselineControlResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_control(
        payload: BaselineControlCreateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_baseline_write_permission),
):
    control = BaselineControl(
        tenant_slug=identity["tenant"],
        asset_id=payload.asset_id,
        asset_name=payload.asset_name,
        asset_hostname=payload.asset_hostname,
        network_zone=payload.network_zone,
        control_id=payload.control_id,
        control_name=payload.control_name,
        category=payload.category,
        desired_state=payload.desired_state,
        actual_state=payload.actual_state,
        status=payload.status,
        severity=payload.severity,
        evidence=payload.evidence,
        recommendation=payload.recommendation,
        validation_pack=payload.validation_pack,
        framework=payload.framework,
    )

    db.add(control)
    db.commit()
    db.refresh(control)

    return control


@app.put("/api/baseline/controls/{control_id}", response_model=BaselineControlResponse)
def update_control(
        control_id: int,
        payload: BaselineControlUpdateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_baseline_write_permission),
):
    control = (
        db.query(BaselineControl)
        .filter(BaselineControl.id == control_id)
        .filter(BaselineControl.tenant_slug == identity["tenant"])
        .first()
    )

    if not control:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Baseline control not found",
        )

    update_data = payload.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(control, field, value)

    control.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(control)

    return control


@app.delete("/api/baseline/controls/{control_id}")
def delete_control(
        control_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_baseline_write_permission),
):
    control = (
        db.query(BaselineControl)
        .filter(BaselineControl.id == control_id)
        .filter(BaselineControl.tenant_slug == identity["tenant"])
        .first()
    )

    if not control:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Baseline control not found",
        )

    db.delete(control)
    db.commit()

    return {
        "message": "Baseline control deleted successfully",
        "control_id": control_id,
    }