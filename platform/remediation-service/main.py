import os
import time
from datetime import datetime, timedelta, timezone
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


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    id = Column(Integer, primary_key=True, index=True)

    tenant_slug = Column(String(120), index=True, nullable=False)

    finding_id = Column(Integer, nullable=True)
    finding_title = Column(String(250), nullable=False)

    asset_id = Column(Integer, nullable=True)
    asset_name = Column(String(150), nullable=False)
    asset_hostname = Column(String(150), nullable=True)
    network_zone = Column(String(120), nullable=True)

    severity = Column(String(50), nullable=False)
    priority = Column(String(50), nullable=False)
    risk_score = Column(Integer, default=0, nullable=False)

    owner = Column(String(150), nullable=False)
    approver = Column(String(150), nullable=True)

    status = Column(String(80), default="open", nullable=False)

    remediation_action = Column(Text, nullable=False)
    validation_method = Column(Text, nullable=False)
    business_impact = Column(Text, nullable=True)

    sla_days = Column(Integer, default=7, nullable=False)
    due_at = Column(DateTime, nullable=False)

    evidence_note = Column(Text, nullable=True)
    validation_result = Column(String(80), nullable=True)
    risk_acceptance_reason = Column(Text, nullable=True)

    created_by = Column(String(255), nullable=False)
    validated_by = Column(String(255), nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    validated_at = Column(DateTime, nullable=True)


class RemediationEvent(Base):
    __tablename__ = "remediation_events"

    id = Column(Integer, primary_key=True, index=True)

    tenant_slug = Column(String(120), index=True, nullable=False)
    remediation_task_id = Column(Integer, nullable=False)

    event_type = Column(String(120), nullable=False)
    message = Column(Text, nullable=False)
    actor = Column(String(255), nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class RemediationTaskCreateRequest(BaseModel):
    finding_id: Optional[int] = None
    finding_title: str = Field(..., min_length=3, max_length=250)

    asset_id: Optional[int] = None
    asset_name: str = Field(..., min_length=2, max_length=150)
    asset_hostname: Optional[str] = Field(None, max_length=150)
    network_zone: Optional[str] = Field(None, max_length=120)

    severity: str = Field(..., min_length=2, max_length=50)
    priority: str = Field(..., min_length=2, max_length=50)
    risk_score: int = Field(default=0, ge=0, le=100)

    owner: str = Field(..., min_length=2, max_length=150)
    approver: Optional[str] = Field(None, max_length=150)

    remediation_action: str = Field(..., min_length=3)
    validation_method: str = Field(..., min_length=3)
    business_impact: Optional[str] = None

    sla_days: int = Field(default=7, ge=1, le=365)


class RemediationTaskUpdateRequest(BaseModel):
    finding_title: Optional[str] = Field(None, min_length=3, max_length=250)

    asset_name: Optional[str] = Field(None, min_length=2, max_length=150)
    asset_hostname: Optional[str] = Field(None, max_length=150)
    network_zone: Optional[str] = Field(None, max_length=120)

    severity: Optional[str] = Field(None, min_length=2, max_length=50)
    priority: Optional[str] = Field(None, min_length=2, max_length=50)
    risk_score: Optional[int] = Field(None, ge=0, le=100)

    owner: Optional[str] = Field(None, min_length=2, max_length=150)
    approver: Optional[str] = Field(None, max_length=150)

    remediation_action: Optional[str] = Field(None, min_length=3)
    validation_method: Optional[str] = Field(None, min_length=3)
    business_impact: Optional[str] = None

    sla_days: Optional[int] = Field(None, ge=1, le=365)


class RemediationStatusUpdateRequest(BaseModel):
    status: str = Field(..., min_length=2, max_length=80)
    note: Optional[str] = None
    evidence_note: Optional[str] = None
    risk_acceptance_reason: Optional[str] = None


class RemediationValidationRequest(BaseModel):
    validation_result: str = Field(..., min_length=2, max_length=80)
    evidence_note: str = Field(..., min_length=3)


class RemediationTaskResponse(BaseModel):
    id: int
    tenant_slug: str

    finding_id: Optional[int]
    finding_title: str

    asset_id: Optional[int]
    asset_name: str
    asset_hostname: Optional[str]
    network_zone: Optional[str]

    severity: str
    priority: str
    risk_score: int

    owner: str
    approver: Optional[str]

    status: str

    remediation_action: str
    validation_method: str
    business_impact: Optional[str]

    sla_days: int
    due_at: datetime

    evidence_note: Optional[str]
    validation_result: Optional[str]
    risk_acceptance_reason: Optional[str]

    created_by: str
    validated_by: Optional[str]

    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime]
    validated_at: Optional[datetime]


class RemediationEventResponse(BaseModel):
    id: int
    tenant_slug: str
    remediation_task_id: int
    event_type: str
    message: str
    actor: str
    created_at: datetime


app = FastAPI(
    title="CyValidator Remediation Service",
    description="Remediation workflow, ownership, SLA and validation service for CyValidator",
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


def require_remediation_write_permission(
        identity: dict = Depends(get_current_identity),
) -> dict:
    allowed_roles = [
        "Platform Admin",
        "Security Manager",
        "Security Analyst",
        "IT Owner",
    ]

    if identity["role"] not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Remediation write permission required",
        )

    return identity


def serialize_task(task: RemediationTask) -> dict:
    return {
        "id": task.id,
        "tenant_slug": task.tenant_slug,
        "finding_id": task.finding_id,
        "finding_title": task.finding_title,
        "asset_id": task.asset_id,
        "asset_name": task.asset_name,
        "asset_hostname": task.asset_hostname,
        "network_zone": task.network_zone,
        "severity": task.severity,
        "priority": task.priority,
        "risk_score": task.risk_score,
        "owner": task.owner,
        "approver": task.approver,
        "status": task.status,
        "remediation_action": task.remediation_action,
        "validation_method": task.validation_method,
        "business_impact": task.business_impact,
        "sla_days": task.sla_days,
        "due_at": task.due_at,
        "evidence_note": task.evidence_note,
        "validation_result": task.validation_result,
        "risk_acceptance_reason": task.risk_acceptance_reason,
        "created_by": task.created_by,
        "validated_by": task.validated_by,
        "created_at": task.created_at,
        "updated_at": task.updated_at,
        "completed_at": task.completed_at,
        "validated_at": task.validated_at,
    }


def serialize_event(event: RemediationEvent) -> dict:
    return {
        "id": event.id,
        "tenant_slug": event.tenant_slug,
        "remediation_task_id": event.remediation_task_id,
        "event_type": event.event_type,
        "message": event.message,
        "actor": event.actor,
        "created_at": event.created_at,
    }


def add_event(
        db: Session,
        tenant_slug: str,
        remediation_task_id: int,
        event_type: str,
        message: str,
        actor: str,
) -> None:
    event = RemediationEvent(
        tenant_slug=tenant_slug,
        remediation_task_id=remediation_task_id,
        event_type=event_type,
        message=message,
        actor=actor,
    )

    db.add(event)
    db.commit()


def is_task_overdue(task: RemediationTask) -> bool:
    if task.status in ["fixed", "validated", "risk_accepted", "false_positive"]:
        return False

    now = datetime.now(timezone.utc)

    due_at = task.due_at
    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)

    return due_at < now


def seed_demo_remediation_tasks(db: Session) -> None:
    existing = (
        db.query(RemediationTask)
        .filter(RemediationTask.tenant_slug == "demo-enterprise")
        .filter(RemediationTask.finding_title == "SSH root login is enabled")
        .first()
    )

    if existing:
        return

    now = datetime.now(timezone.utc)

    demo_tasks = [
        RemediationTask(
            tenant_slug="demo-enterprise",
            finding_id=1,
            finding_title="SSH root login is enabled",
            asset_id=1,
            asset_name="Linux Web Server",
            asset_hostname="linux-web-01",
            network_zone="DMZ",
            severity="High",
            priority="High",
            risk_score=82,
            owner="Infrastructure Team",
            approver="Security Manager",
            status="assigned",
            remediation_action="Disable SSH root login by setting PermitRootLogin no and restart the SSH service.",
            validation_method="Re-run Linux Hardening Pack and confirm LINUX-SSH-001 passes.",
            business_impact="Reduces direct administrative exposure on a public-facing server.",
            sla_days=7,
            due_at=now + timedelta(days=7),
            evidence_note=None,
            validation_result=None,
            risk_acceptance_reason=None,
            created_by="admin@cyvalidator.local",
        ),
        RemediationTask(
            tenant_slug="demo-enterprise",
            finding_id=2,
            finding_title="Database service is exposed outside the application network",
            asset_id=2,
            asset_name="PostgreSQL Database",
            asset_hostname="db-postgres-01",
            network_zone="Database Zone",
            severity="Critical",
            priority="Critical",
            risk_score=94,
            owner="Database Team",
            approver="Security Manager",
            status="open",
            remediation_action="Restrict PostgreSQL access to approved application hosts only and block access from user networks.",
            validation_method="Re-run Database Exposure Pack and confirm DB-NET-001 passes.",
            business_impact="Reduces the probability of unauthorized access to sensitive data.",
            sla_days=3,
            due_at=now + timedelta(days=3),
            evidence_note=None,
            validation_result=None,
            risk_acceptance_reason=None,
            created_by="admin@cyvalidator.local",
        ),
        RemediationTask(
            tenant_slug="demo-enterprise",
            finding_id=3,
            finding_title="Privileged container execution is allowed",
            asset_id=3,
            asset_name="Docker Runtime Host",
            asset_hostname="docker-host-01",
            network_zone="Server Zone",
            severity="Critical",
            priority="Critical",
            risk_score=91,
            owner="Platform Engineering",
            approver="Security Manager",
            status="in_progress",
            remediation_action="Remove privileged mode from containers and enforce least privilege runtime policies.",
            validation_method="Re-run Docker Security Pack and confirm DOCKER-RUNTIME-001 passes.",
            business_impact="Reduces container breakout and host compromise risk.",
            sla_days=5,
            due_at=now + timedelta(days=5),
            evidence_note="Platform team is reviewing container runtime policy.",
            validation_result=None,
            risk_acceptance_reason=None,
            created_by="admin@cyvalidator.local",
        ),
        RemediationTask(
            tenant_slug="demo-enterprise",
            finding_id=4,
            finding_title="Endpoint can communicate with database zone",
            asset_id=4,
            asset_name="Corporate Workstation",
            asset_hostname="win-client-01",
            network_zone="User Zone",
            severity="High",
            priority="High",
            risk_score=78,
            owner="Network Team",
            approver="Security Manager",
            status="waiting_for_approval",
            remediation_action="Block direct workstation-to-database traffic and enforce application-mediated access.",
            validation_method="Re-run Network Segmentation Pack and confirm NET-SEG-001 passes.",
            business_impact="Reduces lateral movement paths from user endpoints to sensitive databases.",
            sla_days=10,
            due_at=now + timedelta(days=10),
            evidence_note="Firewall rule change is prepared and waiting for approval.",
            validation_result=None,
            risk_acceptance_reason=None,
            created_by="admin@cyvalidator.local",
        ),
        RemediationTask(
            tenant_slug="demo-enterprise",
            finding_id=5,
            finding_title="Security audit logging is incomplete",
            asset_id=5,
            asset_name="Management Jump Server",
            asset_hostname="jump-mgmt-01",
            network_zone="Management Zone",
            severity="Medium",
            priority="Medium",
            risk_score=55,
            owner="SOC Team",
            approver="Security Manager",
            status="fixed",
            remediation_action="Enable privileged activity logging and forward logs to central monitoring.",
            validation_method="Confirm privileged activity logs are received by central monitoring.",
            business_impact="Improves detection and investigation coverage for privileged activity.",
            sla_days=14,
            due_at=now + timedelta(days=14),
            evidence_note="Audit logging policy was updated and logs are now visible in monitoring.",
            validation_result="pending_validation",
            risk_acceptance_reason=None,
            created_by="admin@cyvalidator.local",
            completed_at=now,
        ),
    ]

    db.add_all(demo_tasks)
    db.commit()

    for task in demo_tasks:
        add_event(
            db=db,
            tenant_slug=task.tenant_slug,
            remediation_task_id=task.id,
            event_type="task_seeded",
            message=f"Demo remediation task '{task.finding_title}' was seeded.",
            actor="system",
        )


@app.on_event("startup")
def on_startup():
    wait_for_database()
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed_demo_remediation_tasks(db)
    finally:
        db.close()


@app.get("/health")
def health_check():
    return {
        "service": "remediation-service",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/info")
def service_info():
    return {
        "name": "CyValidator Remediation Service",
        "role": "Manages remediation ownership, SLA, workflow events and validation lifecycle",
        "version": "0.1.0",
    }


@app.get("/api/remediations", response_model=list[RemediationTaskResponse])
def list_remediation_tasks(
        status_filter: Optional[str] = None,
        severity: Optional[str] = None,
        priority: Optional[str] = None,
        owner: Optional[str] = None,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    query = db.query(RemediationTask).filter(
        RemediationTask.tenant_slug == identity["tenant"]
    )

    if status_filter:
        query = query.filter(RemediationTask.status == status_filter)

    if severity:
        query = query.filter(RemediationTask.severity == severity)

    if priority:
        query = query.filter(RemediationTask.priority == priority)

    if owner:
        query = query.filter(RemediationTask.owner == owner)

    tasks = query.order_by(RemediationTask.risk_score.desc(), RemediationTask.due_at.asc()).all()

    return [serialize_task(task) for task in tasks]


@app.get("/api/remediations/summary")
def remediation_summary(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    tasks = (
        db.query(RemediationTask)
        .filter(RemediationTask.tenant_slug == identity["tenant"])
        .all()
    )

    total_tasks = len(tasks)
    open_tasks = len([task for task in tasks if task.status == "open"])
    assigned_tasks = len([task for task in tasks if task.status == "assigned"])
    in_progress_tasks = len([task for task in tasks if task.status == "in_progress"])
    waiting_for_approval_tasks = len([task for task in tasks if task.status == "waiting_for_approval"])
    fixed_tasks = len([task for task in tasks if task.status == "fixed"])
    validated_tasks = len([task for task in tasks if task.status == "validated"])
    risk_accepted_tasks = len([task for task in tasks if task.status == "risk_accepted"])
    overdue_tasks = len([task for task in tasks if is_task_overdue(task)])

    critical_tasks = len([task for task in tasks if task.severity == "Critical"])
    high_tasks = len([task for task in tasks if task.severity == "High"])

    avg_risk_score = 0
    if tasks:
        avg_risk_score = round(sum(task.risk_score for task in tasks) / len(tasks), 2)

    owner_breakdown = {}

    for task in tasks:
        if task.owner not in owner_breakdown:
            owner_breakdown[task.owner] = {
                "owner": task.owner,
                "total": 0,
                "open": 0,
                "in_progress": 0,
                "fixed": 0,
                "validated": 0,
                "overdue": 0,
            }

        owner_breakdown[task.owner]["total"] += 1

        if task.status == "open":
            owner_breakdown[task.owner]["open"] += 1

        if task.status == "in_progress":
            owner_breakdown[task.owner]["in_progress"] += 1

        if task.status == "fixed":
            owner_breakdown[task.owner]["fixed"] += 1

        if task.status == "validated":
            owner_breakdown[task.owner]["validated"] += 1

        if is_task_overdue(task):
            owner_breakdown[task.owner]["overdue"] += 1

    return {
        "tenant": identity["tenant"],
        "total_tasks": total_tasks,
        "open_tasks": open_tasks,
        "assigned_tasks": assigned_tasks,
        "in_progress_tasks": in_progress_tasks,
        "waiting_for_approval_tasks": waiting_for_approval_tasks,
        "fixed_tasks": fixed_tasks,
        "validated_tasks": validated_tasks,
        "risk_accepted_tasks": risk_accepted_tasks,
        "overdue_tasks": overdue_tasks,
        "critical_tasks": critical_tasks,
        "high_tasks": high_tasks,
        "average_risk_score": avg_risk_score,
        "owner_breakdown": list(owner_breakdown.values()),
    }


@app.get("/api/remediations/overdue", response_model=list[RemediationTaskResponse])
def overdue_remediation_tasks(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    tasks = (
        db.query(RemediationTask)
        .filter(RemediationTask.tenant_slug == identity["tenant"])
        .all()
    )

    overdue_tasks = [task for task in tasks if is_task_overdue(task)]

    sorted_tasks = sorted(
        overdue_tasks,
        key=lambda task: task.risk_score,
        reverse=True,
    )

    return [serialize_task(task) for task in sorted_tasks]


@app.get("/api/remediations/{task_id}", response_model=RemediationTaskResponse)
def get_remediation_task(
        task_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    task = (
        db.query(RemediationTask)
        .filter(RemediationTask.id == task_id)
        .filter(RemediationTask.tenant_slug == identity["tenant"])
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation task not found",
        )

    return serialize_task(task)


@app.get("/api/remediations/{task_id}/events", response_model=list[RemediationEventResponse])
def get_remediation_events(
        task_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    task = (
        db.query(RemediationTask)
        .filter(RemediationTask.id == task_id)
        .filter(RemediationTask.tenant_slug == identity["tenant"])
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation task not found",
        )

    events = (
        db.query(RemediationEvent)
        .filter(RemediationEvent.tenant_slug == identity["tenant"])
        .filter(RemediationEvent.remediation_task_id == task_id)
        .order_by(RemediationEvent.created_at.asc())
        .all()
    )

    return [serialize_event(event) for event in events]


@app.post(
    "/api/remediations",
    response_model=RemediationTaskResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_remediation_task(
        payload: RemediationTaskCreateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_remediation_write_permission),
):
    now = datetime.now(timezone.utc)

    task = RemediationTask(
        tenant_slug=identity["tenant"],
        finding_id=payload.finding_id,
        finding_title=payload.finding_title,
        asset_id=payload.asset_id,
        asset_name=payload.asset_name,
        asset_hostname=payload.asset_hostname,
        network_zone=payload.network_zone,
        severity=payload.severity,
        priority=payload.priority,
        risk_score=payload.risk_score,
        owner=payload.owner,
        approver=payload.approver,
        status="open",
        remediation_action=payload.remediation_action,
        validation_method=payload.validation_method,
        business_impact=payload.business_impact,
        sla_days=payload.sla_days,
        due_at=now + timedelta(days=payload.sla_days),
        created_by=identity["email"],
        created_at=now,
        updated_at=now,
    )

    db.add(task)
    db.commit()
    db.refresh(task)

    add_event(
        db=db,
        tenant_slug=identity["tenant"],
        remediation_task_id=task.id,
        event_type="task_created",
        message=f"Remediation task was created for finding '{task.finding_title}'.",
        actor=identity["email"],
    )

    db.refresh(task)

    return serialize_task(task)


@app.put("/api/remediations/{task_id}", response_model=RemediationTaskResponse)
def update_remediation_task(
        task_id: int,
        payload: RemediationTaskUpdateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_remediation_write_permission),
):
    task = (
        db.query(RemediationTask)
        .filter(RemediationTask.id == task_id)
        .filter(RemediationTask.tenant_slug == identity["tenant"])
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation task not found",
        )

    update_data = payload.model_dump(exclude_unset=True)

    old_sla_days = task.sla_days

    for field, value in update_data.items():
        setattr(task, field, value)

    if payload.sla_days is not None and payload.sla_days != old_sla_days:
        task.due_at = datetime.now(timezone.utc) + timedelta(days=payload.sla_days)

    task.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(task)

    add_event(
        db=db,
        tenant_slug=identity["tenant"],
        remediation_task_id=task.id,
        event_type="task_updated",
        message="Remediation task details were updated.",
        actor=identity["email"],
    )

    db.refresh(task)

    return serialize_task(task)


@app.patch("/api/remediations/{task_id}/status", response_model=RemediationTaskResponse)
def update_remediation_status(
        task_id: int,
        payload: RemediationStatusUpdateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_remediation_write_permission),
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

    if payload.status == "risk_accepted" and not payload.risk_acceptance_reason:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Risk acceptance reason is required when status is risk_accepted",
        )

    task = (
        db.query(RemediationTask)
        .filter(RemediationTask.id == task_id)
        .filter(RemediationTask.tenant_slug == identity["tenant"])
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation task not found",
        )

    old_status = task.status

    task.status = payload.status
    task.updated_at = datetime.now(timezone.utc)

    if payload.evidence_note:
        task.evidence_note = payload.evidence_note

    if payload.risk_acceptance_reason:
        task.risk_acceptance_reason = payload.risk_acceptance_reason

    if payload.status in ["fixed", "validated", "risk_accepted", "false_positive"]:
        task.completed_at = datetime.now(timezone.utc)

    if payload.status == "validated":
        task.validated_at = datetime.now(timezone.utc)
        task.validated_by = identity["email"]
        task.validation_result = "validated"

    db.commit()
    db.refresh(task)

    message = f"Status changed from {old_status} to {payload.status}."

    if payload.note:
        message = f"{message} Note: {payload.note}"

    add_event(
        db=db,
        tenant_slug=identity["tenant"],
        remediation_task_id=task.id,
        event_type="status_changed",
        message=message,
        actor=identity["email"],
    )

    db.refresh(task)

    return serialize_task(task)


@app.post("/api/remediations/{task_id}/validate", response_model=RemediationTaskResponse)
def validate_remediation_task(
        task_id: int,
        payload: RemediationValidationRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_remediation_write_permission),
):
    allowed_results = [
        "validated",
        "failed_validation",
        "needs_rework",
    ]

    if payload.validation_result not in allowed_results:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid validation result. Allowed values: {allowed_results}",
        )

    task = (
        db.query(RemediationTask)
        .filter(RemediationTask.id == task_id)
        .filter(RemediationTask.tenant_slug == identity["tenant"])
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation task not found",
        )

    task.validation_result = payload.validation_result
    task.evidence_note = payload.evidence_note
    task.validated_by = identity["email"]
    task.validated_at = datetime.now(timezone.utc)
    task.updated_at = datetime.now(timezone.utc)

    if payload.validation_result == "validated":
        task.status = "validated"
        task.completed_at = datetime.now(timezone.utc)

    if payload.validation_result in ["failed_validation", "needs_rework"]:
        task.status = "in_progress"

    db.commit()
    db.refresh(task)

    add_event(
        db=db,
        tenant_slug=identity["tenant"],
        remediation_task_id=task.id,
        event_type="validation_completed",
        message=f"Validation result: {payload.validation_result}. Evidence: {payload.evidence_note}",
        actor=identity["email"],
    )

    db.refresh(task)

    return serialize_task(task)


@app.delete("/api/remediations/{task_id}")
def delete_remediation_task(
        task_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_remediation_write_permission),
):
    task = (
        db.query(RemediationTask)
        .filter(RemediationTask.id == task_id)
        .filter(RemediationTask.tenant_slug == identity["tenant"])
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation task not found",
        )

    events = (
        db.query(RemediationEvent)
        .filter(RemediationEvent.tenant_slug == identity["tenant"])
        .filter(RemediationEvent.remediation_task_id == task_id)
        .all()
    )

    for event in events:
        db.delete(event)

    db.delete(task)
    db.commit()

    return {
        "message": "Remediation task deleted successfully",
        "task_id": task_id,
    }