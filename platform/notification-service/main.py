import json
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


class NotificationEvent(Base):
    __tablename__ = "notification_events"

    id = Column(Integer, primary_key=True, index=True)

    tenant_slug = Column(String(120), index=True, nullable=False)

    event_type = Column(String(150), index=True, nullable=False)
    severity = Column(String(50), nullable=False)
    title = Column(String(250), nullable=False)
    message = Column(Text, nullable=False)

    source_service = Column(String(150), nullable=False)
    source_entity_type = Column(String(150), nullable=True)
    source_entity_id = Column(String(150), nullable=True)

    recipient_role = Column(String(150), nullable=True)
    recipient_owner = Column(String(150), nullable=True)

    delivery_channel = Column(String(80), nullable=False)
    delivery_status = Column(String(80), default="ready", nullable=False)

    email_subject = Column(String(250), nullable=True)
    email_payload_json = Column(Text, nullable=True)

    webhook_url = Column(String(500), nullable=True)
    webhook_payload_json = Column(Text, nullable=True)

    acknowledged_by = Column(String(255), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)

    created_by = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class NotificationSubscription(Base):
    __tablename__ = "notification_subscriptions"

    id = Column(Integer, primary_key=True, index=True)

    tenant_slug = Column(String(120), index=True, nullable=False)

    name = Column(String(200), nullable=False)
    event_type = Column(String(150), nullable=False)
    severity_threshold = Column(String(50), default="Medium", nullable=False)

    channel = Column(String(80), nullable=False)
    target = Column(String(500), nullable=False)

    owner = Column(String(150), nullable=False)
    status = Column(String(80), default="enabled", nullable=False)

    description = Column(Text, nullable=True)

    created_by = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class NotificationEventCreateRequest(BaseModel):
    event_type: str = Field(..., min_length=3, max_length=150)
    severity: str = Field(..., min_length=2, max_length=50)
    title: str = Field(..., min_length=3, max_length=250)
    message: str = Field(..., min_length=3)

    source_service: str = Field(..., min_length=2, max_length=150)
    source_entity_type: Optional[str] = Field(None, max_length=150)
    source_entity_id: Optional[str] = Field(None, max_length=150)

    recipient_role: Optional[str] = Field(None, max_length=150)
    recipient_owner: Optional[str] = Field(None, max_length=150)

    delivery_channel: str = Field(..., min_length=2, max_length=80)

    webhook_url: Optional[str] = Field(None, max_length=500)


class NotificationStatusUpdateRequest(BaseModel):
    delivery_status: str = Field(..., min_length=2, max_length=80)
    acknowledged_by: Optional[str] = Field(None, max_length=255)


class NotificationSubscriptionCreateRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=200)
    event_type: str = Field(..., min_length=3, max_length=150)
    severity_threshold: str = Field(default="Medium", min_length=2, max_length=50)

    channel: str = Field(..., min_length=2, max_length=80)
    target: str = Field(..., min_length=3, max_length=500)

    owner: str = Field(..., min_length=2, max_length=150)
    description: Optional[str] = None


class NotificationSubscriptionUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=200)
    event_type: Optional[str] = Field(None, min_length=3, max_length=150)
    severity_threshold: Optional[str] = Field(None, min_length=2, max_length=50)

    channel: Optional[str] = Field(None, min_length=2, max_length=80)
    target: Optional[str] = Field(None, min_length=3, max_length=500)

    owner: Optional[str] = Field(None, min_length=2, max_length=150)
    status: Optional[str] = Field(None, min_length=2, max_length=80)
    description: Optional[str] = None


class NotificationEventResponse(BaseModel):
    id: int
    tenant_slug: str

    event_type: str
    severity: str
    title: str
    message: str

    source_service: str
    source_entity_type: Optional[str]
    source_entity_id: Optional[str]

    recipient_role: Optional[str]
    recipient_owner: Optional[str]

    delivery_channel: str
    delivery_status: str

    email_subject: Optional[str]
    email_payload_json: Optional[str]

    webhook_url: Optional[str]
    webhook_payload_json: Optional[str]

    acknowledged_by: Optional[str]
    acknowledged_at: Optional[datetime]

    created_by: str
    created_at: datetime
    updated_at: datetime


class NotificationSubscriptionResponse(BaseModel):
    id: int
    tenant_slug: str

    name: str
    event_type: str
    severity_threshold: str

    channel: str
    target: str

    owner: str
    status: str
    description: Optional[str]

    created_by: str
    created_at: datetime
    updated_at: datetime


app = FastAPI(
    title="CyValidator Notification Service",
    description="Notification event, webhook-ready and email-ready payload service for CyValidator",
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


def require_notification_write_permission(
        identity: dict = Depends(get_current_identity),
) -> dict:
    allowed_roles = [
        "Platform Admin",
        "Security Manager",
        "Security Analyst",
    ]

    if identity["role"] not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Notification write permission required",
        )

    return identity


def build_email_subject(severity: str, title: str) -> str:
    return f"[CyValidator][{severity}] {title}"


def build_email_payload(
        tenant_slug: str,
        event_type: str,
        severity: str,
        title: str,
        message: str,
        source_service: str,
        source_entity_type: Optional[str],
        source_entity_id: Optional[str],
        recipient_role: Optional[str],
        recipient_owner: Optional[str],
) -> dict:
    return {
        "product": "CyValidator",
        "tenant": tenant_slug,
        "event_type": event_type,
        "severity": severity,
        "title": title,
        "message": message,
        "source": {
            "service": source_service,
            "entity_type": source_entity_type,
            "entity_id": source_entity_id,
        },
        "recipient": {
            "role": recipient_role,
            "owner": recipient_owner,
        },
        "recommended_action": "Open CyValidator dashboard, review the event context and assign the required remediation action.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def build_webhook_payload(
        tenant_slug: str,
        event_type: str,
        severity: str,
        title: str,
        message: str,
        source_service: str,
        source_entity_type: Optional[str],
        source_entity_id: Optional[str],
) -> dict:
    return {
        "product": "CyValidator",
        "tenant": tenant_slug,
        "event_type": event_type,
        "severity": severity,
        "title": title,
        "message": message,
        "source_service": source_service,
        "source_entity_type": source_entity_type,
        "source_entity_id": source_entity_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def serialize_event(event: NotificationEvent) -> dict:
    return {
        "id": event.id,
        "tenant_slug": event.tenant_slug,
        "event_type": event.event_type,
        "severity": event.severity,
        "title": event.title,
        "message": event.message,
        "source_service": event.source_service,
        "source_entity_type": event.source_entity_type,
        "source_entity_id": event.source_entity_id,
        "recipient_role": event.recipient_role,
        "recipient_owner": event.recipient_owner,
        "delivery_channel": event.delivery_channel,
        "delivery_status": event.delivery_status,
        "email_subject": event.email_subject,
        "email_payload_json": event.email_payload_json,
        "webhook_url": event.webhook_url,
        "webhook_payload_json": event.webhook_payload_json,
        "acknowledged_by": event.acknowledged_by,
        "acknowledged_at": event.acknowledged_at,
        "created_by": event.created_by,
        "created_at": event.created_at,
        "updated_at": event.updated_at,
    }


def serialize_subscription(subscription: NotificationSubscription) -> dict:
    return {
        "id": subscription.id,
        "tenant_slug": subscription.tenant_slug,
        "name": subscription.name,
        "event_type": subscription.event_type,
        "severity_threshold": subscription.severity_threshold,
        "channel": subscription.channel,
        "target": subscription.target,
        "owner": subscription.owner,
        "status": subscription.status,
        "description": subscription.description,
        "created_by": subscription.created_by,
        "created_at": subscription.created_at,
        "updated_at": subscription.updated_at,
    }


def create_notification_event(
        db: Session,
        tenant_slug: str,
        event_type: str,
        severity: str,
        title: str,
        message: str,
        source_service: str,
        source_entity_type: Optional[str],
        source_entity_id: Optional[str],
        recipient_role: Optional[str],
        recipient_owner: Optional[str],
        delivery_channel: str,
        webhook_url: Optional[str],
        created_by: str,
) -> NotificationEvent:
    email_subject = None
    email_payload_json = None
    webhook_payload_json = None

    if delivery_channel in ["email_ready", "all"]:
        email_subject = build_email_subject(severity, title)
        email_payload_json = json.dumps(
            build_email_payload(
                tenant_slug=tenant_slug,
                event_type=event_type,
                severity=severity,
                title=title,
                message=message,
                source_service=source_service,
                source_entity_type=source_entity_type,
                source_entity_id=source_entity_id,
                recipient_role=recipient_role,
                recipient_owner=recipient_owner,
            )
        )

    if delivery_channel in ["webhook_ready", "all"]:
        webhook_payload_json = json.dumps(
            build_webhook_payload(
                tenant_slug=tenant_slug,
                event_type=event_type,
                severity=severity,
                title=title,
                message=message,
                source_service=source_service,
                source_entity_type=source_entity_type,
                source_entity_id=source_entity_id,
            )
        )

    event = NotificationEvent(
        tenant_slug=tenant_slug,
        event_type=event_type,
        severity=severity,
        title=title,
        message=message,
        source_service=source_service,
        source_entity_type=source_entity_type,
        source_entity_id=source_entity_id,
        recipient_role=recipient_role,
        recipient_owner=recipient_owner,
        delivery_channel=delivery_channel,
        delivery_status="ready",
        email_subject=email_subject,
        email_payload_json=email_payload_json,
        webhook_url=webhook_url,
        webhook_payload_json=webhook_payload_json,
        created_by=created_by,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event


def seed_demo_notifications(db: Session) -> None:
    existing = (
        db.query(NotificationEvent)
        .filter(NotificationEvent.tenant_slug == "demo-enterprise")
        .filter(NotificationEvent.title == "Critical database exposure detected")
        .first()
    )

    if existing:
        return

    demo_events = [
        {
            "event_type": "critical_finding_created",
            "severity": "Critical",
            "title": "Critical database exposure detected",
            "message": "PostgreSQL Database is reachable from non-application zones and requires immediate remediation.",
            "source_service": "findings-service",
            "source_entity_type": "finding",
            "source_entity_id": "2",
            "recipient_role": "Security Manager",
            "recipient_owner": "Database Team",
            "delivery_channel": "all",
            "webhook_url": "https://example.local/webhooks/cyvalidator",
        },
        {
            "event_type": "attack_path_detected",
            "severity": "Critical",
            "title": "Critical attack path reaches sensitive database",
            "message": "Attack Graph Engine identified a path from external exposure to PostgreSQL Database.",
            "source_service": "attack-graph-engine",
            "source_entity_type": "attack_path",
            "source_entity_id": "1",
            "recipient_role": "Security Manager",
            "recipient_owner": "Security Team",
            "delivery_channel": "email_ready",
            "webhook_url": None,
        },
        {
            "event_type": "scan_completed",
            "severity": "Medium",
            "title": "Docker security scan completed",
            "message": "Docker Security Pack completed with privileged container and root user findings.",
            "source_service": "scan-orchestrator",
            "source_entity_type": "scan_run",
            "source_entity_id": "2",
            "recipient_role": "Security Analyst",
            "recipient_owner": "Platform Engineering",
            "delivery_channel": "in_app",
            "webhook_url": None,
        },
        {
            "event_type": "remediation_waiting_for_approval",
            "severity": "High",
            "title": "Network segmentation fix is waiting for approval",
            "message": "A remediation task for workstation-to-database access is waiting for security approval.",
            "source_service": "remediation-service",
            "source_entity_type": "remediation_task",
            "source_entity_id": "4",
            "recipient_role": "Security Manager",
            "recipient_owner": "Network Team",
            "delivery_channel": "email_ready",
            "webhook_url": None,
        },
    ]

    for event_data in demo_events:
        create_notification_event(
            db=db,
            tenant_slug="demo-enterprise",
            event_type=event_data["event_type"],
            severity=event_data["severity"],
            title=event_data["title"],
            message=event_data["message"],
            source_service=event_data["source_service"],
            source_entity_type=event_data["source_entity_type"],
            source_entity_id=event_data["source_entity_id"],
            recipient_role=event_data["recipient_role"],
            recipient_owner=event_data["recipient_owner"],
            delivery_channel=event_data["delivery_channel"],
            webhook_url=event_data["webhook_url"],
            created_by="system",
        )

    demo_subscriptions = [
        NotificationSubscription(
            tenant_slug="demo-enterprise",
            name="Critical Findings to Security Managers",
            event_type="critical_finding_created",
            severity_threshold="Critical",
            channel="email_ready",
            target="security-managers@example.local",
            owner="Security Team",
            status="enabled",
            description="Email-ready notifications for critical findings.",
            created_by="system",
        ),
        NotificationSubscription(
            tenant_slug="demo-enterprise",
            name="Attack Path Webhook",
            event_type="attack_path_detected",
            severity_threshold="High",
            channel="webhook_ready",
            target="https://example.local/webhooks/cyvalidator",
            owner="Security Team",
            status="enabled",
            description="Webhook-ready payloads for high-risk attack paths.",
            created_by="system",
        ),
        NotificationSubscription(
            tenant_slug="demo-enterprise",
            name="Remediation Workflow Updates",
            event_type="remediation_status_changed",
            severity_threshold="Medium",
            channel="in_app",
            target="CyValidator dashboard",
            owner="Security Operations",
            status="enabled",
            description="In-app notifications for remediation status changes.",
            created_by="system",
        ),
    ]

    db.add_all(demo_subscriptions)
    db.commit()


@app.on_event("startup")
def on_startup():
    wait_for_database()
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed_demo_notifications(db)
    finally:
        db.close()


@app.get("/health")
def health_check():
    return {
        "service": "notification-service",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/info")
def service_info():
    return {
        "name": "CyValidator Notification Service",
        "role": "Generates in-app, webhook-ready and email-ready notification events",
        "version": "0.1.0",
    }


@app.get("/api/notifications/events", response_model=list[NotificationEventResponse])
def list_notification_events(
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        delivery_channel: Optional[str] = None,
        delivery_status: Optional[str] = None,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    query = db.query(NotificationEvent).filter(
        NotificationEvent.tenant_slug == identity["tenant"]
    )

    if event_type:
        query = query.filter(NotificationEvent.event_type == event_type)

    if severity:
        query = query.filter(NotificationEvent.severity == severity)

    if delivery_channel:
        query = query.filter(NotificationEvent.delivery_channel == delivery_channel)

    if delivery_status:
        query = query.filter(NotificationEvent.delivery_status == delivery_status)

    events = query.order_by(NotificationEvent.created_at.desc()).all()

    return [serialize_event(event) for event in events]


@app.get("/api/notifications/events/summary")
def notification_events_summary(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    events = (
        db.query(NotificationEvent)
        .filter(NotificationEvent.tenant_slug == identity["tenant"])
        .all()
    )

    total_events = len(events)
    ready_events = len([event for event in events if event.delivery_status == "ready"])
    delivered_events = len([event for event in events if event.delivery_status == "delivered"])
    acknowledged_events = len([event for event in events if event.delivery_status == "acknowledged"])
    failed_events = len([event for event in events if event.delivery_status == "failed"])

    critical_events = len([event for event in events if event.severity == "Critical"])
    high_events = len([event for event in events if event.severity == "High"])

    channels = {}

    for event in events:
        if event.delivery_channel not in channels:
            channels[event.delivery_channel] = {
                "channel": event.delivery_channel,
                "events": 0,
                "ready": 0,
                "delivered": 0,
                "acknowledged": 0,
                "failed": 0,
            }

        channels[event.delivery_channel]["events"] += 1

        if event.delivery_status == "ready":
            channels[event.delivery_channel]["ready"] += 1

        if event.delivery_status == "delivered":
            channels[event.delivery_channel]["delivered"] += 1

        if event.delivery_status == "acknowledged":
            channels[event.delivery_channel]["acknowledged"] += 1

        if event.delivery_status == "failed":
            channels[event.delivery_channel]["failed"] += 1

    return {
        "tenant": identity["tenant"],
        "total_events": total_events,
        "ready_events": ready_events,
        "delivered_events": delivered_events,
        "acknowledged_events": acknowledged_events,
        "failed_events": failed_events,
        "critical_events": critical_events,
        "high_events": high_events,
        "channel_breakdown": list(channels.values()),
    }


@app.get("/api/notifications/events/email-ready", response_model=list[NotificationEventResponse])
def email_ready_events(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    events = (
        db.query(NotificationEvent)
        .filter(NotificationEvent.tenant_slug == identity["tenant"])
        .filter(NotificationEvent.email_payload_json.isnot(None))
        .filter(NotificationEvent.delivery_status == "ready")
        .order_by(NotificationEvent.created_at.desc())
        .all()
    )

    return [serialize_event(event) for event in events]


@app.get("/api/notifications/events/webhook-ready", response_model=list[NotificationEventResponse])
def webhook_ready_events(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    events = (
        db.query(NotificationEvent)
        .filter(NotificationEvent.tenant_slug == identity["tenant"])
        .filter(NotificationEvent.webhook_payload_json.isnot(None))
        .filter(NotificationEvent.delivery_status == "ready")
        .order_by(NotificationEvent.created_at.desc())
        .all()
    )

    return [serialize_event(event) for event in events]


@app.get("/api/notifications/events/{event_id}", response_model=NotificationEventResponse)
def get_notification_event(
        event_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    event = (
        db.query(NotificationEvent)
        .filter(NotificationEvent.id == event_id)
        .filter(NotificationEvent.tenant_slug == identity["tenant"])
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification event not found",
        )

    return serialize_event(event)


@app.post(
    "/api/notifications/events",
    response_model=NotificationEventResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_notification(
        payload: NotificationEventCreateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_notification_write_permission),
):
    allowed_channels = [
        "in_app",
        "email_ready",
        "webhook_ready",
        "all",
    ]

    if payload.delivery_channel not in allowed_channels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid delivery channel. Allowed values: {allowed_channels}",
        )

    event = create_notification_event(
        db=db,
        tenant_slug=identity["tenant"],
        event_type=payload.event_type,
        severity=payload.severity,
        title=payload.title,
        message=payload.message,
        source_service=payload.source_service,
        source_entity_type=payload.source_entity_type,
        source_entity_id=payload.source_entity_id,
        recipient_role=payload.recipient_role,
        recipient_owner=payload.recipient_owner,
        delivery_channel=payload.delivery_channel,
        webhook_url=payload.webhook_url,
        created_by=identity["email"],
    )

    return serialize_event(event)


@app.patch("/api/notifications/events/{event_id}/status", response_model=NotificationEventResponse)
def update_notification_status(
        event_id: int,
        payload: NotificationStatusUpdateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_notification_write_permission),
):
    allowed_statuses = [
        "ready",
        "delivered",
        "failed",
        "acknowledged",
        "ignored",
    ]

    if payload.delivery_status not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid delivery status. Allowed values: {allowed_statuses}",
        )

    event = (
        db.query(NotificationEvent)
        .filter(NotificationEvent.id == event_id)
        .filter(NotificationEvent.tenant_slug == identity["tenant"])
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification event not found",
        )

    event.delivery_status = payload.delivery_status
    event.updated_at = datetime.now(timezone.utc)

    if payload.delivery_status == "acknowledged":
        event.acknowledged_by = payload.acknowledged_by or identity["email"]
        event.acknowledged_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(event)

    return serialize_event(event)


@app.delete("/api/notifications/events/{event_id}")
def delete_notification_event(
        event_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_notification_write_permission),
):
    event = (
        db.query(NotificationEvent)
        .filter(NotificationEvent.id == event_id)
        .filter(NotificationEvent.tenant_slug == identity["tenant"])
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification event not found",
        )

    db.delete(event)
    db.commit()

    return {
        "message": "Notification event deleted successfully",
        "event_id": event_id,
    }


@app.get("/api/notifications/subscriptions", response_model=list[NotificationSubscriptionResponse])
def list_notification_subscriptions(
        event_type: Optional[str] = None,
        channel: Optional[str] = None,
        status_filter: Optional[str] = None,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    query = db.query(NotificationSubscription).filter(
        NotificationSubscription.tenant_slug == identity["tenant"]
    )

    if event_type:
        query = query.filter(NotificationSubscription.event_type == event_type)

    if channel:
        query = query.filter(NotificationSubscription.channel == channel)

    if status_filter:
        query = query.filter(NotificationSubscription.status == status_filter)

    subscriptions = query.order_by(NotificationSubscription.created_at.desc()).all()

    return [serialize_subscription(subscription) for subscription in subscriptions]


@app.get("/api/notifications/subscriptions/summary")
def notification_subscriptions_summary(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    subscriptions = (
        db.query(NotificationSubscription)
        .filter(NotificationSubscription.tenant_slug == identity["tenant"])
        .all()
    )

    total_subscriptions = len(subscriptions)
    enabled_subscriptions = len(
        [subscription for subscription in subscriptions if subscription.status == "enabled"]
    )
    disabled_subscriptions = len(
        [subscription for subscription in subscriptions if subscription.status == "disabled"]
    )

    channels = {}

    for subscription in subscriptions:
        if subscription.channel not in channels:
            channels[subscription.channel] = {
                "channel": subscription.channel,
                "subscriptions": 0,
                "enabled": 0,
                "disabled": 0,
            }

        channels[subscription.channel]["subscriptions"] += 1

        if subscription.status == "enabled":
            channels[subscription.channel]["enabled"] += 1

        if subscription.status == "disabled":
            channels[subscription.channel]["disabled"] += 1

    return {
        "tenant": identity["tenant"],
        "total_subscriptions": total_subscriptions,
        "enabled_subscriptions": enabled_subscriptions,
        "disabled_subscriptions": disabled_subscriptions,
        "channel_breakdown": list(channels.values()),
    }


@app.get("/api/notifications/subscriptions/{subscription_id}", response_model=NotificationSubscriptionResponse)
def get_notification_subscription(
        subscription_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    subscription = (
        db.query(NotificationSubscription)
        .filter(NotificationSubscription.id == subscription_id)
        .filter(NotificationSubscription.tenant_slug == identity["tenant"])
        .first()
    )

    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification subscription not found",
        )

    return serialize_subscription(subscription)


@app.post(
    "/api/notifications/subscriptions",
    response_model=NotificationSubscriptionResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_notification_subscription(
        payload: NotificationSubscriptionCreateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_notification_write_permission),
):
    allowed_channels = [
        "in_app",
        "email_ready",
        "webhook_ready",
    ]

    if payload.channel not in allowed_channels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid channel. Allowed values: {allowed_channels}",
        )

    subscription = NotificationSubscription(
        tenant_slug=identity["tenant"],
        name=payload.name,
        event_type=payload.event_type,
        severity_threshold=payload.severity_threshold,
        channel=payload.channel,
        target=payload.target,
        owner=payload.owner,
        status="enabled",
        description=payload.description,
        created_by=identity["email"],
    )

    db.add(subscription)
    db.commit()
    db.refresh(subscription)

    return serialize_subscription(subscription)


@app.put("/api/notifications/subscriptions/{subscription_id}", response_model=NotificationSubscriptionResponse)
def update_notification_subscription(
        subscription_id: int,
        payload: NotificationSubscriptionUpdateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_notification_write_permission),
):
    subscription = (
        db.query(NotificationSubscription)
        .filter(NotificationSubscription.id == subscription_id)
        .filter(NotificationSubscription.tenant_slug == identity["tenant"])
        .first()
    )

    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification subscription not found",
        )

    update_data = payload.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(subscription, field, value)

    subscription.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(subscription)

    return serialize_subscription(subscription)


@app.patch("/api/notifications/subscriptions/{subscription_id}/status", response_model=NotificationSubscriptionResponse)
def update_notification_subscription_status(
        subscription_id: int,
        status_value: str,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_notification_write_permission),
):
    allowed_statuses = [
        "enabled",
        "disabled",
    ]

    if status_value not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Allowed values: {allowed_statuses}",
        )

    subscription = (
        db.query(NotificationSubscription)
        .filter(NotificationSubscription.id == subscription_id)
        .filter(NotificationSubscription.tenant_slug == identity["tenant"])
        .first()
    )

    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification subscription not found",
        )

    subscription.status = status_value
    subscription.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(subscription)

    return serialize_subscription(subscription)


@app.delete("/api/notifications/subscriptions/{subscription_id}")
def delete_notification_subscription(
        subscription_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_notification_write_permission),
):
    subscription = (
        db.query(NotificationSubscription)
        .filter(NotificationSubscription.id == subscription_id)
        .filter(NotificationSubscription.tenant_slug == identity["tenant"])
        .first()
    )

    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification subscription not found",
        )

    db.delete(subscription)
    db.commit()

    return {
        "message": "Notification subscription deleted successfully",
        "subscription_id": subscription_id,
    }