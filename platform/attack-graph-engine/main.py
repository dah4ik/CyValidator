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


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id = Column(Integer, primary_key=True, index=True)

    tenant_slug = Column(String(120), index=True, nullable=False)

    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)

    entry_point = Column(String(150), nullable=False)
    target_asset = Column(String(150), nullable=False)
    target_asset_id = Column(Integer, nullable=False)

    severity = Column(String(50), nullable=False)
    path_risk_score = Column(Integer, nullable=False)
    status = Column(String(80), default="active", nullable=False)

    nodes_json = Column(Text, nullable=False)
    edges_json = Column(Text, nullable=False)

    business_impact = Column(Text, nullable=False)
    technical_reasoning = Column(Text, nullable=False)
    recommended_break_point = Column(Text, nullable=False)
    estimated_risk_reduction = Column(Integer, nullable=False)

    related_findings = Column(String(500), nullable=True)
    related_controls = Column(String(500), nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AttackPathCreateRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=3)

    entry_point: str = Field(..., min_length=2, max_length=150)
    target_asset: str = Field(..., min_length=2, max_length=150)
    target_asset_id: int

    severity: str = Field(..., min_length=2, max_length=50)
    path_risk_score: int = Field(..., ge=0, le=100)

    nodes: list[dict]
    edges: list[dict]

    business_impact: str = Field(..., min_length=3)
    technical_reasoning: str = Field(..., min_length=3)
    recommended_break_point: str = Field(..., min_length=3)
    estimated_risk_reduction: int = Field(..., ge=0, le=100)

    related_findings: Optional[str] = None
    related_controls: Optional[str] = None


class AttackPathUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=200)
    description: Optional[str] = Field(None, min_length=3)

    entry_point: Optional[str] = Field(None, min_length=2, max_length=150)
    target_asset: Optional[str] = Field(None, min_length=2, max_length=150)
    target_asset_id: Optional[int] = None

    severity: Optional[str] = Field(None, min_length=2, max_length=50)
    path_risk_score: Optional[int] = Field(None, ge=0, le=100)
    status: Optional[str] = Field(None, min_length=2, max_length=80)

    nodes: Optional[list[dict]] = None
    edges: Optional[list[dict]] = None

    business_impact: Optional[str] = Field(None, min_length=3)
    technical_reasoning: Optional[str] = Field(None, min_length=3)
    recommended_break_point: Optional[str] = Field(None, min_length=3)
    estimated_risk_reduction: Optional[int] = Field(None, ge=0, le=100)

    related_findings: Optional[str] = None
    related_controls: Optional[str] = None


class AttackPathResponse(BaseModel):
    id: int
    tenant_slug: str

    name: str
    description: str

    entry_point: str
    target_asset: str
    target_asset_id: int

    severity: str
    path_risk_score: int
    status: str

    nodes: list[dict]
    edges: list[dict]

    business_impact: str
    technical_reasoning: str
    recommended_break_point: str
    estimated_risk_reduction: int

    related_findings: Optional[str]
    related_controls: Optional[str]

    created_at: datetime
    updated_at: datetime


app = FastAPI(
    title="CyValidator Attack Graph Engine",
    description="Attack path simulation and break-point recommendation engine for CyValidator",
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


def require_attack_graph_write_permission(
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
            detail="Attack graph write permission required",
        )

    return identity


def serialize_attack_path(path: AttackPath) -> dict:
    return {
        "id": path.id,
        "tenant_slug": path.tenant_slug,
        "name": path.name,
        "description": path.description,
        "entry_point": path.entry_point,
        "target_asset": path.target_asset,
        "target_asset_id": path.target_asset_id,
        "severity": path.severity,
        "path_risk_score": path.path_risk_score,
        "status": path.status,
        "nodes": json.loads(path.nodes_json),
        "edges": json.loads(path.edges_json),
        "business_impact": path.business_impact,
        "technical_reasoning": path.technical_reasoning,
        "recommended_break_point": path.recommended_break_point,
        "estimated_risk_reduction": path.estimated_risk_reduction,
        "related_findings": path.related_findings,
        "related_controls": path.related_controls,
        "created_at": path.created_at,
        "updated_at": path.updated_at,
    }


def seed_demo_attack_paths(db: Session) -> None:
    existing = (
        db.query(AttackPath)
        .filter(AttackPath.tenant_slug == "demo-enterprise")
        .filter(AttackPath.name == "External to Database Exposure Path")
        .first()
    )

    if existing:
        return

    path_1_nodes = [
        {
            "id": "external-attacker",
            "label": "External Attacker",
            "type": "entry-point",
            "zone": "Internet",
            "risk": "High",
        },
        {
            "id": "linux-web-01",
            "label": "Linux Web Server",
            "type": "asset",
            "zone": "DMZ",
            "risk": "High",
        },
        {
            "id": "db-postgres-01",
            "label": "PostgreSQL Database",
            "type": "critical-asset",
            "zone": "Database Zone",
            "risk": "Critical",
        },
    ]

    path_1_edges = [
        {
            "source": "external-attacker",
            "target": "linux-web-01",
            "label": "Public service exposure",
            "technique": "Initial Access",
        },
        {
            "source": "linux-web-01",
            "target": "db-postgres-01",
            "label": "Database reachable from non-application segment",
            "technique": "Lateral Movement",
        },
    ]

    path_2_nodes = [
        {
            "id": "win-client-01",
            "label": "Corporate Workstation",
            "type": "entry-point",
            "zone": "User Zone",
            "risk": "High",
        },
        {
            "id": "docker-host-01",
            "label": "Docker Runtime Host",
            "type": "asset",
            "zone": "Server Zone",
            "risk": "Critical",
        },
        {
            "id": "db-postgres-01",
            "label": "PostgreSQL Database",
            "type": "critical-asset",
            "zone": "Database Zone",
            "risk": "Critical",
        },
    ]

    path_2_edges = [
        {
            "source": "win-client-01",
            "target": "docker-host-01",
            "label": "Unnecessary lateral access from user zone",
            "technique": "Lateral Movement",
        },
        {
            "source": "docker-host-01",
            "target": "db-postgres-01",
            "label": "Privileged runtime can reach sensitive database",
            "technique": "Privilege Escalation",
        },
    ]

    path_3_nodes = [
        {
            "id": "external-attacker",
            "label": "External Attacker",
            "type": "entry-point",
            "zone": "Internet",
            "risk": "High",
        },
        {
            "id": "linux-web-01",
            "label": "Linux Web Server",
            "type": "asset",
            "zone": "DMZ",
            "risk": "High",
        },
        {
            "id": "jump-mgmt-01",
            "label": "Management Jump Server",
            "type": "privileged-asset",
            "zone": "Management Zone",
            "risk": "High",
        },
        {
            "id": "db-postgres-01",
            "label": "PostgreSQL Database",
            "type": "critical-asset",
            "zone": "Database Zone",
            "risk": "Critical",
        },
    ]

    path_3_edges = [
        {
            "source": "external-attacker",
            "target": "linux-web-01",
            "label": "Public-facing host with SSH hardening issue",
            "technique": "Initial Access",
        },
        {
            "source": "linux-web-01",
            "target": "jump-mgmt-01",
            "label": "Potential administrative trust path",
            "technique": "Lateral Movement",
        },
        {
            "source": "jump-mgmt-01",
            "target": "db-postgres-01",
            "label": "Privileged management path to sensitive database",
            "technique": "Credential Access",
        },
    ]

    demo_paths = [
        AttackPath(
            tenant_slug="demo-enterprise",
            name="External to Database Exposure Path",
            description="Simulates a path where an external attacker reaches a public Linux server and then a sensitive database due to weak segmentation.",
            entry_point="External Attacker",
            target_asset="PostgreSQL Database",
            target_asset_id=2,
            severity="Critical",
            path_risk_score=96,
            status="active",
            nodes_json=json.dumps(path_1_nodes),
            edges_json=json.dumps(path_1_edges),
            business_impact="Sensitive database exposure may lead to unauthorized data access and business disruption.",
            technical_reasoning="The path combines public service exposure, weak SSH hardening and database network reachability.",
            recommended_break_point="Restrict PostgreSQL access to approved application hosts only.",
            estimated_risk_reduction=42,
            related_findings="2,1",
            related_controls="DB-NET-001,LINUX-SSH-001",
        ),
        AttackPath(
            tenant_slug="demo-enterprise",
            name="User Zone to Container Host to Database Path",
            description="Simulates lateral movement from a corporate workstation to a container host and then to the database zone.",
            entry_point="Corporate Workstation",
            target_asset="PostgreSQL Database",
            target_asset_id=2,
            severity="Critical",
            path_risk_score=92,
            status="active",
            nodes_json=json.dumps(path_2_nodes),
            edges_json=json.dumps(path_2_edges),
            business_impact="A compromised endpoint may become a stepping stone toward container infrastructure and sensitive data.",
            technical_reasoning="The path combines weak segmentation, privileged container runtime and database reachability.",
            recommended_break_point="Block direct User Zone access to Server Zone and Database Zone.",
            estimated_risk_reduction=38,
            related_findings="4,3,2",
            related_controls="NET-SEG-001,DOCKER-RUNTIME-001,DB-NET-001",
        ),
        AttackPath(
            tenant_slug="demo-enterprise",
            name="Public Server to Management Zone Path",
            description="Simulates a high-impact path from a public-facing server to the management zone and then to a critical database.",
            entry_point="External Attacker",
            target_asset="PostgreSQL Database",
            target_asset_id=2,
            severity="High",
            path_risk_score=84,
            status="active",
            nodes_json=json.dumps(path_3_nodes),
            edges_json=json.dumps(path_3_edges),
            business_impact="Management zone exposure may increase the blast radius of a public-facing system compromise.",
            technical_reasoning="The path exists because of a combination of weak hardening and excessive administrative trust paths.",
            recommended_break_point="Enforce strict DMZ to Management Zone isolation and allow only approved jump workflows.",
            estimated_risk_reduction=31,
            related_findings="1,5",
            related_controls="LINUX-SSH-001,LOG-AUDIT-001",
        ),
    ]

    db.add_all(demo_paths)
    db.commit()


@app.on_event("startup")
def on_startup():
    wait_for_database()
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed_demo_attack_paths(db)
    finally:
        db.close()


@app.get("/health")
def health_check():
    return {
        "service": "attack-graph-engine",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/info")
def service_info():
    return {
        "name": "CyValidator Attack Graph Engine",
        "role": "Simulates attack paths, critical assets and break-point recommendations",
        "version": "0.1.0",
    }


@app.get("/api/attack-graph/paths", response_model=list[AttackPathResponse])
def list_attack_paths(
        severity: Optional[str] = None,
        status_filter: Optional[str] = None,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    query = db.query(AttackPath).filter(
        AttackPath.tenant_slug == identity["tenant"]
    )

    if severity:
        query = query.filter(AttackPath.severity == severity)

    if status_filter:
        query = query.filter(AttackPath.status == status_filter)

    paths = query.order_by(AttackPath.path_risk_score.desc()).all()

    return [serialize_attack_path(path) for path in paths]


@app.get("/api/attack-graph/summary")
def attack_graph_summary(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    paths = (
        db.query(AttackPath)
        .filter(AttackPath.tenant_slug == identity["tenant"])
        .all()
    )

    active_paths = [path for path in paths if path.status == "active"]

    critical_paths = [
        path for path in active_paths
        if path.severity.lower() == "critical"
    ]

    high_paths = [
        path for path in active_paths
        if path.severity.lower() == "high"
    ]

    average_path_risk = 0

    if active_paths:
        average_path_risk = round(
            sum(path.path_risk_score for path in active_paths) / len(active_paths),
            2,
            )

    total_estimated_risk_reduction = sum(
        path.estimated_risk_reduction for path in active_paths
    )

    most_valuable_break_points = sorted(
        [
            {
                "path_id": path.id,
                "path_name": path.name,
                "recommended_break_point": path.recommended_break_point,
                "estimated_risk_reduction": path.estimated_risk_reduction,
            }
            for path in active_paths
        ],
        key=lambda item: item["estimated_risk_reduction"],
        reverse=True,
    )

    return {
        "tenant": identity["tenant"],
        "total_paths": len(paths),
        "active_paths": len(active_paths),
        "critical_paths": len(critical_paths),
        "high_paths": len(high_paths),
        "average_path_risk": average_path_risk,
        "total_estimated_risk_reduction": total_estimated_risk_reduction,
        "top_break_points": most_valuable_break_points[:5],
    }


@app.get("/api/attack-graph/critical")
def critical_attack_paths(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    paths = (
        db.query(AttackPath)
        .filter(AttackPath.tenant_slug == identity["tenant"])
        .filter(AttackPath.severity == "Critical")
        .order_by(AttackPath.path_risk_score.desc())
        .all()
    )

    return [serialize_attack_path(path) for path in paths]


@app.get("/api/attack-graph/break-points")
def attack_graph_break_points(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    paths = (
        db.query(AttackPath)
        .filter(AttackPath.tenant_slug == identity["tenant"])
        .filter(AttackPath.status == "active")
        .all()
    )

    break_points = []

    for path in paths:
        break_points.append(
            {
                "path_id": path.id,
                "path_name": path.name,
                "severity": path.severity,
                "path_risk_score": path.path_risk_score,
                "recommended_break_point": path.recommended_break_point,
                "estimated_risk_reduction": path.estimated_risk_reduction,
                "business_impact": path.business_impact,
            }
        )

    sorted_break_points = sorted(
        break_points,
        key=lambda item: item["estimated_risk_reduction"],
        reverse=True,
    )

    return {
        "tenant": identity["tenant"],
        "message": "Break-points represent the most effective places to disrupt attack paths.",
        "break_points": sorted_break_points,
    }


@app.get("/api/attack-graph/paths/{path_id}", response_model=AttackPathResponse)
def get_attack_path(
        path_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    path = (
        db.query(AttackPath)
        .filter(AttackPath.id == path_id)
        .filter(AttackPath.tenant_slug == identity["tenant"])
        .first()
    )

    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack path not found",
        )

    return serialize_attack_path(path)


@app.post(
    "/api/attack-graph/paths",
    response_model=AttackPathResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_attack_path(
        payload: AttackPathCreateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_attack_graph_write_permission),
):
    path = AttackPath(
        tenant_slug=identity["tenant"],
        name=payload.name,
        description=payload.description,
        entry_point=payload.entry_point,
        target_asset=payload.target_asset,
        target_asset_id=payload.target_asset_id,
        severity=payload.severity,
        path_risk_score=payload.path_risk_score,
        status="active",
        nodes_json=json.dumps(payload.nodes),
        edges_json=json.dumps(payload.edges),
        business_impact=payload.business_impact,
        technical_reasoning=payload.technical_reasoning,
        recommended_break_point=payload.recommended_break_point,
        estimated_risk_reduction=payload.estimated_risk_reduction,
        related_findings=payload.related_findings,
        related_controls=payload.related_controls,
    )

    db.add(path)
    db.commit()
    db.refresh(path)

    return serialize_attack_path(path)


@app.put("/api/attack-graph/paths/{path_id}", response_model=AttackPathResponse)
def update_attack_path(
        path_id: int,
        payload: AttackPathUpdateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_attack_graph_write_permission),
):
    path = (
        db.query(AttackPath)
        .filter(AttackPath.id == path_id)
        .filter(AttackPath.tenant_slug == identity["tenant"])
        .first()
    )

    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack path not found",
        )

    update_data = payload.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        if field == "nodes":
            path.nodes_json = json.dumps(value)
        elif field == "edges":
            path.edges_json = json.dumps(value)
        else:
            setattr(path, field, value)

    path.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(path)

    return serialize_attack_path(path)


@app.patch("/api/attack-graph/paths/{path_id}/status")
def update_attack_path_status(
        path_id: int,
        status_value: str,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_attack_graph_write_permission),
):
    allowed_statuses = [
        "active",
        "mitigated",
        "risk_accepted",
        "false_positive",
    ]

    if status_value not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Allowed values: {allowed_statuses}",
        )

    path = (
        db.query(AttackPath)
        .filter(AttackPath.id == path_id)
        .filter(AttackPath.tenant_slug == identity["tenant"])
        .first()
    )

    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack path not found",
        )

    path.status = status_value
    path.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(path)

    return serialize_attack_path(path)


@app.delete("/api/attack-graph/paths/{path_id}")
def delete_attack_path(
        path_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_attack_graph_write_permission),
):
    path = (
        db.query(AttackPath)
        .filter(AttackPath.id == path_id)
        .filter(AttackPath.tenant_slug == identity["tenant"])
        .first()
    )

    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack path not found",
        )

    db.delete(path)
    db.commit()

    return {
        "message": "Attack path deleted successfully",
        "path_id": path_id,
    }