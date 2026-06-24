import os
import time
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker


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


class ValidationPack(Base):
    __tablename__ = "validation_packs"

    id = Column(Integer, primary_key=True, index=True)

    tenant_slug = Column(String(120), index=True, nullable=False)

    pack_key = Column(String(150), unique=True, index=True, nullable=False)
    name = Column(String(200), nullable=False)
    category = Column(String(120), nullable=False)
    version = Column(String(50), nullable=False)

    description = Column(Text, nullable=False)
    author = Column(String(150), nullable=False)

    status = Column(String(80), default="enabled", nullable=False)
    maturity = Column(String(80), default="beta", nullable=False)

    target_platform = Column(String(150), nullable=False)
    risk_domain = Column(String(150), nullable=False)

    checks_count = Column(Integer, default=0, nullable=False)
    last_run_status = Column(String(80), nullable=True)
    last_run_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    checks = relationship("ValidationCheck", back_populates="pack")


class ValidationCheck(Base):
    __tablename__ = "validation_checks"

    id = Column(Integer, primary_key=True, index=True)

    tenant_slug = Column(String(120), index=True, nullable=False)

    pack_id = Column(Integer, ForeignKey("validation_packs.id"), nullable=False)

    check_key = Column(String(150), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)

    severity = Column(String(50), nullable=False)
    control_id = Column(String(150), nullable=False)
    framework = Column(String(150), nullable=True)

    expected_result = Column(String(255), nullable=False)
    recommendation = Column(Text, nullable=False)

    check_type = Column(String(120), nullable=False)
    enabled = Column(String(20), default="true", nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    pack = relationship("ValidationPack", back_populates="checks")


class ValidationCheckCreateRequest(BaseModel):
    check_key: str = Field(..., min_length=2, max_length=150)
    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=3)

    severity: str = Field(..., min_length=2, max_length=50)
    control_id: str = Field(..., min_length=2, max_length=150)
    framework: Optional[str] = None

    expected_result: str = Field(..., min_length=2, max_length=255)
    recommendation: str = Field(..., min_length=3)

    check_type: str = Field(..., min_length=2, max_length=120)
    enabled: str = Field(default="true", min_length=2, max_length=20)


class ValidationPackCreateRequest(BaseModel):
    pack_key: str = Field(..., min_length=2, max_length=150)
    name: str = Field(..., min_length=3, max_length=200)
    category: str = Field(..., min_length=2, max_length=120)
    version: str = Field(..., min_length=1, max_length=50)

    description: str = Field(..., min_length=3)
    author: str = Field(..., min_length=2, max_length=150)

    status: str = Field(default="enabled", min_length=2, max_length=80)
    maturity: str = Field(default="beta", min_length=2, max_length=80)

    target_platform: str = Field(..., min_length=2, max_length=150)
    risk_domain: str = Field(..., min_length=2, max_length=150)

    checks: list[ValidationCheckCreateRequest] = []


class ValidationPackUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=200)
    category: Optional[str] = Field(None, min_length=2, max_length=120)
    version: Optional[str] = Field(None, min_length=1, max_length=50)

    description: Optional[str] = Field(None, min_length=3)
    author: Optional[str] = Field(None, min_length=2, max_length=150)

    status: Optional[str] = Field(None, min_length=2, max_length=80)
    maturity: Optional[str] = Field(None, min_length=2, max_length=80)

    target_platform: Optional[str] = Field(None, min_length=2, max_length=150)
    risk_domain: Optional[str] = Field(None, min_length=2, max_length=150)

    last_run_status: Optional[str] = None


class ValidationCheckResponse(BaseModel):
    id: int
    tenant_slug: str
    pack_id: int

    check_key: str
    title: str
    description: str

    severity: str
    control_id: str
    framework: Optional[str]

    expected_result: str
    recommendation: str

    check_type: str
    enabled: str

    created_at: datetime
    updated_at: datetime


class ValidationPackResponse(BaseModel):
    id: int
    tenant_slug: str

    pack_key: str
    name: str
    category: str
    version: str

    description: str
    author: str

    status: str
    maturity: str

    target_platform: str
    risk_domain: str

    checks_count: int
    last_run_status: Optional[str]
    last_run_at: Optional[datetime]

    created_at: datetime
    updated_at: datetime


class ValidationPackDetailResponse(ValidationPackResponse):
    checks: list[ValidationCheckResponse]


app = FastAPI(
    title="CyValidator Validation Pack Registry",
    description="Validation pack registry, metadata and check catalog for CyValidator",
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


def require_pack_write_permission(identity: dict = Depends(get_current_identity)) -> dict:
    allowed_roles = [
        "Platform Admin",
        "Security Manager",
    ]

    if identity["role"] not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Validation pack write permission required",
        )

    return identity


def serialize_check(check: ValidationCheck) -> dict:
    return {
        "id": check.id,
        "tenant_slug": check.tenant_slug,
        "pack_id": check.pack_id,
        "check_key": check.check_key,
        "title": check.title,
        "description": check.description,
        "severity": check.severity,
        "control_id": check.control_id,
        "framework": check.framework,
        "expected_result": check.expected_result,
        "recommendation": check.recommendation,
        "check_type": check.check_type,
        "enabled": check.enabled,
        "created_at": check.created_at,
        "updated_at": check.updated_at,
    }


def serialize_pack(pack: ValidationPack, include_checks: bool = False) -> dict:
    data = {
        "id": pack.id,
        "tenant_slug": pack.tenant_slug,
        "pack_key": pack.pack_key,
        "name": pack.name,
        "category": pack.category,
        "version": pack.version,
        "description": pack.description,
        "author": pack.author,
        "status": pack.status,
        "maturity": pack.maturity,
        "target_platform": pack.target_platform,
        "risk_domain": pack.risk_domain,
        "checks_count": pack.checks_count,
        "last_run_status": pack.last_run_status,
        "last_run_at": pack.last_run_at,
        "created_at": pack.created_at,
        "updated_at": pack.updated_at,
    }

    if include_checks:
        data["checks"] = [serialize_check(check) for check in pack.checks]

    return data


def create_pack_with_checks(
        db: Session,
        tenant_slug: str,
        pack_key: str,
        name: str,
        category: str,
        version: str,
        description: str,
        author: str,
        maturity: str,
        target_platform: str,
        risk_domain: str,
        checks: list[dict],
) -> None:
    existing = (
        db.query(ValidationPack)
        .filter(ValidationPack.tenant_slug == tenant_slug)
        .filter(ValidationPack.pack_key == pack_key)
        .first()
    )

    if existing:
        return

    pack = ValidationPack(
        tenant_slug=tenant_slug,
        pack_key=pack_key,
        name=name,
        category=category,
        version=version,
        description=description,
        author=author,
        status="enabled",
        maturity=maturity,
        target_platform=target_platform,
        risk_domain=risk_domain,
        checks_count=len(checks),
        last_run_status="not_run",
        last_run_at=None,
    )

    db.add(pack)
    db.commit()
    db.refresh(pack)

    for check_data in checks:
        check = ValidationCheck(
            tenant_slug=tenant_slug,
            pack_id=pack.id,
            check_key=check_data["check_key"],
            title=check_data["title"],
            description=check_data["description"],
            severity=check_data["severity"],
            control_id=check_data["control_id"],
            framework=check_data.get("framework"),
            expected_result=check_data["expected_result"],
            recommendation=check_data["recommendation"],
            check_type=check_data["check_type"],
            enabled="true",
        )

        db.add(check)

    db.commit()


def seed_validation_packs(db: Session) -> None:
    tenant_slug = "demo-enterprise"

    create_pack_with_checks(
        db=db,
        tenant_slug=tenant_slug,
        pack_key="linux-hardening-pack",
        name="Linux Hardening Pack",
        category="Operating System Security",
        version="1.0.0",
        description="Validates Linux server hardening posture, SSH exposure, host firewall and audit controls.",
        author="CyValidator Security Research",
        maturity="stable",
        target_platform="Ubuntu Server / Linux",
        risk_domain="Host Hardening",
        checks=[
            {
                "check_key": "LINUX-SSH-001",
                "title": "SSH root login must be disabled",
                "description": "Detects whether direct root login is allowed over SSH.",
                "severity": "High",
                "control_id": "LINUX-SSH-001",
                "framework": "Internal Linux Baseline",
                "expected_result": "PermitRootLogin no",
                "recommendation": "Disable root login over SSH and use named administrative accounts.",
                "check_type": "configuration",
            },
            {
                "check_key": "LINUX-SSH-002",
                "title": "SSH password authentication should be disabled",
                "description": "Validates whether SSH password authentication is disabled in favor of key-based access.",
                "severity": "Medium",
                "control_id": "LINUX-SSH-002",
                "framework": "Internal Linux Baseline",
                "expected_result": "PasswordAuthentication no",
                "recommendation": "Use SSH keys and disable password-based authentication.",
                "check_type": "configuration",
            },
            {
                "check_key": "LINUX-FW-001",
                "title": "Host firewall must be enabled",
                "description": "Validates whether host firewall protection is enabled.",
                "severity": "High",
                "control_id": "LINUX-FW-001",
                "framework": "Internal Linux Baseline",
                "expected_result": "Firewall enabled",
                "recommendation": "Enable host firewall and allow only required inbound services.",
                "check_type": "configuration",
            },
            {
                "check_key": "LINUX-AUDIT-001",
                "title": "Audit logging must be enabled",
                "description": "Checks whether Linux audit logging is enabled and active.",
                "severity": "Medium",
                "control_id": "LINUX-AUDIT-001",
                "framework": "Internal Linux Baseline",
                "expected_result": "Audit service enabled",
                "recommendation": "Enable auditd and forward security logs to central monitoring.",
                "check_type": "logging",
            },
        ],
    )

    create_pack_with_checks(
        db=db,
        tenant_slug=tenant_slug,
        pack_key="docker-security-pack",
        name="Docker Security Pack",
        category="Container Security",
        version="1.0.0",
        description="Validates Docker runtime security, privileged containers, root execution and dangerous mounts.",
        author="CyValidator Security Research",
        maturity="stable",
        target_platform="Docker / Container Hosts",
        risk_domain="Container Runtime",
        checks=[
            {
                "check_key": "DOCKER-RUNTIME-001",
                "title": "Privileged containers must be disabled",
                "description": "Detects containers running with privileged mode enabled.",
                "severity": "Critical",
                "control_id": "DOCKER-RUNTIME-001",
                "framework": "Internal Container Security Baseline",
                "expected_result": "Privileged mode disabled",
                "recommendation": "Avoid privileged containers and enforce least privilege runtime policies.",
                "check_type": "runtime",
            },
            {
                "check_key": "DOCKER-USER-001",
                "title": "Containers should not run as root",
                "description": "Validates whether containers are running as non-root users.",
                "severity": "Medium",
                "control_id": "DOCKER-USER-001",
                "framework": "Internal Container Security Baseline",
                "expected_result": "Non-root user",
                "recommendation": "Define a non-root user in Dockerfiles and runtime policies.",
                "check_type": "runtime",
            },
            {
                "check_key": "DOCKER-MOUNT-001",
                "title": "Docker socket must not be mounted into containers",
                "description": "Detects dangerous docker.sock mounts inside containers.",
                "severity": "Critical",
                "control_id": "DOCKER-MOUNT-001",
                "framework": "Internal Container Security Baseline",
                "expected_result": "No docker.sock mount",
                "recommendation": "Remove Docker socket mounts from application containers.",
                "check_type": "runtime",
            },
            {
                "check_key": "DOCKER-CAP-001",
                "title": "Dangerous Linux capabilities must be removed",
                "description": "Checks for excessive Linux capabilities assigned to containers.",
                "severity": "High",
                "control_id": "DOCKER-CAP-001",
                "framework": "Internal Container Security Baseline",
                "expected_result": "Least privilege capabilities",
                "recommendation": "Drop unnecessary capabilities and avoid SYS_ADMIN.",
                "check_type": "runtime",
            },
        ],
    )

    create_pack_with_checks(
        db=db,
        tenant_slug=tenant_slug,
        pack_key="database-exposure-pack",
        name="Database Exposure Pack",
        category="Database Security",
        version="1.0.0",
        description="Validates database exposure, network reachability and segmentation assumptions.",
        author="CyValidator Security Research",
        maturity="stable",
        target_platform="PostgreSQL / Database Services",
        risk_domain="Data Exposure",
        checks=[
            {
                "check_key": "DB-NET-001",
                "title": "Database must be reachable only from application zone",
                "description": "Validates whether database services are reachable from unauthorized network zones.",
                "severity": "Critical",
                "control_id": "DB-NET-001",
                "framework": "Internal Database Baseline",
                "expected_result": "Application Zone only",
                "recommendation": "Restrict database access to approved application hosts only.",
                "check_type": "network",
            },
            {
                "check_key": "DB-AUTH-001",
                "title": "Default credentials must not be used",
                "description": "Detects simulated usage of known default database credentials.",
                "severity": "Critical",
                "control_id": "DB-AUTH-001",
                "framework": "Internal Database Baseline",
                "expected_result": "No default credentials",
                "recommendation": "Rotate default credentials and enforce strong secrets management.",
                "check_type": "authentication",
            },
            {
                "check_key": "DB-LOG-001",
                "title": "Database authentication logging must be enabled",
                "description": "Validates whether database authentication events are logged.",
                "severity": "Medium",
                "control_id": "DB-LOG-001",
                "framework": "Internal Database Baseline",
                "expected_result": "Authentication logging enabled",
                "recommendation": "Enable database authentication logging and forward logs to monitoring.",
                "check_type": "logging",
            },
        ],
    )

    create_pack_with_checks(
        db=db,
        tenant_slug=tenant_slug,
        pack_key="web-api-security-pack",
        name="Web API Security Pack",
        category="Application Security",
        version="1.0.0",
        description="Validates common Web API security controls such as headers, verbose errors and rate limiting.",
        author="CyValidator Security Research",
        maturity="beta",
        target_platform="Web APIs",
        risk_domain="Application Exposure",
        checks=[
            {
                "check_key": "API-HEADERS-001",
                "title": "Security headers must be present",
                "description": "Checks whether expected HTTP security headers are configured.",
                "severity": "Medium",
                "control_id": "API-HEADERS-001",
                "framework": "Internal API Security Baseline",
                "expected_result": "Security headers present",
                "recommendation": "Configure security headers such as HSTS, X-Content-Type-Options and CSP.",
                "check_type": "http",
            },
            {
                "check_key": "API-ERROR-001",
                "title": "Verbose errors must not expose internals",
                "description": "Detects verbose error messages that may expose internal details.",
                "severity": "Medium",
                "control_id": "API-ERROR-001",
                "framework": "Internal API Security Baseline",
                "expected_result": "Generic error responses",
                "recommendation": "Return generic error messages and keep technical details in logs only.",
                "check_type": "application",
            },
            {
                "check_key": "API-RATE-001",
                "title": "Rate limiting should be enabled",
                "description": "Checks whether API rate limiting is configured.",
                "severity": "High",
                "control_id": "API-RATE-001",
                "framework": "Internal API Security Baseline",
                "expected_result": "Rate limiting enabled",
                "recommendation": "Enable API rate limiting for authentication and sensitive endpoints.",
                "check_type": "application",
            },
        ],
    )

    create_pack_with_checks(
        db=db,
        tenant_slug=tenant_slug,
        pack_key="network-segmentation-pack",
        name="Network Segmentation Pack",
        category="Network Security",
        version="1.0.0",
        description="Validates network segmentation controls and unnecessary reachability between zones.",
        author="CyValidator Security Research",
        maturity="beta",
        target_platform="Enterprise Networks",
        risk_domain="Lateral Movement",
        checks=[
            {
                "check_key": "NET-SEG-001",
                "title": "User zone must not directly access database zone",
                "description": "Detects direct workstation access to database services.",
                "severity": "High",
                "control_id": "NET-SEG-001",
                "framework": "Internal Network Segmentation Baseline",
                "expected_result": "Blocked",
                "recommendation": "Block direct user zone to database zone access.",
                "check_type": "network",
            },
            {
                "check_key": "NET-DMZ-001",
                "title": "DMZ must be isolated from management zone",
                "description": "Checks whether public-facing DMZ systems can reach management assets.",
                "severity": "Critical",
                "control_id": "NET-DMZ-001",
                "framework": "Internal Network Segmentation Baseline",
                "expected_result": "Blocked",
                "recommendation": "Restrict DMZ to Management Zone traffic to approved flows only.",
                "check_type": "network",
            },
        ],
    )

    create_pack_with_checks(
        db=db,
        tenant_slug=tenant_slug,
        pack_key="iam-risk-pack",
        name="IAM Risk Pack",
        category="Identity Security",
        version="1.0.0",
        description="Validates identity and access management assumptions such as MFA and privileged access.",
        author="CyValidator Security Research",
        maturity="beta",
        target_platform="IAM / Access Control",
        risk_domain="Identity Exposure",
        checks=[
            {
                "check_key": "IAM-MFA-001",
                "title": "Privileged access must require MFA",
                "description": "Validates whether privileged users are required to use MFA.",
                "severity": "Critical",
                "control_id": "IAM-MFA-001",
                "framework": "Internal IAM Baseline",
                "expected_result": "MFA required",
                "recommendation": "Enforce MFA for all privileged access paths.",
                "check_type": "identity",
            },
            {
                "check_key": "IAM-ADMIN-001",
                "title": "Inactive admin accounts must be disabled",
                "description": "Detects inactive privileged accounts.",
                "severity": "High",
                "control_id": "IAM-ADMIN-001",
                "framework": "Internal IAM Baseline",
                "expected_result": "No inactive admin accounts",
                "recommendation": "Disable inactive privileged accounts and review admin group membership.",
                "check_type": "identity",
            },
        ],
    )

    create_pack_with_checks(
        db=db,
        tenant_slug=tenant_slug,
        pack_key="data-protection-pack",
        name="Data Protection Pack",
        category="Data Security",
        version="1.0.0",
        description="Validates sensitive data protection controls such as encryption and backup exposure.",
        author="CyValidator Security Research",
        maturity="beta",
        target_platform="Databases / File Stores / Backup Systems",
        risk_domain="Sensitive Data",
        checks=[
            {
                "check_key": "DATA-ENC-001",
                "title": "Sensitive data must be encrypted at rest",
                "description": "Validates whether sensitive data stores use encryption at rest.",
                "severity": "Critical",
                "control_id": "DATA-ENC-001",
                "framework": "Internal Data Protection Baseline",
                "expected_result": "Encryption enabled",
                "recommendation": "Enable encryption at rest for sensitive databases and storage systems.",
                "check_type": "data-protection",
            },
            {
                "check_key": "DATA-BACKUP-001",
                "title": "Backup systems must not be exposed to user networks",
                "description": "Checks whether backup infrastructure is isolated from user networks.",
                "severity": "High",
                "control_id": "DATA-BACKUP-001",
                "framework": "Internal Data Protection Baseline",
                "expected_result": "Backup network isolated",
                "recommendation": "Restrict backup system access to approved administrative paths only.",
                "check_type": "network",
            },
        ],
    )


@app.on_event("startup")
def on_startup():
    wait_for_database()
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed_validation_packs(db)
    finally:
        db.close()


@app.get("/health")
def health_check():
    return {
        "service": "validation-pack-registry",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/info")
def service_info():
    return {
        "name": "CyValidator Validation Pack Registry",
        "role": "Manages validation pack metadata, check catalog and marketplace-style registry",
        "version": "0.1.0",
    }


@app.get("/api/validation-packs", response_model=list[ValidationPackResponse])
def list_validation_packs(
        category: Optional[str] = None,
        status_filter: Optional[str] = None,
        maturity: Optional[str] = None,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    query = db.query(ValidationPack).filter(
        ValidationPack.tenant_slug == identity["tenant"]
    )

    if category:
        query = query.filter(ValidationPack.category == category)

    if status_filter:
        query = query.filter(ValidationPack.status == status_filter)

    if maturity:
        query = query.filter(ValidationPack.maturity == maturity)

    packs = query.order_by(ValidationPack.category.asc(), ValidationPack.name.asc()).all()

    return [serialize_pack(pack) for pack in packs]


@app.get("/api/validation-packs/summary")
def validation_pack_summary(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    packs = (
        db.query(ValidationPack)
        .filter(ValidationPack.tenant_slug == identity["tenant"])
        .all()
    )

    total_packs = len(packs)
    enabled_packs = len([pack for pack in packs if pack.status == "enabled"])
    disabled_packs = len([pack for pack in packs if pack.status == "disabled"])
    stable_packs = len([pack for pack in packs if pack.maturity == "stable"])
    beta_packs = len([pack for pack in packs if pack.maturity == "beta"])
    total_checks = sum(pack.checks_count for pack in packs)

    categories = {}

    for pack in packs:
        if pack.category not in categories:
            categories[pack.category] = {
                "category": pack.category,
                "packs": 0,
                "checks": 0,
                "enabled": 0,
                "disabled": 0,
            }

        categories[pack.category]["packs"] += 1
        categories[pack.category]["checks"] += pack.checks_count

        if pack.status == "enabled":
            categories[pack.category]["enabled"] += 1

        if pack.status == "disabled":
            categories[pack.category]["disabled"] += 1

    return {
        "tenant": identity["tenant"],
        "total_packs": total_packs,
        "enabled_packs": enabled_packs,
        "disabled_packs": disabled_packs,
        "stable_packs": stable_packs,
        "beta_packs": beta_packs,
        "total_checks": total_checks,
        "categories": list(categories.values()),
    }


@app.get("/api/validation-packs/categories")
def validation_pack_categories(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    packs = (
        db.query(ValidationPack)
        .filter(ValidationPack.tenant_slug == identity["tenant"])
        .all()
    )

    categories = sorted(list(set(pack.category for pack in packs)))

    return {
        "tenant": identity["tenant"],
        "categories": categories,
    }


@app.get("/api/validation-packs/{pack_key}", response_model=ValidationPackDetailResponse)
def get_validation_pack(
        pack_key: str,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    pack = (
        db.query(ValidationPack)
        .filter(ValidationPack.tenant_slug == identity["tenant"])
        .filter(ValidationPack.pack_key == pack_key)
        .first()
    )

    if not pack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Validation pack not found",
        )

    return serialize_pack(pack, include_checks=True)


@app.get("/api/validation-packs/{pack_key}/checks", response_model=list[ValidationCheckResponse])
def get_validation_pack_checks(
        pack_key: str,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    pack = (
        db.query(ValidationPack)
        .filter(ValidationPack.tenant_slug == identity["tenant"])
        .filter(ValidationPack.pack_key == pack_key)
        .first()
    )

    if not pack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Validation pack not found",
        )

    checks = (
        db.query(ValidationCheck)
        .filter(ValidationCheck.tenant_slug == identity["tenant"])
        .filter(ValidationCheck.pack_id == pack.id)
        .order_by(ValidationCheck.id.asc())
        .all()
    )

    return [serialize_check(check) for check in checks]


@app.post(
    "/api/validation-packs",
    response_model=ValidationPackDetailResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_validation_pack(
        payload: ValidationPackCreateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_pack_write_permission),
):
    existing = (
        db.query(ValidationPack)
        .filter(ValidationPack.tenant_slug == identity["tenant"])
        .filter(ValidationPack.pack_key == payload.pack_key)
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Validation pack already exists",
        )

    pack = ValidationPack(
        tenant_slug=identity["tenant"],
        pack_key=payload.pack_key,
        name=payload.name,
        category=payload.category,
        version=payload.version,
        description=payload.description,
        author=payload.author,
        status=payload.status,
        maturity=payload.maturity,
        target_platform=payload.target_platform,
        risk_domain=payload.risk_domain,
        checks_count=len(payload.checks),
        last_run_status="not_run",
        last_run_at=None,
    )

    db.add(pack)
    db.commit()
    db.refresh(pack)

    for check_payload in payload.checks:
        check = ValidationCheck(
            tenant_slug=identity["tenant"],
            pack_id=pack.id,
            check_key=check_payload.check_key,
            title=check_payload.title,
            description=check_payload.description,
            severity=check_payload.severity,
            control_id=check_payload.control_id,
            framework=check_payload.framework,
            expected_result=check_payload.expected_result,
            recommendation=check_payload.recommendation,
            check_type=check_payload.check_type,
            enabled=check_payload.enabled,
        )

        db.add(check)

    db.commit()
    db.refresh(pack)

    return serialize_pack(pack, include_checks=True)


@app.put("/api/validation-packs/{pack_key}", response_model=ValidationPackResponse)
def update_validation_pack(
        pack_key: str,
        payload: ValidationPackUpdateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_pack_write_permission),
):
    pack = (
        db.query(ValidationPack)
        .filter(ValidationPack.tenant_slug == identity["tenant"])
        .filter(ValidationPack.pack_key == pack_key)
        .first()
    )

    if not pack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Validation pack not found",
        )

    update_data = payload.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(pack, field, value)

    if payload.last_run_status:
        pack.last_run_at = datetime.now(timezone.utc)

    pack.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(pack)

    return serialize_pack(pack)


@app.patch("/api/validation-packs/{pack_key}/status", response_model=ValidationPackResponse)
def update_validation_pack_status(
        pack_key: str,
        status_value: str,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_pack_write_permission),
):
    allowed_statuses = [
        "enabled",
        "disabled",
        "deprecated",
        "testing",
    ]

    if status_value not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Allowed values: {allowed_statuses}",
        )

    pack = (
        db.query(ValidationPack)
        .filter(ValidationPack.tenant_slug == identity["tenant"])
        .filter(ValidationPack.pack_key == pack_key)
        .first()
    )

    if not pack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Validation pack not found",
        )

    pack.status = status_value
    pack.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(pack)

    return serialize_pack(pack)


@app.delete("/api/validation-packs/{pack_key}")
def delete_validation_pack(
        pack_key: str,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_pack_write_permission),
):
    pack = (
        db.query(ValidationPack)
        .filter(ValidationPack.tenant_slug == identity["tenant"])
        .filter(ValidationPack.pack_key == pack_key)
        .first()
    )

    if not pack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Validation pack not found",
        )

    checks = (
        db.query(ValidationCheck)
        .filter(ValidationCheck.tenant_slug == identity["tenant"])
        .filter(ValidationCheck.pack_id == pack.id)
        .all()
    )

    for check in checks:
        db.delete(check)

    db.delete(pack)
    db.commit()

    return {
        "message": "Validation pack deleted successfully",
        "pack_key": pack_key,
    }