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

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AssetCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=150)
    hostname: str = Field(..., min_length=2, max_length=150)
    ip_address: str = Field(..., min_length=3, max_length=50)

    asset_type: str = Field(..., min_length=2, max_length=80)
    os_type: str = Field(..., min_length=2, max_length=80)
    environment: str = Field(..., min_length=2, max_length=80)

    network_zone: str = Field(..., min_length=2, max_length=120)
    business_owner: str = Field(..., min_length=2, max_length=150)
    technical_owner: str = Field(..., min_length=2, max_length=150)

    business_criticality: int = Field(..., ge=1, le=5)
    exposure_level: str = Field(..., min_length=2, max_length=80)

    tags: Optional[str] = None
    description: Optional[str] = None


class AssetUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=150)
    hostname: Optional[str] = Field(None, min_length=2, max_length=150)
    ip_address: Optional[str] = Field(None, min_length=3, max_length=50)

    asset_type: Optional[str] = Field(None, min_length=2, max_length=80)
    os_type: Optional[str] = Field(None, min_length=2, max_length=80)
    environment: Optional[str] = Field(None, min_length=2, max_length=80)

    network_zone: Optional[str] = Field(None, min_length=2, max_length=120)
    business_owner: Optional[str] = Field(None, min_length=2, max_length=150)
    technical_owner: Optional[str] = Field(None, min_length=2, max_length=150)

    business_criticality: Optional[int] = Field(None, ge=1, le=5)
    exposure_level: Optional[str] = Field(None, min_length=2, max_length=80)

    tags: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None


class AssetResponse(BaseModel):
    id: int
    tenant_slug: str

    name: str
    hostname: str
    ip_address: str

    asset_type: str
    os_type: str
    environment: str

    network_zone: str
    business_owner: str
    technical_owner: str

    business_criticality: int
    exposure_level: str

    tags: Optional[str]
    description: Optional[str]
    status: str

    created_at: datetime
    updated_at: datetime


app = FastAPI(
    title="CyValidator Asset Service",
    description="Asset inventory, zones, owners and criticality management for CyValidator",
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


def require_asset_write_permission(identity: dict = Depends(get_current_identity)) -> dict:
    allowed_roles = [
        "Platform Admin",
        "Security Manager",
        "Security Analyst",
    ]

    if identity["role"] not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Asset write permission required",
        )

    return identity


def require_asset_delete_permission(identity: dict = Depends(get_current_identity)) -> dict:
    allowed_roles = [
        "Platform Admin",
        "Security Manager",
    ]

    if identity["role"] not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Asset delete permission required",
        )

    return identity


def seed_demo_assets(db: Session) -> None:
    existing_asset = (
        db.query(Asset)
        .filter(Asset.tenant_slug == "demo-enterprise")
        .filter(Asset.hostname == "linux-web-01")
        .first()
    )

    if existing_asset:
        return

    demo_assets = [
        Asset(
            tenant_slug="demo-enterprise",
            name="Linux Web Server",
            hostname="linux-web-01",
            ip_address="10.10.20.11",
            asset_type="server",
            os_type="Ubuntu Server",
            environment="production",
            network_zone="DMZ",
            business_owner="Digital Services",
            technical_owner="Infrastructure Team",
            business_criticality=5,
            exposure_level="public",
            tags="linux,web,dmz,critical",
            description="Public-facing Linux web server used by the demo enterprise environment.",
            status="active",
        ),
        Asset(
            tenant_slug="demo-enterprise",
            name="PostgreSQL Database",
            hostname="db-postgres-01",
            ip_address="10.10.30.21",
            asset_type="database",
            os_type="PostgreSQL",
            environment="production",
            network_zone="Database Zone",
            business_owner="Business Applications",
            technical_owner="Database Team",
            business_criticality=5,
            exposure_level="internal",
            tags="database,postgres,sensitive-data",
            description="Database server storing sensitive demo business data.",
            status="active",
        ),
        Asset(
            tenant_slug="demo-enterprise",
            name="Docker Runtime Host",
            hostname="docker-host-01",
            ip_address="10.10.40.15",
            asset_type="container-host",
            os_type="Ubuntu Server",
            environment="production",
            network_zone="Server Zone",
            business_owner="Platform Engineering",
            technical_owner="DevOps Team",
            business_criticality=4,
            exposure_level="internal",
            tags="docker,containers,devsecops",
            description="Container runtime host used for application services.",
            status="active",
        ),
        Asset(
            tenant_slug="demo-enterprise",
            name="Corporate Workstation",
            hostname="win-client-01",
            ip_address="10.10.10.51",
            asset_type="workstation",
            os_type="Windows 11",
            environment="corporate",
            network_zone="User Zone",
            business_owner="Corporate IT",
            technical_owner="Endpoint Team",
            business_criticality=3,
            exposure_level="internal",
            tags="endpoint,user-zone,windows",
            description="Corporate endpoint used to simulate user-zone exposure.",
            status="active",
        ),
        Asset(
            tenant_slug="demo-enterprise",
            name="Management Jump Server",
            hostname="jump-mgmt-01",
            ip_address="10.10.50.10",
            asset_type="server",
            os_type="Ubuntu Server",
            environment="production",
            network_zone="Management Zone",
            business_owner="Security Operations",
            technical_owner="Infrastructure Team",
            business_criticality=5,
            exposure_level="restricted",
            tags="management,jump-server,privileged-access",
            description="Privileged management server used for administrative access.",
            status="active",
        ),
    ]

    db.add_all(demo_assets)
    db.commit()


@app.on_event("startup")
def on_startup():
    wait_for_database()
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed_demo_assets(db)
    finally:
        db.close()


@app.get("/health")
def health_check():
    return {
        "service": "asset-service",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/info")
def service_info():
    return {
        "name": "CyValidator Asset Service",
        "role": "Manages enterprise assets, zones, ownership, exposure and business criticality",
        "version": "0.1.0",
    }


@app.get("/api/assets", response_model=list[AssetResponse])
def list_assets(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    tenant_slug = identity["tenant"]

    assets = (
        db.query(Asset)
        .filter(Asset.tenant_slug == tenant_slug)
        .order_by(Asset.id)
        .all()
    )

    return assets


@app.get("/api/assets/summary")
def assets_summary(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    tenant_slug = identity["tenant"]

    assets = db.query(Asset).filter(Asset.tenant_slug == tenant_slug).all()

    total_assets = len(assets)
    critical_assets = len([asset for asset in assets if asset.business_criticality >= 5])
    public_assets = len([asset for asset in assets if asset.exposure_level == "public"])

    zones = sorted(list(set(asset.network_zone for asset in assets)))
    environments = sorted(list(set(asset.environment for asset in assets)))
    asset_types = sorted(list(set(asset.asset_type for asset in assets)))

    return {
        "tenant": tenant_slug,
        "total_assets": total_assets,
        "critical_assets": critical_assets,
        "public_assets": public_assets,
        "zones": zones,
        "environments": environments,
        "asset_types": asset_types,
    }


@app.get("/api/assets/zones")
def list_asset_zones(
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    tenant_slug = identity["tenant"]

    assets = db.query(Asset).filter(Asset.tenant_slug == tenant_slug).all()

    zones = {}

    for asset in assets:
        if asset.network_zone not in zones:
            zones[asset.network_zone] = {
                "zone": asset.network_zone,
                "assets_count": 0,
                "critical_assets": 0,
                "public_assets": 0,
            }

        zones[asset.network_zone]["assets_count"] += 1

        if asset.business_criticality >= 5:
            zones[asset.network_zone]["critical_assets"] += 1

        if asset.exposure_level == "public":
            zones[asset.network_zone]["public_assets"] += 1

    return list(zones.values())


@app.get("/api/assets/{asset_id}", response_model=AssetResponse)
def get_asset(
        asset_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(get_current_identity),
):
    tenant_slug = identity["tenant"]

    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .filter(Asset.tenant_slug == tenant_slug)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    return asset


@app.post("/api/assets", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(
        payload: AssetCreateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_asset_write_permission),
):
    asset = Asset(
        tenant_slug=identity["tenant"],
        name=payload.name,
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        asset_type=payload.asset_type,
        os_type=payload.os_type,
        environment=payload.environment,
        network_zone=payload.network_zone,
        business_owner=payload.business_owner,
        technical_owner=payload.technical_owner,
        business_criticality=payload.business_criticality,
        exposure_level=payload.exposure_level,
        tags=payload.tags,
        description=payload.description,
        status="active",
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return asset


@app.put("/api/assets/{asset_id}", response_model=AssetResponse)
def update_asset(
        asset_id: int,
        payload: AssetUpdateRequest,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_asset_write_permission),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .filter(Asset.tenant_slug == identity["tenant"])
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    update_data = payload.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(asset, field, value)

    asset.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(asset)

    return asset


@app.delete("/api/assets/{asset_id}")
def delete_asset(
        asset_id: int,
        db: Session = Depends(get_db),
        identity: dict = Depends(require_asset_delete_permission),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .filter(Asset.tenant_slug == identity["tenant"])
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    db.delete(asset)
    db.commit()

    return {
        "message": "Asset deleted successfully",
        "asset_id": asset_id,
    }