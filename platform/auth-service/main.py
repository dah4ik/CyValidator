import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://cyvalidator:cyvalidator@postgres:5432/cyvalidator",
)

JWT_SECRET = os.getenv("JWT_SECRET", "change_me_in_production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), unique=True, nullable=False)
    slug = Column(String(120), unique=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    users = relationship("User", back_populates="tenant")


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255), nullable=True)

    users = relationship("User", back_populates="role")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)

    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(150), nullable=False)
    hashed_password = Column(String(255), nullable=False)

    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login_at = Column(DateTime, nullable=True)

    tenant = relationship("Tenant", back_populates="users")
    role = relationship("Role", back_populates="users")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user: dict


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    tenant: str
    role: str
    is_active: bool
    is_superuser: bool


class TenantResponse(BaseModel):
    id: int
    name: str
    slug: str


class RoleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None


app = FastAPI(
    title="CyValidator Auth Service",
    description="Authentication, tenants, users, roles and RBAC foundation for CyValidator",
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


def hash_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_context.verify(plain_password, hashed_password)


def create_access_token(user: User) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(user.id),
        "email": user.email,
        "tenant": user.tenant.slug,
        "role": user.role.name,
        "is_superuser": user.is_superuser,
        "exp": expires_at,
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


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


def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: Session = Depends(get_db),
) -> User:
    payload = decode_access_token(credentials.credentials)
    user_id = int(payload.get("sub"))

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is disabled",
        )

    return user


def require_admin_user(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role.name not in ["Platform Admin", "Security Manager"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    return current_user


def seed_initial_data(db: Session) -> None:
    existing_tenant = db.query(Tenant).filter(Tenant.slug == "demo-enterprise").first()

    if not existing_tenant:
        tenant = Tenant(
            name="Demo Enterprise",
            slug="demo-enterprise",
        )
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
    else:
        tenant = existing_tenant

    default_roles = [
        {
            "name": "Platform Admin",
            "description": "Full platform administration permissions",
        },
        {
            "name": "Security Manager",
            "description": "Can manage findings, risk and remediation workflows",
        },
        {
            "name": "Security Analyst",
            "description": "Can view assets, run validations and review findings",
        },
        {
            "name": "IT Owner",
            "description": "Can view assigned remediation items",
        },
        {
            "name": "Read Only Auditor",
            "description": "Read-only access for audit and compliance review",
        },
    ]

    for role_data in default_roles:
        role = db.query(Role).filter(Role.name == role_data["name"]).first()
        if not role:
            db.add(Role(**role_data))

    db.commit()

    admin_role = db.query(Role).filter(Role.name == "Platform Admin").first()

    admin_user = db.query(User).filter(User.email == "admin@cyvalidator.local").first()

    if not admin_user:
        admin_user = User(
            tenant_id=tenant.id,
            role_id=admin_role.id,
            email="admin@cyvalidator.local",
            full_name="CyValidator Admin",
            hashed_password=hash_password("Admin123!"),
            is_active=True,
            is_superuser=True,
        )
        db.add(admin_user)
        db.commit()


@app.on_event("startup")
def on_startup():
    wait_for_database()
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed_initial_data(db)
    finally:
        db.close()


@app.get("/health")
def health_check():
    return {
        "service": "auth-service",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/info")
def service_info():
    return {
        "name": "CyValidator Auth Service",
        "role": "Manages tenants, users, roles, JWT authentication and RBAC foundation",
        "version": "0.1.0",
        "demo_user": "admin@cyvalidator.local",
    }


@app.post("/api/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is disabled",
        )

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)

    access_token = create_access_token(user)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in_minutes": ACCESS_TOKEN_EXPIRE_MINUTES,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "tenant": user.tenant.slug,
            "role": user.role.name,
            "is_superuser": user.is_superuser,
        },
    }


@app.get("/api/auth/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "tenant": current_user.tenant.slug,
        "role": current_user.role.name,
        "is_active": current_user.is_active,
        "is_superuser": current_user.is_superuser,
    }


@app.get("/api/auth/tenants", response_model=list[TenantResponse])
def list_tenants(
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin_user),
):
    tenants = db.query(Tenant).order_by(Tenant.id).all()

    return [
        {
            "id": tenant.id,
            "name": tenant.name,
            "slug": tenant.slug,
        }
        for tenant in tenants
    ]


@app.get("/api/auth/roles", response_model=list[RoleResponse])
def list_roles(
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin_user),
):
    roles = db.query(Role).order_by(Role.id).all()

    return [
        {
            "id": role.id,
            "name": role.name,
            "description": role.description,
        }
        for role in roles
    ]


@app.get("/api/auth/users", response_model=list[UserResponse])
def list_users(
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin_user),
):
    users = db.query(User).order_by(User.id).all()

    return [
        {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "tenant": user.tenant.slug,
            "role": user.role.name,
            "is_active": user.is_active,
            "is_superuser": user.is_superuser,
        }
        for user in users
    ]


@app.get("/api/auth/rbac/permissions")
def rbac_permissions(current_user: User = Depends(get_current_user)):
    role_permissions = {
        "Platform Admin": [
            "platform:admin",
            "tenants:read",
            "users:read",
            "assets:manage",
            "scans:run",
            "findings:manage",
            "remediation:manage",
            "reports:generate",
        ],
        "Security Manager": [
            "assets:read",
            "scans:run",
            "findings:manage",
            "remediation:manage",
            "reports:generate",
        ],
        "Security Analyst": [
            "assets:read",
            "scans:run",
            "findings:read",
            "reports:read",
        ],
        "IT Owner": [
            "findings:read",
            "remediation:update",
        ],
        "Read Only Auditor": [
            "assets:read",
            "findings:read",
            "reports:read",
            "audit:read",
        ],
    }

    return {
        "user": current_user.email,
        "role": current_user.role.name,
        "permissions": role_permissions.get(current_user.role.name, []),
    }