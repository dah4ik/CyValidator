import os
from datetime import datetime, timezone

from fastapi import FastAPI, Response


app = FastAPI(
    title="CyValidator Lab - Vulnerable API Simulation",
    description="Simulated web API control gaps for CyValidator",
    version="0.1.0",
)


@app.get("/")
def root(response: Response):
    response.headers["X-CyValidator-Lab"] = "vulnerable-api"

    return {
        "lab": "CyValidator",
        "case": os.getenv("LAB_CASE_NAME", "vulnerable-api"),
        "description": "Simulated API with missing defensive controls.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health_check():
    return {
        "service": "vulnerable-api",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/metadata")
def metadata():
    return {
        "case": "vulnerable-api",
        "related_validation_pack": "Web API Security Pack",
        "risk_domain": "Application Exposure",
        "simulated_controls": {
            "security_headers": os.getenv("DEMO_SECURITY_HEADERS", "missing"),
            "rate_limiting": os.getenv("DEMO_RATE_LIMITING", "disabled"),
            "admin_endpoint": os.getenv("DEMO_ADMIN_ENDPOINT", "exposed"),
            "verbose_errors": "enabled",
        },
        "expected_findings": [
            {
                "control_id": "API-HEADERS-001",
                "title": "Security headers must be present",
                "severity": "Medium",
            },
            {
                "control_id": "API-RATE-001",
                "title": "Rate limiting should be enabled",
                "severity": "High",
            },
            {
                "control_id": "API-ERROR-001",
                "title": "Verbose errors must not expose internals",
                "severity": "Medium",
            },
        ],
    }


@app.get("/admin")
def simulated_public_admin():
    return {
        "warning": "This is a simulated exposed admin endpoint for lab validation only.",
        "admin_panel": "demo-visible",
        "authentication": "not_enforced_in_simulation",
        "recommended_fix": "Require authentication, authorization and audit logging for administrative endpoints.",
    }


@app.get("/api/users/{user_id}")
def get_demo_user(user_id: int):
    return {
        "user_id": user_id,
        "username": f"demo-user-{user_id}",
        "role": "demo",
        "note": "This is fake demo data for lab validation only.",
    }


@app.get("/debug/error")
def simulated_verbose_error():
    return {
        "error": "SimulatedVerboseError",
        "stack_trace": [
            "File '/app/main.py', line 100, in simulated_verbose_error",
            "raise SimulatedVerboseError('demo')",
        ],
        "internal_service": "lab-vulnerable-api",
        "recommended_fix": "Return generic errors to clients and keep technical details in server logs only.",
    }


@app.get("/api/security-posture")
def api_security_posture():
    return {
        "security_headers": {
            "Strict-Transport-Security": "missing",
            "Content-Security-Policy": "missing",
            "X-Content-Type-Options": "missing",
        },
        "rate_limiting": "disabled",
        "admin_endpoint_public": True,
        "verbose_errors": True,
    }