import os
from datetime import datetime, timezone

from fastapi import FastAPI


app = FastAPI(
    title="CyValidator Lab - Logging Disabled Service",
    description="Simulated missing audit logging and monitoring coverage case for CyValidator",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "lab": "CyValidator",
        "case": os.getenv("LAB_CASE_NAME", "logging-disabled-service"),
        "description": "Simulated service with missing audit and forwarding controls.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health_check():
    return {
        "service": "logging-disabled-service",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/metadata")
def metadata():
    return {
        "case": "logging-disabled-service",
        "related_validation_pack": "Logging and Monitoring Pack",
        "risk_domain": "Detection Coverage",
        "simulated_controls": {
            "audit_logging": os.getenv("SIMULATED_AUDIT_LOGGING", "disabled"),
            "log_forwarding": os.getenv("SIMULATED_FORWARDING", "disabled"),
            "security_events": os.getenv("SIMULATED_SECURITY_EVENTS", "not_collected"),
        },
        "expected_findings": [
            {
                "control_id": "LOG-AUDIT-001",
                "title": "Privileged activity logging must be enabled",
                "severity": "Medium",
            },
            {
                "control_id": "LOG-FWD-001",
                "title": "Security logs must be forwarded to monitoring",
                "severity": "High",
            },
        ],
    }


@app.get("/audit/status")
def audit_status():
    return {
        "authentication_events": "not_collected",
        "privileged_activity": "not_collected",
        "configuration_changes": "not_collected",
        "central_forwarding": "disabled",
        "recommended_fix": "Enable audit logging and forward security-relevant events to a central monitoring platform.",
    }


@app.get("/events/demo")
def demo_events():
    return {
        "events": [],
        "note": "No events are returned because this lab case simulates disabled logging.",
    }