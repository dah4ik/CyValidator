import os
from datetime import datetime, timezone

from fastapi import FastAPI


app = FastAPI(
    title="CyValidator Lab - Sensitive Data Store",
    description="Simulated sensitive data protection lab case for CyValidator",
    version="0.1.0",
)


DEMO_RECORDS = [
    {
        "record_id": "DEMO-001",
        "classification": "sensitive-demo",
        "owner": "Finance Demo Team",
        "content": "Fake demo financial record for validation only.",
    },
    {
        "record_id": "DEMO-002",
        "classification": "sensitive-demo",
        "owner": "HR Demo Team",
        "content": "Fake demo HR record for validation only.",
    },
    {
        "record_id": "DEMO-003",
        "classification": "internal-demo",
        "owner": "Operations Demo Team",
        "content": "Fake demo operational record for validation only.",
    },
]


@app.get("/")
def root():
    return {
        "lab": "CyValidator",
        "case": os.getenv("LAB_CASE_NAME", "sensitive-data-store"),
        "description": "Simulated sensitive data store with protection gaps.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health_check():
    return {
        "service": "sensitive-data-store",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/metadata")
def metadata():
    return {
        "case": "sensitive-data-store",
        "related_validation_pack": "Data Protection Pack",
        "risk_domain": "Sensitive Data",
        "simulated_controls": {
            "encryption_at_rest": os.getenv("SIMULATED_ENCRYPTION_AT_REST", "disabled"),
            "backup_exposure": os.getenv("SIMULATED_BACKUP_EXPOSURE", "user_zone_accessible"),
            "data_classification": os.getenv("SIMULATED_DATA_CLASSIFICATION", "sensitive_demo_data"),
        },
        "expected_findings": [
            {
                "control_id": "DATA-ENC-001",
                "title": "Sensitive data must be encrypted at rest",
                "severity": "Critical",
            },
            {
                "control_id": "DATA-BACKUP-001",
                "title": "Backup systems must not be exposed to user networks",
                "severity": "High",
            },
        ],
    }


@app.get("/records")
def list_demo_records():
    return {
        "warning": "This endpoint returns fake demo data only.",
        "records": DEMO_RECORDS,
    }


@app.get("/protection/status")
def protection_status():
    return {
        "encryption_at_rest": "disabled",
        "backup_network_isolation": "not_enforced",
        "data_classification": "partial",
        "access_review": "not_recent",
        "recommended_actions": [
            "Enable encryption at rest.",
            "Restrict backup access to approved administrative paths.",
            "Classify sensitive data stores.",
            "Review access permissions periodically.",
        ],
    }