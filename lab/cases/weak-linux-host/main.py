import os
from datetime import datetime, timezone

from fastapi import FastAPI


app = FastAPI(
    title="CyValidator Lab - Weak Linux Host",
    description="Simulated Linux hardening lab case for CyValidator",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "lab": "CyValidator",
        "case": os.getenv("LAB_CASE_NAME", "weak-linux-host"),
        "description": "Simulated Linux host with hardening gaps.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health_check():
    return {
        "service": "weak-linux-host",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/metadata")
def metadata():
    return {
        "case": "weak-linux-host",
        "related_validation_pack": "Linux Hardening Pack",
        "risk_domain": "Host Hardening",
        "simulated_controls": {
            "ssh_root_login": os.getenv("SIMULATED_ROOT_LOGIN", "enabled"),
            "host_firewall": os.getenv("SIMULATED_FIREWALL", "disabled"),
            "audit_logging": os.getenv("SIMULATED_AUDIT_LOGGING", "partial"),
            "password_authentication": "enabled",
        },
        "expected_findings": [
            {
                "control_id": "LINUX-SSH-001",
                "title": "SSH root login must be disabled",
                "expected": "PermitRootLogin no",
                "actual": "PermitRootLogin yes",
                "severity": "High",
            },
            {
                "control_id": "LINUX-SSH-002",
                "title": "SSH password authentication should be disabled",
                "expected": "PasswordAuthentication no",
                "actual": "PasswordAuthentication yes",
                "severity": "Medium",
            },
            {
                "control_id": "LINUX-FW-001",
                "title": "Host firewall must be enabled",
                "expected": "Firewall enabled",
                "actual": "Firewall disabled",
                "severity": "High",
            },
        ],
    }


@app.get("/simulated/ssh-config")
def simulated_ssh_config():
    with open("simulated_sshd_config.txt", "r", encoding="utf-8") as file:
        content = file.read()

    return {
        "file": "simulated_sshd_config.txt",
        "note": "This is simulated configuration data. No real SSH daemon is running.",
        "content": content,
    }


@app.get("/simulated/baseline-state")
def simulated_baseline_state():
    return {
        "asset_name": "Lab Weak Linux Host",
        "hostname": "lab-linux-weak-01",
        "network_zone": "Lab DMZ",
        "baseline_state": [
            {
                "control_id": "LINUX-SSH-001",
                "desired_state": "PermitRootLogin no",
                "actual_state": "PermitRootLogin yes",
                "status": "failed",
            },
            {
                "control_id": "LINUX-FW-001",
                "desired_state": "Firewall enabled",
                "actual_state": "Firewall disabled",
                "status": "failed",
            },
            {
                "control_id": "LINUX-AUDIT-001",
                "desired_state": "Audit service enabled",
                "actual_state": "Audit service partially enabled",
                "status": "warning",
            },
        ],
    }