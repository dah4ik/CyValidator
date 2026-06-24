import os
from datetime import datetime, timezone

from fastapi import FastAPI


app = FastAPI(
    title="CyValidator Lab - Privileged Container Simulation",
    description="Simulated container runtime risk metadata for CyValidator",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "lab": "CyValidator",
        "case": os.getenv("LAB_CASE_NAME", "privileged-container-sim"),
        "description": "Simulated privileged container runtime risk case.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health_check():
    return {
        "service": "privileged-container-sim",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/metadata")
def metadata():
    return {
        "case": "privileged-container-sim",
        "related_validation_pack": "Docker Security Pack",
        "risk_domain": "Container Runtime",
        "note": "This service simulates risky runtime metadata without actually running as a privileged container.",
        "simulated_controls": {
            "privileged_mode": os.getenv("SIMULATED_PRIVILEGED_MODE", "enabled"),
            "root_user": os.getenv("SIMULATED_ROOT_USER", "enabled"),
            "docker_socket_mount": os.getenv("SIMULATED_DOCKER_SOCKET_MOUNT", "detected"),
            "dangerous_capabilities": "simulated",
        },
        "expected_findings": [
            {
                "control_id": "DOCKER-RUNTIME-001",
                "title": "Privileged containers must be disabled",
                "severity": "Critical",
            },
            {
                "control_id": "DOCKER-USER-001",
                "title": "Containers should not run as root",
                "severity": "Medium",
            },
            {
                "control_id": "DOCKER-MOUNT-001",
                "title": "Docker socket must not be mounted into containers",
                "severity": "Critical",
            },
        ],
    }


@app.get("/runtime/metadata")
def runtime_metadata():
    return {
        "container_name": "cyvalidator-lab-privileged-container-sim",
        "simulated_user": "root",
        "simulated_privileged": True,
        "simulated_mounts": [
            "/var/run/docker.sock:/var/run/docker.sock",
            "/:/host",
        ],
        "simulated_capabilities": [
            "SYS_ADMIN",
            "NET_ADMIN",
        ],
        "safe_mode": True,
        "explanation": "The container does not actually receive privileged Docker settings. This is simulated metadata for validation testing.",
    }


@app.get("/runtime/recommendation")
def runtime_recommendation():
    return {
        "recommended_actions": [
            "Do not run containers with privileged mode.",
            "Do not mount the Docker socket into application containers.",
            "Run containers as non-root users.",
            "Drop unnecessary Linux capabilities.",
            "Use read-only filesystem where possible.",
        ]
    }