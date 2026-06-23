from datetime import datetime, timezone

from fastapi import FastAPI

app = FastAPI(
    title="CyValidator API Gateway",
    description="Central API Gateway for CyValidator",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "platform": "CyValidator",
        "service": "api-gateway",
        "message": "Enterprise Exposure, Drift and Remediation Validation Platform",
    }


@app.get("/health")
def health_check():
    return {
        "service": "api-gateway",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/platform/info")
def platform_info():
    return {
        "name": "CyValidator",
        "description": "Startup-style cybersecurity platform for exposure validation, configuration drift detection and remediation management",
        "development_platform": "Windows",
        "target_deployment_platform": "Ubuntu Server",
        "runtime": "Docker Compose",
        "version": "0.1.0",
        "modules": [
            "API Gateway",
            "Frontend Dashboard",
            "PostgreSQL",
            "Redis",
            "Future Auth Service",
            "Future Asset Service",
            "Future Scan Orchestrator",
            "Future Risk Engine",
            "Future Validation Packs",
        ],
    }