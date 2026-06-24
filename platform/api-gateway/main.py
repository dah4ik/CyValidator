import os
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Header, HTTPException, Request

AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://auth-service:8081")
ASSET_SERVICE_URL = os.getenv("ASSET_SERVICE_URL", "http://asset-service:8082")
FINDINGS_SERVICE_URL = os.getenv("FINDINGS_SERVICE_URL", "http://findings-service:8083")

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
        "version": "0.4.0",
        "modules": [
            "API Gateway",
            "Frontend Dashboard",
            "Auth Service",
            "Asset Service",
            "Findings Service",
            "PostgreSQL",
            "Redis",
            "Future Scan Orchestrator",
            "Future Risk Engine",
            "Future Validation Packs",
        ],
    }


async def forward_json_response(response: httpx.Response):
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", "Upstream service error")
        except ValueError:
            detail = response.text

        raise HTTPException(
            status_code=response.status_code,
            detail=detail,
        )

    return response.json()


@app.get("/api/services/health")
async def services_health():
    services = {
        "auth-service": f"{AUTH_SERVICE_URL}/health",
        "asset-service": f"{ASSET_SERVICE_URL}/health",
        "findings-service": f"{FINDINGS_SERVICE_URL}/health",
    }

    results = {}

    async with httpx.AsyncClient(timeout=5.0) as client:
        for service_name, url in services.items():
            try:
                response = await client.get(url)
                results[service_name] = {
                    "status_code": response.status_code,
                    "response": response.json(),
                }
            except httpx.HTTPError as error:
                results[service_name] = {
                    "status": "unreachable",
                    "error": str(error),
                }

    return {
        "gateway": "healthy",
        "services": results,
    }


@app.post("/api/auth/login")
async def proxy_login(request: Request):
    payload = await request.json()

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{AUTH_SERVICE_URL}/api/auth/login",
            json=payload,
        )

    return await forward_json_response(response)


@app.get("/api/auth/me")
async def proxy_me(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{AUTH_SERVICE_URL}/api/auth/me",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/auth/rbac/permissions")
async def proxy_permissions(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{AUTH_SERVICE_URL}/api/auth/rbac/permissions",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/assets")
async def proxy_list_assets(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{ASSET_SERVICE_URL}/api/assets",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/assets/summary")
async def proxy_assets_summary(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{ASSET_SERVICE_URL}/api/assets/summary",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/assets/zones")
async def proxy_asset_zones(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{ASSET_SERVICE_URL}/api/assets/zones",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/assets/{asset_id}")
async def proxy_get_asset(asset_id: int, authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{ASSET_SERVICE_URL}/api/assets/{asset_id}",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.post("/api/assets")
async def proxy_create_asset(request: Request, authorization: str = Header(...)):
    payload = await request.json()

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{ASSET_SERVICE_URL}/api/assets",
            json=payload,
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.put("/api/assets/{asset_id}")
async def proxy_update_asset(
        asset_id: int,
        request: Request,
        authorization: str = Header(...),
):
    payload = await request.json()

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.put(
            f"{ASSET_SERVICE_URL}/api/assets/{asset_id}",
            json=payload,
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.delete("/api/assets/{asset_id}")
async def proxy_delete_asset(asset_id: int, authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.delete(
            f"{ASSET_SERVICE_URL}/api/assets/{asset_id}",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/findings")
async def proxy_list_findings(
        authorization: str = Header(...),
        status_filter: str | None = None,
        severity: str | None = None,
):
    params = {}

    if status_filter:
        params["status_filter"] = status_filter

    if severity:
        params["severity"] = severity

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{FINDINGS_SERVICE_URL}/api/findings",
            headers={"Authorization": authorization},
            params=params,
        )

    return await forward_json_response(response)


@app.get("/api/findings/summary")
async def proxy_findings_summary(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{FINDINGS_SERVICE_URL}/api/findings/summary",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/findings/{finding_id}")
async def proxy_get_finding(finding_id: int, authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{FINDINGS_SERVICE_URL}/api/findings/{finding_id}",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.post("/api/findings")
async def proxy_create_finding(request: Request, authorization: str = Header(...)):
    payload = await request.json()

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{FINDINGS_SERVICE_URL}/api/findings",
            json=payload,
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.put("/api/findings/{finding_id}")
async def proxy_update_finding(
        finding_id: int,
        request: Request,
        authorization: str = Header(...),
):
    payload = await request.json()

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.put(
            f"{FINDINGS_SERVICE_URL}/api/findings/{finding_id}",
            json=payload,
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.patch("/api/findings/{finding_id}/status")
async def proxy_update_finding_status(
        finding_id: int,
        request: Request,
        authorization: str = Header(...),
):
    payload = await request.json()

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.patch(
            f"{FINDINGS_SERVICE_URL}/api/findings/{finding_id}/status",
            json=payload,
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.delete("/api/findings/{finding_id}")
async def proxy_delete_finding(finding_id: int, authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.delete(
            f"{FINDINGS_SERVICE_URL}/api/findings/{finding_id}",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)