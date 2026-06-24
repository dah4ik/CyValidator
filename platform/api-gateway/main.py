import os
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Header, HTTPException, Request

AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://auth-service:8081")
ASSET_SERVICE_URL = os.getenv("ASSET_SERVICE_URL", "http://asset-service:8082")
FINDINGS_SERVICE_URL = os.getenv("FINDINGS_SERVICE_URL", "http://findings-service:8083")
RISK_ENGINE_URL = os.getenv("RISK_ENGINE_URL", "http://risk-engine:8084")
BASELINE_ENGINE_URL = os.getenv("BASELINE_ENGINE_URL", "http://baseline-engine:8085")
ATTACK_GRAPH_ENGINE_URL = os.getenv(
    "ATTACK_GRAPH_ENGINE_URL",
    "http://attack-graph-engine:8086",
)

app = FastAPI(
    title="CyValidator API Gateway",
    description="Central API Gateway for CyValidator",
    version="0.7.0",
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
        "version": "0.7.0",
        "modules": [
            "API Gateway",
            "Frontend Dashboard",
            "Auth Service",
            "Asset Service",
            "Findings Service",
            "Risk Engine",
            "Baseline Engine",
            "Attack Graph Engine",
            "PostgreSQL",
            "Redis",
            "Future Scan Orchestrator",
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

    try:
        return response.json()
    except ValueError:
        return {
            "status_code": response.status_code,
            "body": response.text,
        }


@app.get("/api/services/health")
async def services_health():
    services = {
        "auth-service": f"{AUTH_SERVICE_URL}/health",
        "asset-service": f"{ASSET_SERVICE_URL}/health",
        "findings-service": f"{FINDINGS_SERVICE_URL}/health",
        "risk-engine": f"{RISK_ENGINE_URL}/health",
        "baseline-engine": f"{BASELINE_ENGINE_URL}/health",
        "attack-graph-engine": f"{ATTACK_GRAPH_ENGINE_URL}/health",
    }

    results = {}

    async with httpx.AsyncClient(timeout=5.0) as client:
        for service_name, url in services.items():
            try:
                response = await client.get(url)
                results[service_name] = {
                    "status": "reachable",
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


# ============================================================
# Auth Service Proxy
# ============================================================

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


@app.get("/api/auth/tenants")
async def proxy_list_tenants(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{AUTH_SERVICE_URL}/api/auth/tenants",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/auth/roles")
async def proxy_list_roles(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{AUTH_SERVICE_URL}/api/auth/roles",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/auth/users")
async def proxy_list_users(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{AUTH_SERVICE_URL}/api/auth/users",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


# ============================================================
# Asset Service Proxy
# ============================================================

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


# ============================================================
# Findings Service Proxy
# ============================================================

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


# ============================================================
# Risk Engine Proxy
# ============================================================

@app.get("/api/risk/summary")
async def proxy_risk_summary(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{RISK_ENGINE_URL}/api/risk/summary",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/risk/security-score")
async def proxy_security_score(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{RISK_ENGINE_URL}/api/risk/security-score",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/risk/priorities")
async def proxy_risk_priorities(
        authorization: str = Header(...),
        limit: int = 5,
):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{RISK_ENGINE_URL}/api/risk/priorities",
            headers={"Authorization": authorization},
            params={"limit": limit},
        )

    return await forward_json_response(response)


@app.get("/api/risk/assets")
async def proxy_risky_assets(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{RISK_ENGINE_URL}/api/risk/assets",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/risk/remediation-roi")
async def proxy_remediation_roi(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{RISK_ENGINE_URL}/api/risk/remediation-roi",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


# ============================================================
# Baseline Engine Proxy
# ============================================================

@app.get("/api/baseline/summary")
async def proxy_baseline_summary(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{BASELINE_ENGINE_URL}/api/baseline/summary",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/baseline/controls")
async def proxy_baseline_controls(
        authorization: str = Header(...),
        status_filter: str | None = None,
        severity: str | None = None,
        category: str | None = None,
):
    params = {}

    if status_filter:
        params["status_filter"] = status_filter

    if severity:
        params["severity"] = severity

    if category:
        params["category"] = category

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{BASELINE_ENGINE_URL}/api/baseline/controls",
            headers={"Authorization": authorization},
            params=params,
        )

    return await forward_json_response(response)


@app.get("/api/baseline/failed")
async def proxy_failed_baseline_controls(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{BASELINE_ENGINE_URL}/api/baseline/failed",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/baseline/controls/{control_id}")
async def proxy_get_baseline_control(
        control_id: int,
        authorization: str = Header(...),
):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{BASELINE_ENGINE_URL}/api/baseline/controls/{control_id}",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.post("/api/baseline/controls")
async def proxy_create_baseline_control(
        request: Request,
        authorization: str = Header(...),
):
    payload = await request.json()

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{BASELINE_ENGINE_URL}/api/baseline/controls",
            json=payload,
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.put("/api/baseline/controls/{control_id}")
async def proxy_update_baseline_control(
        control_id: int,
        request: Request,
        authorization: str = Header(...),
):
    payload = await request.json()

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.put(
            f"{BASELINE_ENGINE_URL}/api/baseline/controls/{control_id}",
            json=payload,
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.delete("/api/baseline/controls/{control_id}")
async def proxy_delete_baseline_control(
        control_id: int,
        authorization: str = Header(...),
):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.delete(
            f"{BASELINE_ENGINE_URL}/api/baseline/controls/{control_id}",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


# ============================================================
# Attack Graph Engine Proxy
# ============================================================

@app.get("/api/attack-graph/summary")
async def proxy_attack_graph_summary(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{ATTACK_GRAPH_ENGINE_URL}/api/attack-graph/summary",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/attack-graph/paths")
async def proxy_attack_graph_paths(
        authorization: str = Header(...),
        severity: str | None = None,
        status_filter: str | None = None,
):
    params = {}

    if severity:
        params["severity"] = severity

    if status_filter:
        params["status_filter"] = status_filter

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{ATTACK_GRAPH_ENGINE_URL}/api/attack-graph/paths",
            headers={"Authorization": authorization},
            params=params,
        )

    return await forward_json_response(response)


@app.get("/api/attack-graph/critical")
async def proxy_critical_attack_paths(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{ATTACK_GRAPH_ENGINE_URL}/api/attack-graph/critical",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/attack-graph/break-points")
async def proxy_attack_graph_break_points(authorization: str = Header(...)):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{ATTACK_GRAPH_ENGINE_URL}/api/attack-graph/break-points",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.get("/api/attack-graph/paths/{path_id}")
async def proxy_get_attack_path(
        path_id: int,
        authorization: str = Header(...),
):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{ATTACK_GRAPH_ENGINE_URL}/api/attack-graph/paths/{path_id}",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.post("/api/attack-graph/paths")
async def proxy_create_attack_path(
        request: Request,
        authorization: str = Header(...),
):
    payload = await request.json()

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{ATTACK_GRAPH_ENGINE_URL}/api/attack-graph/paths",
            json=payload,
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.put("/api/attack-graph/paths/{path_id}")
async def proxy_update_attack_path(
        path_id: int,
        request: Request,
        authorization: str = Header(...),
):
    payload = await request.json()

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.put(
            f"{ATTACK_GRAPH_ENGINE_URL}/api/attack-graph/paths/{path_id}",
            json=payload,
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)


@app.patch("/api/attack-graph/paths/{path_id}/status")
async def proxy_update_attack_path_status(
        path_id: int,
        status_value: str,
        authorization: str = Header(...),
):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.patch(
            f"{ATTACK_GRAPH_ENGINE_URL}/api/attack-graph/paths/{path_id}/status",
            headers={"Authorization": authorization},
            params={"status_value": status_value},
        )

    return await forward_json_response(response)


@app.delete("/api/attack-graph/paths/{path_id}")
async def proxy_delete_attack_path(
        path_id: int,
        authorization: str = Header(...),
):
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.delete(
            f"{ATTACK_GRAPH_ENGINE_URL}/api/attack-graph/paths/{path_id}",
            headers={"Authorization": authorization},
        )

    return await forward_json_response(response)