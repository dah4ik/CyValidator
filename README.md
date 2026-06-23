# CyValidator

CyValidator is a startup-style cybersecurity platform for exposure validation, configuration drift detection, attack path analysis and remediation management.

## Product Vision

Modern security teams often struggle to understand which technical weaknesses create real business risk.

CyValidator is designed to help security teams:

- identify exposed assets;
- validate security controls;
- detect configuration drift;
- prioritize remediation;
- simulate attack paths;
- prove risk reduction.

## Development Model

This project is developed on Windows using Docker Desktop.

The final deployment model will be prepared for Ubuntu Server.

## Current Commit Scope

Commit #1 creates the base development foundation:

- Docker Compose platform;
- API Gateway;
- frontend dashboard placeholder;
- PostgreSQL;
- Redis;
- project documentation;
- future validation pack structure.

## Services

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| API Gateway | http://localhost:8080 |
| API Gateway Health | http://localhost:8080/health |
| API Docs | http://localhost:8080/docs |
| PostgreSQL | localhost:5432 |
| Redis | localhost:6379 |

## Run Locally on Windows

Requirements:

- Docker Desktop
- Git
- VS Code or WebStorm

Start platform:

```bash
docker compose up --build