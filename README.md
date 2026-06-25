# CyValidator

**CyValidator** is a startup-style cybersecurity platform for enterprise cyber exposure validation, configuration drift detection, attack path analysis, risk scoring and remediation prioritization.

The platform is designed to help security teams understand not only **what is misconfigured**, but also **which weaknesses create real business risk**, **which assets are most exposed**, and **which remediation actions reduce risk the most**.

---

## Product Tagline

**CyValidator — Enterprise Cyber Exposure, Drift & Remediation Validation Platform**

---

## Product Vision

Modern organizations usually have many security tools, but security teams still struggle to answer basic business-driven questions:

* Which assets are exposed?
* Which systems drifted away from the desired security baseline?
* Which weaknesses create realistic attack paths?
* Which findings should be fixed first?
* Which remediation actions reduce the most risk?
* Can the organization prove that security posture improved over time?

**CyValidator** is designed as a centralized cyber validation platform that connects asset inventory, baseline validation, findings, attack paths, risk scoring, validation packs and remediation workflows into one product-oriented system.

---

## Main Use Cases

CyValidator helps security and infrastructure teams with:

* enterprise asset visibility;
* cyber exposure validation;
* configuration drift detection;
* desired state vs actual state comparison;
* validation pack management;
* scan orchestration;
* security findings management;
* attack path analysis;
* remediation prioritization;
* executive and technical risk reporting;
* controlled lab-based validation.

---

## Key Capabilities

### Asset Inventory

CyValidator stores enterprise assets with business context:

* asset name;
* hostname;
* IP address;
* asset type;
* operating system;
* environment;
* network zone;
* business owner;
* technical owner;
* business criticality;
* exposure level;
* tags;
* description.

---

### Authentication and RBAC

The platform includes a dedicated authentication service with:

* tenants;
* users;
* roles;
* JWT authentication;
* demo admin user;
* role-based access control foundation.

Demo credentials:

```text
Email: admin@cyvalidator.local
Password: Admin123!
```

---

### Findings Management

CyValidator manages security findings with:

* affected asset;
* severity;
* risk score;
* evidence;
* technical details;
* business impact;
* remediation guidance;
* owner;
* SLA;
* status lifecycle;
* validation pack reference;
* MITRE technique reference.

---

### Risk Engine

The Risk Engine calculates:

* security score;
* enterprise risk score;
* risky assets;
* top remediation priorities;
* remediation ROI;
* status-based risk reduction;
* average enterprise risk.

Risk is calculated using a combination of:

* finding severity;
* original risk score;
* asset business criticality;
* asset exposure level;
* finding status.

---

### Baseline Engine

The Baseline Engine provides desired state vs actual state validation.

It supports:

* baseline controls;
* desired state;
* actual state;
* pass/fail/warning status;
* control severity;
* compliance score;
* failed controls;
* category-based compliance breakdown;
* recommendations.

This module is inspired by enterprise configuration governance and drift detection concepts.

---

### Attack Graph Engine

The Attack Graph Engine provides Pentera-style attack path simulation.

It supports:

* attack paths;
* graph nodes;
* graph edges;
* entry points;
* critical target assets;
* path severity;
* path risk score;
* business impact;
* technical reasoning;
* break-point recommendations;
* estimated risk reduction.

This helps identify which control fixes can disrupt the most dangerous paths.

---

### Scan Orchestrator

The Scan Orchestrator manages validation run lifecycle.

It supports:

* scan runs;
* manual scan execution;
* scan status lifecycle;
* scan progress;
* validation pack execution simulation;
* execution logs;
* scan result summary;
* scan events.

---

### Validation Pack Registry

CyValidator includes a marketplace-style validation pack registry.

It stores:

* pack metadata;
* pack category;
* pack version;
* pack maturity;
* pack status;
* target platform;
* risk domain;
* checks catalog;
* expected result;
* control ID;
* framework reference;
* recommendation.

Current validation packs:

* Linux Hardening Pack;
* Docker Security Pack;
* Database Exposure Pack;
* Web API Security Pack;
* Network Segmentation Pack;
* IAM Risk Pack;
* Data Protection Pack.

---

### Lab Environment

CyValidator includes an isolated local demo lab for controlled validation scenarios.

The lab simulates:

* weak Linux host;
* exposed PostgreSQL database;
* vulnerable API;
* privileged container risk;
* disabled logging;
* sensitive data store protection gaps.

The lab is designed for defensive local testing only.

---

## Architecture

Current architecture:

```text
Browser
   |
   v
Frontend Dashboard
   |
   v
API Gateway
   |
   +--> Auth Service
   +--> Asset Service
   +--> Findings Service
   +--> Risk Engine
   +--> Baseline Engine
   +--> Attack Graph Engine
   +--> Scan Orchestrator
   +--> Validation Pack Registry
   |
   +--> PostgreSQL
   +--> Redis
```

---

## Repository Structure

```text
CyValidator/
├── docker-compose.yml
├── README.md
├── .env.example
├── .gitignore
├── .gitattributes
│
├── platform/
│   ├── api-gateway/
│   ├── auth-service/
│   ├── asset-service/
│   ├── findings-service/
│   ├── risk-engine/
│   ├── baseline-engine/
│   ├── attack-graph-engine/
│   ├── scan-orchestrator/
│   ├── validation-pack-registry/
│   └── frontend/
│
├── validation-packs/
│   ├── linux-hardening-pack/
│   ├── docker-security-pack/
│   ├── database-exposure-pack/
│   └── web-api-security-pack/
│
├── lab/
│   ├── docker-compose.lab.yml
│   ├── README.md
│   └── cases/
│       ├── weak-linux-host/
│       ├── exposed-postgres/
│       ├── vulnerable-api/
│       ├── privileged-container-sim/
│       ├── logging-disabled-service/
│       └── sensitive-data-store/
│
└── docs/
    └── architecture.md
```

---

## Development Model

This project is developed on **Windows** using:

* Docker Desktop;
* Docker Compose;
* Git;
* VS Code or WebStorm.

The final production-like deployment target will be **Ubuntu Server**.

Ubuntu deployment files will be added in a later commit.

---

## Requirements

Install:

* Docker Desktop;
* Git;
* VS Code or WebStorm.

Optional:

* Postman;
* DBeaver;
* pgAdmin.

---

## Environment Configuration

Example environment file:

```env
PROJECT_NAME=CyValidator
ENVIRONMENT=development

POSTGRES_USER=cyvalidator
POSTGRES_PASSWORD=cyvalidator
POSTGRES_DB=cyvalidator

API_GATEWAY_PORT=8080
FRONTEND_PORT=3000

JWT_SECRET=change_me_in_production
```

For local development, Docker Compose currently provides development defaults directly in `docker-compose.yml`.

---

## Run Locally

From the project root:

```bash
docker compose up --build
```

Stop the platform:

```bash
docker compose down
```

Rebuild from scratch:

```bash
docker compose down
docker compose up --build
```

---

## Services

| Service                         | URL                          |
| ------------------------------- | ---------------------------- |
| Frontend                        | http://localhost:3000        |
| API Gateway                     | http://localhost:8080        |
| API Gateway Health              | http://localhost:8080/health |
| API Gateway Docs                | http://localhost:8080/docs   |
| Auth Service                    | http://localhost:8081        |
| Auth Service Health             | http://localhost:8081/health |
| Asset Service                   | http://localhost:8082        |
| Asset Service Health            | http://localhost:8082/health |
| Findings Service                | http://localhost:8083        |
| Findings Service Health         | http://localhost:8083/health |
| Risk Engine                     | http://localhost:8084        |
| Risk Engine Health              | http://localhost:8084/health |
| Baseline Engine                 | http://localhost:8085        |
| Baseline Engine Health          | http://localhost:8085/health |
| Attack Graph Engine             | http://localhost:8086        |
| Attack Graph Engine Health      | http://localhost:8086/health |
| Scan Orchestrator               | http://localhost:8087        |
| Scan Orchestrator Health        | http://localhost:8087/health |
| Validation Pack Registry        | http://localhost:8088        |
| Validation Pack Registry Health | http://localhost:8088/health |
| PostgreSQL                      | localhost:5432               |
| Redis                           | localhost:6379               |

---

## Check Platform Health

Open:

```text
http://localhost:8080/api/services/health
```

Expected services:

```text
auth-service
asset-service
findings-service
risk-engine
baseline-engine
attack-graph-engine
scan-orchestrator
validation-pack-registry
```

---

## API Documentation

Swagger UI:

```text
http://localhost:8080/docs
```

OpenAPI JSON:

```text
http://localhost:8080/openapi.json
```

---

## Authentication

Login endpoint:

```bash
POST http://localhost:8080/api/auth/login
```

Body:

```json
{
  "email": "admin@cyvalidator.local",
  "password": "Admin123!"
}
```

The response includes an `access_token`.

Use it in protected requests:

```text
Authorization: Bearer <token>
```

Current user:

```bash
GET http://localhost:8080/api/auth/me
Authorization: Bearer <token>
```

RBAC permissions:

```bash
GET http://localhost:8080/api/auth/rbac/permissions
Authorization: Bearer <token>
```

Tenants:

```bash
GET http://localhost:8080/api/auth/tenants
Authorization: Bearer <token>
```

Roles:

```bash
GET http://localhost:8080/api/auth/roles
Authorization: Bearer <token>
```

Users:

```bash
GET http://localhost:8080/api/auth/users
Authorization: Bearer <token>
```

---

## Asset API

List assets:

```bash
GET http://localhost:8080/api/assets
Authorization: Bearer <token>
```

Asset summary:

```bash
GET http://localhost:8080/api/assets/summary
Authorization: Bearer <token>
```

Asset zones:

```bash
GET http://localhost:8080/api/assets/zones
Authorization: Bearer <token>
```

Get asset by ID:

```bash
GET http://localhost:8080/api/assets/1
Authorization: Bearer <token>
```

Create asset:

```bash
POST http://localhost:8080/api/assets
Authorization: Bearer <token>
```

Example body:

```json
{
  "name": "Linux Application Server",
  "hostname": "app-linux-01",
  "ip_address": "10.10.20.50",
  "asset_type": "server",
  "os_type": "Ubuntu Server",
  "environment": "production",
  "network_zone": "Server Zone",
  "business_owner": "Application Team",
  "technical_owner": "Infrastructure Team",
  "business_criticality": 4,
  "exposure_level": "internal",
  "tags": "linux,application,server",
  "description": "Application server used for production workloads"
}
```

---

## Findings API

List findings:

```bash
GET http://localhost:8080/api/findings
Authorization: Bearer <token>
```

Findings summary:

```bash
GET http://localhost:8080/api/findings/summary
Authorization: Bearer <token>
```

Filter by severity:

```bash
GET http://localhost:8080/api/findings?severity=Critical
Authorization: Bearer <token>
```

Filter by status:

```bash
GET http://localhost:8080/api/findings?status_filter=open
Authorization: Bearer <token>
```

Get finding by ID:

```bash
GET http://localhost:8080/api/findings/1
Authorization: Bearer <token>
```

Update finding status:

```bash
PATCH http://localhost:8080/api/findings/1/status
Authorization: Bearer <token>
```

Body:

```json
{
  "status": "in_progress"
}
```

---

## Risk API

Risk summary:

```bash
GET http://localhost:8080/api/risk/summary
Authorization: Bearer <token>
```

Security score:

```bash
GET http://localhost:8080/api/risk/security-score
Authorization: Bearer <token>
```

Top remediation priorities:

```bash
GET http://localhost:8080/api/risk/priorities
Authorization: Bearer <token>
```

Risky assets:

```bash
GET http://localhost:8080/api/risk/assets
Authorization: Bearer <token>
```

Remediation ROI:

```bash
GET http://localhost:8080/api/risk/remediation-roi
Authorization: Bearer <token>
```

---

## Baseline API

Baseline summary:

```bash
GET http://localhost:8080/api/baseline/summary
Authorization: Bearer <token>
```

List baseline controls:

```bash
GET http://localhost:8080/api/baseline/controls
Authorization: Bearer <token>
```

Failed controls:

```bash
GET http://localhost:8080/api/baseline/failed
Authorization: Bearer <token>
```

Filter by severity:

```bash
GET http://localhost:8080/api/baseline/controls?severity=Critical
Authorization: Bearer <token>
```

Filter by category:

```bash
GET http://localhost:8080/api/baseline/controls?category=Docker Security
Authorization: Bearer <token>
```

Get baseline control:

```bash
GET http://localhost:8080/api/baseline/controls/1
Authorization: Bearer <token>
```

---

## Attack Graph API

Attack graph summary:

```bash
GET http://localhost:8080/api/attack-graph/summary
Authorization: Bearer <token>
```

List attack paths:

```bash
GET http://localhost:8080/api/attack-graph/paths
Authorization: Bearer <token>
```

Critical attack paths:

```bash
GET http://localhost:8080/api/attack-graph/critical
Authorization: Bearer <token>
```

Break-point recommendations:

```bash
GET http://localhost:8080/api/attack-graph/break-points
Authorization: Bearer <token>
```

Get attack path:

```bash
GET http://localhost:8080/api/attack-graph/paths/1
Authorization: Bearer <token>
```

Update attack path status:

```bash
PATCH http://localhost:8080/api/attack-graph/paths/1/status?status_value=mitigated
Authorization: Bearer <token>
```

---

## Scan Orchestrator API

List scan runs:

```bash
GET http://localhost:8080/api/scans
Authorization: Bearer <token>
```

Scan summary:

```bash
GET http://localhost:8080/api/scans/summary
Authorization: Bearer <token>
```

Get scan run:

```bash
GET http://localhost:8080/api/scans/1
Authorization: Bearer <token>
```

Get scan events:

```bash
GET http://localhost:8080/api/scans/1/events
Authorization: Bearer <token>
```

Run validation scan:

```bash
POST http://localhost:8080/api/scans/run
Authorization: Bearer <token>
```

Example body:

```json
{
  "name": "Manual Docker Security Validation",
  "scan_type": "runtime-validation",
  "validation_pack": "Docker Security Pack",
  "target_scope": "Server Zone",
  "target_description": "Validate Docker runtime exposure and privileged container risks",
  "trigger_type": "manual"
}
```

---

## Validation Pack Registry API

List validation packs:

```bash
GET http://localhost:8080/api/validation-packs
Authorization: Bearer <token>
```

Validation pack summary:

```bash
GET http://localhost:8080/api/validation-packs/summary
Authorization: Bearer <token>
```

Validation pack categories:

```bash
GET http://localhost:8080/api/validation-packs/categories
Authorization: Bearer <token>
```

Get pack details:

```bash
GET http://localhost:8080/api/validation-packs/linux-hardening-pack
Authorization: Bearer <token>
```

Get pack checks:

```bash
GET http://localhost:8080/api/validation-packs/linux-hardening-pack/checks
Authorization: Bearer <token>
```

Update pack status:

```bash
PATCH http://localhost:8080/api/validation-packs/linux-hardening-pack/status?status_value=disabled
Authorization: Bearer <token>
```

---

## Lab Environment

CyValidator includes an isolated local lab environment.

Start the lab:

```bash
docker compose -f lab/docker-compose.lab.yml up --build
```

Stop the lab:

```bash
docker compose -f lab/docker-compose.lab.yml down
```

Lab services:

| Case                            | URL                   | Purpose                            |
| ------------------------------- | --------------------- | ---------------------------------- |
| Weak Linux Host                 | http://localhost:9101 | Simulates Linux hardening failures |
| Vulnerable API                  | http://localhost:9102 | Simulates Web API security gaps    |
| Privileged Container Simulation | http://localhost:9103 | Simulates container runtime risks  |
| Logging Disabled Service        | http://localhost:9104 | Simulates missing audit coverage   |
| Sensitive Data Store            | http://localhost:9105 | Simulates data protection gaps     |
| Exposed PostgreSQL              | 127.0.0.1:15432       | Simulates database exposure        |

Demo lab PostgreSQL:

```text
Host: 127.0.0.1
Port: 15432
Database: lab_sensitive_db
Username: lab_admin
Password: lab_password
```

Check lab metadata:

```text
http://localhost:9101/metadata
http://localhost:9102/metadata
http://localhost:9103/metadata
http://localhost:9104/metadata
http://localhost:9105/metadata
```

---

## Demo Data

CyValidator seeds demo enterprise data automatically.

Demo tenant:

```text
demo-enterprise
```

Demo user:

```text
admin@cyvalidator.local
```

Demo assets include:

* Linux Web Server;
* PostgreSQL Database;
* Docker Runtime Host;
* Corporate Workstation;
* Management Jump Server.

Demo findings include:

* SSH root login is enabled;
* Database service is exposed outside the application network;
* Privileged container execution is allowed;
* Endpoint can communicate with database zone;
* Security audit logging is incomplete.

Demo attack paths include:

* External to Database Exposure Path;
* User Zone to Container Host to Database Path;
* Public Server to Management Zone Path.

---

## Current Commit Scope

The project currently includes:

* API Gateway;
* frontend dashboard placeholder;
* PostgreSQL;
* Redis;
* Auth Service;
* Asset Service;
* Findings Service;
* Risk Engine;
* Baseline Engine;
* Attack Graph Engine;
* Scan Orchestrator;
* Validation Pack Registry;
* isolated lab environment.

---

## Commit History Plan

### Commit #1

```text
Initialize CyValidator development foundation
```

Created:

* Docker Compose platform;
* API Gateway;
* frontend placeholder;
* PostgreSQL;
* Redis;
* project structure;
* initial documentation.

### Commit #2

```text
Add authentication service with tenants roles and JWT login
```

Created:

* Auth Service;
* tenants;
* users;
* roles;
* JWT login;
* RBAC skeleton.

### Commit #3

```text
Add asset inventory service with zones owners and criticality
```

Created:

* Asset Service;
* asset inventory;
* business criticality;
* network zones;
* exposure level;
* demo assets.

### Commit #4

```text
Add findings service with severity risk evidence and remediation fields
```

Created:

* Findings Service;
* finding lifecycle;
* evidence;
* remediation;
* SLA;
* demo findings.

### Commit #5

```text
Add risk engine with enterprise scoring and remediation priority
```

Created:

* Risk Engine;
* security score;
* enterprise risk score;
* top risky assets;
* remediation priorities;
* remediation ROI.

### Commit #6

```text
Add baseline engine with desired vs actual control validation
```

Created:

* Baseline Engine;
* desired vs actual validation;
* compliance score;
* failed controls;
* demo baseline controls.

### Commit #7

```text
Add attack graph engine with attack paths and break-point recommendations
```

Created:

* Attack Graph Engine;
* attack paths;
* graph nodes and edges;
* break-point recommendations;
* estimated risk reduction.

### Commit #8

```text
Add scan orchestrator with validation run lifecycle
```

Created:

* Scan Orchestrator;
* scan runs;
* scan events;
* manual scan execution;
* simulated validation pack execution.

### Commit #9

```text
Add validation pack registry and pack metadata
```

Created:

* Validation Pack Registry;
* pack metadata;
* check catalog;
* pack categories;
* pack maturity;
* pack status lifecycle.

### Commit #10

```text
Add lab environment with isolated security cases
```

Created:

* isolated demo lab;
* weak Linux host simulation;
* exposed PostgreSQL lab;
* vulnerable API simulation;
* privileged container simulation;
* logging-disabled simulation;
* sensitive data store simulation.

---

## Product Roadmap

Planned next modules:

* Remediation Workflow Service;
* Notification Service;
* Report Service;
* Audit Service;
* React frontend dashboard;
* protected frontend routes;
* attack graph visualization;
* remediation board;
* Postman collection;
* production Docker Compose;
* Ubuntu Server deployment package;
* security hardening;
* final screenshots and project documentation.

---

## Future Ubuntu Deployment

At a later stage, the project will include:

* Ubuntu Server installation guide;
* Docker installation script;
* production Docker Compose file;
* production `.env` example;
* systemd service example;
* backup script;
* restore script;
* deployment hardening checklist.

---

## Security Notice

CyValidator is designed for defensive cybersecurity validation, learning, architecture demonstration and controlled lab environments.

Do not use this project against systems you do not own or do not have explicit permission to test.

The lab environment is intentionally isolated and uses simulated risky states instead of enabling truly dangerous runtime configurations.

---

## Disclaimer

This project is a portfolio and product-style cybersecurity platform prototype.

It is not a finished commercial product.

Before using any part of this project in a real environment, review security controls, secrets management, authentication, authorization, logging, network exposure and deployment hardening.

---

## License

This project is currently provided for educational, defensive security and portfolio purposes.

A formal license can be added later.
