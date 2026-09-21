# AI-GRC Platform

An automated Governance, Risk Management, and Compliance (GRC) platform integrating network discovery, vulnerability scanning, CVE enrichment via the NVD REST API, asset intelligence, inherent and residual risk modeling, security controls catalog, and compliance framework mapping.

> **Roadmap & Disclaimer**: AI/LLM-assisted analysis is planned for a future phase. Phase 3 establishes the compliance mapping layer. This platform is an internal GRC tracking and assessment tool; metrics such as "Implementation Coverage" reflect internal progress against supported requirements and do not constitute formal compliance certification or legal assurance.

---

## Architecture Overview

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                   React 19 Dashboard (Vite Frontend)                     │
│  - Asset Inventory & Intelligence Editor (Criticality, Exposure, Owner)  │
│  - GRC Risk Register (Inherent vs. Residual Risk, Ownership, Treatment)  │
│  - Security Controls Catalog & Mitigation Assignments                    │
│  - Compliance Mapping (NIST CSF 2.0 & ISO/IEC 27001:2022)                │
│  - Vulnerability Findings & CVE Correlation                              │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │ REST API (JSON)
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          FastAPI Backend Service                         │
│  - Asset Intelligence Management & Dynamic Recalculation                 │
│  - GRC Risk Calculation Engine (scanner/grc_engine.py)                    │
│  - Security Controls Catalog & Association Management                    │
│  - Compliance Mapping Engine & Implementation Coverage Calculator        │
│  - Technical Scanner Pipeline (Nmap, CVE/NVD, Heuristics)                 │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
┌──────────────────────────────────────────┐ ┌─────────────────────────────┐
│           PostgreSQL Database            │ │      Scanner Pipeline       │
│  - assets (with GRC Intel)               │ │  - Nmap Scanner (-sV -O)    │
│  - risks (Inherent/Residual)             │ │  - CVE Lookup (NVD API 2.0) │
│  - controls (Catalog)                    │ │  - Vulnerability Scanner    │
│  - risk_controls (M2M)                   │ │  - GRC Risk Engine          │
│  - compliance_frameworks                 │ │                             │
│  - compliance_requirements               │ │                             │
│  - control_compliance_mappings           │ │                             │
│  - vulnerabilities                       │ │                             │
└──────────────────────────────────────────┘ └─────────────────────────────┘
```

---

## The Governance Chain

The platform establishes an end-to-end trace from physical infrastructure up to regulatory standards:

$$\text{Asset} \longrightarrow \text{Vulnerability} \longrightarrow \text{Risk} \longrightarrow \text{Security Control} \longrightarrow \text{Compliance Requirement} \longrightarrow \text{Framework}$$

1. **Asset**: Monitored host with operational context (Criticality, Environment, Exposure, Owner, Function).
2. **Vulnerability**: Port finding enriched with CVE IDs and CVSS scores.
3. **Risk**: Inherent Risk ($L \times I$) and Residual Risk calculated after applying controls.
4. **Security Control**: Defensive safeguard (Preventive, Detective, Corrective) reducing likelihood.
5. **Compliance Requirement**: Standard subcategory or control clause from an authoritative framework.
6. **Framework**: Authoritative baseline (NIST CSF 2.0 or ISO/IEC 27001:2022).

---

## Supported Compliance Frameworks (Phase 3)

The platform supports two major cybersecurity frameworks, seeded as a **reviewed prototype subset / supported requirements catalogue**:

### 1. NIST Cybersecurity Framework (CSF) 2.0
- **Version**: 2.0 (Official February 2024 revision)
- **Functions Supported**:
  - **Govern (GV)**: `GV.OC-01`, `GV.RM-01`
  - **Identify (ID)**: `ID.AM-01`, `ID.RA-01`
  - **Protect (PR)**: `PR.AA-01`, `PR.AA-03`, `PR.AA-05`, `PR.DS-01`, `PR.DS-02`, `PR.DS-11`, `PR.PS-01`, `PR.PS-02`, `PR.IR-01`
  - **Detect (DE)**: `DE.CM-01`, `DE.AE-03`
  - **Respond (RS)**: `RS.MA-01`, `RS.MI-01`
  - **Recover (RC)**: `RC.RP-01`

### 2. ISO/IEC 27001:2022
- **Version**: 2022 (Annex A Information Security Controls)
- **Themes Supported**:
  - **Organizational (A.5)**: `A.5.15`, `A.5.16`, `A.5.17`, `A.5.18`
  - **People (A.6)**: `A.6.3`
  - **Physical (A.7)**: `A.7.2`
  - **Technological (A.8)**: `A.8.1`, `A.8.5`, `A.8.7`, `A.8.8`, `A.8.13`, `A.8.15`, `A.8.16`, `A.8.20`, `A.8.22`, `A.8.24`

---

## Compliance Logic & Assessment

### Control-to-Requirement Mapping
- A mapping designates that a security control is relevant or supporting to a compliance requirement:
  - **Direct**: Primary technical or administrative implementation of the requirement.
  - **Supporting**: Secondary or complementary safeguard.
- **Important Rule**: Mapping a control **never** automatically marks a requirement as `Implemented`. Controls provide implementation evidence, but formal compliance status remains an independent audit assessment.

### Requirement Statuses
Each requirement carries an independently managed assessment status:
- `Not Assessed` (Default baseline)
- `Not Implemented`
- `Partially Implemented`
- `Implemented`
- `Not Applicable`

### Implementation Coverage Metric
To track internal GRC readiness without making unsubstantiated certification claims, the platform calculates **"Implementation Coverage"**:

$$\text{Implementation Coverage (\%)} = \frac{\text{Implemented} + 0.5 \times \text{Partially Implemented}}{\text{Total Requirements} - \text{Not Applicable}} \times 100$$

---

## Current Functionality

- **Single-Host Network Scan (`POST /scan?target=...`)**:
  - Scans target host via Nmap for open ports, operating system, and software versions.
  - Enriches findings with NVD CVE data and CVSS scores.
  - Registers asset intelligence and GRC risks with inherent and residual risk scores.
  - Maintains lifecycle: active findings marked `Open`, absent findings marked `Resolved`, reappearing findings reopened.
- **Network Discovery (`POST /discover?network=...`)**:
  - Discovers active private hosts (RFC 1918, max `/24`) and registers them with safe asset intelligence defaults.
- **Asset Intelligence Management (`GET /assets`, `PATCH /assets/{id}`)**:
  - View and edit asset criticality, environment, exposure, owner, and business function.
  - Modifying criticality or exposure dynamically recalculates inherent and residual risk for all associated risks.
- **Risk Register (`GET /risks`, `PATCH /risks/{id}`)**:
  - View inherent vs. residual risk, likelihood/impact breakdown, assigned controls, treatment, owner, and due date.
- **Security Controls Catalog (`GET /controls`, `POST /controls`, `PATCH /controls/{id}`, `DELETE /controls/{id}`)**:
  - Manage defensive safeguards with category, framework, effectiveness, and status.
- **Control Assignment (`POST /risks/{id}/controls/{cid}`, `DELETE /risks/{id}/controls/{cid}`)**:
  - Assign or detach controls from risks to dynamically adjust residual risk scores.
- **Compliance Mapping (`GET /compliance/frameworks`, `GET /compliance/requirements`, `GET /compliance/summary`, `PATCH /compliance/requirements/{id}`)**:
  - View frameworks and supported requirements.
  - Filter requirements by framework, status, function/theme, or category.
  - Inspect mapped security controls and mapping strength (`Direct` / `Supporting`).
  - Track Implementation Coverage metrics per framework.
  - Update requirement assessment status and audit observations.
- **Vulnerability Findings (`GET /vulnerabilities`)**:
  - Lists all technical vulnerabilities, CVE IDs, CVSS scores, confidence ratings, and status.

---

## Prerequisites

- **Python**: 3.11 or later
- **PostgreSQL**: Running locally on port 5432 (database `ai_grc`)
- **Nmap**: Installed and available in system PATH
- **Node.js**: 18 or later with npm

---

## Getting Started

### 1. Database Migrations

Run non-destructive migrations in sequence:
```powershell
# Phase 2 (Asset Intelligence, Inherent/Residual Risk, Controls)
python scripts/migrate_phase2.py

# Phase 3 (Compliance Frameworks, Requirements, Control Mappings)
python scripts/migrate_phase3.py
```

### 2. Backend Setup

1. Activate virtual environment and run development server:
   ```powershell
   cd backend
   .\venv\Scripts\Activate.ps1
   python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```
   Backend API: `http://127.0.0.1:8000` (Interactive Swagger Docs: `http://127.0.0.1:8000/docs`).

### 3. Frontend Setup

1. Install dependencies and start Vite:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   Dashboard: `http://127.0.0.1:5173`.

### 4. Running Tests

- **Phase 2 Isolated Test Suite**:
  ```powershell
  python -m unittest tests/test_phase2_isolated.py -v
  ```

- **Phase 3 Isolated Test Suite**:
  ```powershell
  python -m unittest tests/test_phase3_isolated.py -v
  ```

- **Run All Isolated Tests**:
  ```powershell
  python -m unittest discover tests -v
  ```

- **Live REST API Verification**:
  ```powershell
  python scripts/verify_phase3_api.py
  ```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check & database connection status |
| `POST` | `/scan?target=...` | Scan single IPv4 host, enrich findings, register GRC risks |
| `POST` | `/discover?network=...` | Discover hosts on private CIDR subnet (max `/24`) |
| `GET` | `/assets` | Retrieve all tracked assets with asset intelligence |
| `GET` | `/assets/{id}` | Retrieve a specific asset |
| `PATCH` | `/assets/{id}` | Update asset intelligence (criticality, env, exposure, owner, function) |
| `GET` | `/risks` | Retrieve all risk register entries with inherent and residual risk |
| `GET` | `/risks/{id}` | Retrieve a specific risk register entry |
| `PATCH` | `/risks/{id}` | Update risk treatment, owner, due date, status |
| `GET` | `/controls` | Retrieve security controls catalog |
| `POST` | `/controls` | Create new security control in catalog |
| `GET` | `/controls/{id}` | Retrieve a specific security control |
| `PATCH` | `/controls/{id}` | Update security control attributes |
| `DELETE` | `/controls/{id}` | Delete security control from catalog |
| `POST` | `/risks/{id}/controls/{cid}` | Assign mitigating security control to risk |
| `DELETE` | `/risks/{id}/controls/{cid}` | Detach security control from risk |
| `GET` | `/compliance/frameworks` | Retrieve supported compliance frameworks (NIST CSF 2.0, ISO 27001:2022) |
| `GET` | `/compliance/requirements` | Retrieve compliance requirements with filters (framework, status, function, category) |
| `GET` | `/compliance/mappings` | Retrieve all control-to-compliance requirement mappings |
| `GET` | `/compliance/summary` | Retrieve Implementation Coverage metrics and status counts per framework |
| `PATCH` | `/compliance/requirements/{id}` | Update requirement assessment status and auditor notes |
| `GET` | `/vulnerabilities` | Retrieve all vulnerability findings |
