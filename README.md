# AI-GRC Platform

An automated Governance, Risk Management, and Compliance (GRC) platform integrating network discovery, vulnerability scanning, CVE enrichment via the NVD REST API, asset intelligence, inherent and residual risk modeling, security controls catalog, and risk treatment workflows.

> **Note on Roadmap**: AI/LLM-assisted analysis is planned for a future phase. Phase 2 focuses on establishing a robust, explainable, and industry-standard GRC risk management model.

---

## Architecture Overview

```text
┌─────────────────────────────────────────────────────────────┐
│             React 19 Dashboard (Vite Frontend)              │
│  - Asset Inventory & Intelligence Editor (Criticality/Env)  │
│  - GRC Risk Register (Inherent vs. Residual Risk)           │
│  - Security Controls Catalog & Mitigation Assignments       │
│  - Vulnerability Findings & CVE Correlation                 │
└──────────────────────────────┬──────────────────────────────┘
                               │ REST API (JSON)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Backend Service                  │
│  - Asset Intelligence Management & Dynamic Recalculation   │
│  - GRC Risk Calculation Engine (scanner/grc_engine.py)      │
│  - Security Controls Catalog & Association Management       │
│  - Technical Scanner Pipeline (Nmap, CVE/NVD, Heuristics)   │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
┌─────────────────────────────┐ ┌─────────────────────────────┐
│    PostgreSQL Database      │ │      Scanner Pipeline       │
│  - assets (with GRC Intel)  │ │  - Nmap Scanner (-sV -O)    │
│  - risks (Inherent/Residual)│ │  - CVE Lookup (NVD API 2.0) │
│  - controls (Catalog)       │ │  - Vulnerability Scanner    │
│  - risk_controls (M2M)      │ │  - GRC Risk Engine          │
│  - vulnerabilities          │ │                             │
└─────────────────────────────┘ └─────────────────────────────┘
```

---

## Phase 2 GRC Risk Model

### 1. Inherent Risk
- **Impact Score (1–4)**: Directly derived from Asset Business Criticality:
  - Low $\to$ 1, Medium $\to$ 2 (default), High $\to$ 3, Critical $\to$ 4.
- **Likelihood Score (1–4)**:
  - Derived primarily from CVSS score (CVSS $\ge 9.0 \to 4$; $7.0-8.9 \to 3$; $4.0-6.9 \to 2$; $< 4.0 \to 1$).
  - If CVSS is unavailable, falls back to severity string (`critical` $\to 4$, `high` $\to 3$, `medium` $\to 2$, `low` $\to 1$).
  - If both are unavailable, uses baseline fallback.
  - Adjusted by Asset Exposure modifier: External (+1), Internal (-1), DMZ (0).
  - Strictly clamped between 1 and 4.
- **Inherent Risk Score**: $\text{Likelihood Score} \times \text{Impact Score}$ (Range: 1–16).
- **Risk Level Thresholds**:
  - 1–3: Low
  - 4–6: Medium
  - 7–11: High
  - 12–16: Critical

### 2. Residual Risk & Mitigating Controls
- In Phase 2, security controls reduce **likelihood only**. Impact remains unchanged (`residual_impact == impact_score`).
- Mitigating effect per implemented control:
  - High Effectiveness: -2 Likelihood points
  - Medium Effectiveness: -1 Likelihood point
  - Low Effectiveness: 0 points
- **Floor constraint**: Residual likelihood cannot drop below 1.
- **Residual Risk Score**: $\text{Residual Likelihood} \times \text{Residual Impact}$ (Range: 1–16).

### 3. Risk Treatment & Governance
- **Treatment Options**: Mitigate (default), Accept, Transfer, Avoid.
- **Ownership**: Assigned Risk Owner and remediation Due Date.
- **Lifecycle Status**: Open, Under Review, Accepted, Resolved.

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
- **Control Assignment (`POST /risks/{id}/controls/{control_id}`, `DELETE /risks/{id}/controls/{control_id}`)**:
  - Assign or detach controls from risks to dynamically adjust residual risk scores.
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

### 1. Backend Setup

1. Activate Python virtual environment:
   ```powershell
   cd backend
   .\venv\Scripts\Activate.ps1
   ```

2. Run Phase 2 database migration:
   ```powershell
   python ..\scripts\migrate_phase2.py
   ```

3. Start the FastAPI development server:
   ```powershell
   python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```
   Backend API: `http://127.0.0.1:8000` (Interactive docs: `http://127.0.0.1:8000/docs`).

### 2. Frontend Setup

1. Install frontend dependencies:
   ```bash
   cd frontend
   npm install
   ```

2. Run the Vite development server:
   ```bash
   npm run dev
   ```
   Dashboard: `http://127.0.0.1:5173`.

### 3. Running Tests

- **Phase 2 Isolated Test Suite** (does not modify real database):
  ```powershell
  python -m unittest tests/test_phase2_isolated.py -v
  ```

- **Live REST API Verification**:
  ```powershell
  python scripts/verify_phase2_api.py
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
| `GET` | `/vulnerabilities` | Retrieve all vulnerability findings |
