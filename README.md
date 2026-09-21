# AI-GRC Platform

An automated Governance, Risk Management, and Compliance (GRC) platform integrating network discovery, vulnerability scanning, CVE enrichment via the NVD REST API, and automated risk register management.

---

## Architecture Overview

The platform consists of four primary components:

1. **Frontend**: React 19 single-page dashboard built with Vite, displaying monitored assets, risk scores, and vulnerability findings.
2. **Backend API**: FastAPI application exposing endpoints for single-host scanning, subnet discovery, asset inventory, risk register, and vulnerability tracking.
3. **Scanner Pipeline**:
   - **Nmap Scanner (`scanner/nmap_scanner.py`)**: Executes local Nmap commands for service/version detection (`-sV -O -oX`) and subnet host discovery (`-sn`).
   - **Risk Engine (`scanner/risk_engine.py`)**: Computes heuristic risk scores and security findings based on exposed ports and services.
   - **Vulnerability Scanner (`scanner/vulnerability_scanner.py`)**: Maps identified services to known vulnerabilities.
   - **CVE Lookup (`scanner/cve_lookup.py`)**: Queries the NIST National Vulnerability Database (NVD) 2.0 REST API to identify and correlate CVEs, CVSS scores, and version ranges.
4. **Database**: PostgreSQL storing monitored `assets`, `risks`, and `vulnerabilities` using SQLAlchemy ORM.

---

## Current Functionality

- **Single-Host Network Scan (`POST /scan?target=...`)**:
  - Validates single IPv4 address target.
  - Scans target host via Nmap for open ports, operating system, and software versions.
  - Enriches findings with NVD CVE data and CVSS scores.
  - Updates asset inventory with latest scan timestamp and risk rating.
  - Updates GRC risk register with compliance controls (NIST CSF) and remediation recommendations.
  - Maintains vulnerability and risk lifecycles: active findings marked `Open`, resolved findings marked `Resolved`, reappearing findings reopened.
- **Network Discovery (`POST /discover?network=...`)**:
  - Validates IPv4 CIDR notation.
  - Restricts scans to private networks (RFC 1918) with a maximum subnet size of `/24`.
  - Discovers active network hosts and registers them in the asset inventory.
- **Asset Inventory (`GET /assets`)**:
  - Lists all tracked assets, IP addresses, hostnames, open ports, risk scores, and last seen timestamps.
- **Risk Register (`GET /risks`)**:
  - Lists all compliance risks, likelihood, impact, risk scores, treatment, status, and control mappings.
- **Vulnerability Findings (`GET /vulnerabilities`)**:
  - Lists all identified vulnerabilities, affected ports, services, products, versions, CVE IDs, CVSS scores, confidence ratings, and status.

---

## Prerequisites

- **Python**: 3.11 or later
- **PostgreSQL**: Running locally on port 5432
- **Nmap**: Installed and available in the system PATH
- **Node.js**: 18 or later with npm

---

## Getting Started

### 1. Backend Setup

1. Create and activate a Python virtual environment:
   ```bash
   cd backend
   python -m venv venv
   # On Windows:
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r ../requirements.txt
   ```

3. Configure environment variables:
   Copy `.env.example` to `backend/.env` and specify your PostgreSQL credentials:
   ```bash
   cp ../.env.example backend/.env
   ```
   Edit `backend/.env`:
   ```env
   DATABASE_URL=postgresql://<username>:<password>@localhost:5432/ai_grc
   ```

4. Run the FastAPI development server:
   ```bash
   cd backend
   uvicorn main:app --reload
   ```
   The backend API will be available at `http://127.0.0.1:8000`.

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
   The dashboard will be available at `http://localhost:5173`.

---

## API Reference

| Method | Endpoint | Query Parameters | Description |
|---|---|---|---|
| `GET` | `/` | None | Health check & database connection status |
| `GET` | `/assets` | None | Retrieve all tracked assets |
| `GET` | `/risks` | None | Retrieve all risk register records |
| `GET` | `/vulnerabilities` | None | Retrieve all vulnerability findings |
| `POST` | `/scan` | `target` (IPv4 string, default `192.168.127.1`) | Run full port scan, CVE enrichment, and risk analysis on target |
| `POST` | `/discover` | `network` (IPv4 CIDR string, default `192.168.127.0/24`) | Discover active hosts on a private subnet (max `/24`) |
