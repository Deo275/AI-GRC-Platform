# AI-GRC Platform

An automated Governance, Risk Management, and Compliance (GRC) platform integrating network discovery, vulnerability scanning, CVE enrichment via the NVD REST API, asset intelligence, inherent and residual risk modeling, security controls catalog, and compliance framework mapping.

> **Roadmap & Disclaimer**: Phase 4 introduces the AI-Assisted Security & Risk Intelligence layer. The rule-based GRC risk engine remains the authoritative source for official risk scores, inherent/residual ratings, likelihood, and impact. AI intelligence provides supplementary, transparent, and auditable decision support for both technical and non-technical stakeholders under a strict human-in-the-loop governance model.

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

---

## Phase 4 — AI-Assisted Security & Risk Intelligence

Phase 4 adds an AI security intelligence layer that analyzes technical vulnerability findings and GRC risk contexts, translating them into clear, actionable intelligence for two distinct audiences:
1. **Technical / Security Engineers (SecOps)**: Technical severity interpretation, CVSS analysis, attack surface context, and vendor-neutral 3-tier remediation steps.
2. **Non-Technical GRC & Business Stakeholders**: Plain-language explanations, business consequences, compliance impacts, and governance recommendations.

### Multi-LLM Provider Failover Architecture (Phase 4C)

The platform employs a resilient, sequential multi-LLM failover chain (`ProviderChain`) that transparently cascades across multiple frontier and open-weight models before guaranteeing completion via an offline deterministic fallback:

```text
                  AI Analysis Request (POST /risks/{id}/analyze)
                                        │
                                        ▼
                  ProviderChain Orchestrator [DEFAULT: AI_PROVIDER=chain]
                                        │
                       ┌────────────────┴────────────────┐
                       │ 1. Google Gemini 3.8 Flash      │ (Primary: GEMINI_API_KEY, 8s timeout)
                       └────────────────┬────────────────┘
                                        │ AIProviderError / Timeout / 503
                                        ▼
                       ┌────────────────┴────────────────┐
                       │ 2. OpenAI (gpt-4o-mini)         │ (Secondary: OPENAI_API_KEY, 7s timeout)
                       └────────────────┬────────────────┘
                                        │ AIProviderError / Timeout / 429 / 500
                                        ▼
                       ┌────────────────┴────────────────┐
                       │ 3. Groq (openai/gpt-oss-120b)   │ (Tertiary: GROQ_API_KEY, 5s timeout)
                       └────────────────┬────────────────┘
                                        │ AIProviderError / Timeout / 429 / 500
                                        ▼
                       ┌────────────────┴────────────────┐
                       │ 4. Rule-Assisted Local GRC      │ (Guaranteed Tail: offline, deterministic)
                       └────────────────┬────────────────┘
                                        │
                                        ▼
                 Structured AIAnalysisResult & Immutability Guarantee
```

#### Provider Hierarchy & Structured Output Strategy

| Tier | Provider | Default Model | Timeout | Output Format | Role |
|---|---|---|---|---|---|
| **Tier 1** | `GeminiAIProvider` | `gemini-3.8-flash` | 8s | Native `response_schema` | Primary generative LLM via official Google GenAI SDK |
| **Tier 2** | `OpenAIProvider` | `gpt-4o-mini` | 7s | `json_schema` structured output | Secondary LLM with typed error classification & fallback |
| **Tier 3** | `GroqProvider` | `openai/gpt-oss-120b` | 5s | `json_schema` structured output | High-throughput tertiary open-source LLM via Groq Cloud |
| **Tail** | `RuleAssistedAIProvider` | `rule-assisted-grc-v1` | 0s | Deterministic Python heuristics | Offline expert system; guaranteed zero-dependency fallback |

- **Sequential Execution**: Providers are invoked strictly in sequential order. No concurrent or parallel API requests are made.
- **Single Attempt**: Each external provider receives exactly one request attempt; no cross-provider retries or exponential backoff loops.
- **Failover Auditability**: If failover occurs, the model identifier reflects the full attempt chain (e.g. `rule-assisted-grc-v1 (chain-failover: GeminiAIProvider, OpenAIProvider, GroqProvider)`), `human_review_required` is automatically set to `True`, and a failover notice is appended to `human_review_reasons`.
- **Credential Hygiene**: API keys are read strictly from environment variables, scrubbed via regex sanitizers from all attempt logs, and never logged or serialized to the database.

### Human-in-the-Loop Model

AI intelligence operates strictly as advisory decision support. The authoritative risk ratings remain governed by the rule-based risk engine:

```text
Technical Finding  ──►  Rule-Based Risk Engine  ──►  AI Security Intelligence  ──►  Human Review  ──►  Final GRC Decision
                           (Authoritative)                (Advisory & Audit)            (Mandatory)
```

### Critical Architectural Guarantees & Constraints

1. **Strict Immutability**: AI intelligence **NEVER** modifies or overwrites official rule-based risk scores (`inherent_risk_score`, `residual_risk_score`, `likelihood`, `impact`, `risk_level`, `status`, `treatment`, `risk_owner`, `due_date`).
2. **No Hallucinations / Unsupported Claims**: AI does not invent CVEs, non-existent software versions, fake vendor advisories, or unverified business impacts. Inferred impacts are explicitly qualified.
3. **Pluggable Provider Abstraction**:
   - `chain` (Default): Sequential multi-LLM failover (Gemini → OpenAI → Groq → RuleAssisted).
   - `gemini`: Standalone Gemini with internal fallback to RuleAssisted (Phase 4A behavior).
   - `local`: Offline deterministic heuristics only (`RuleAssistedAIProvider`).
   - `openai`: Legacy `ExternalLLMProvider` (Phase 4A backward-compatible).
   - `openai-native`: Production `OpenAIProvider` with JSON Schema structured outputs.
   - `groq`: Standalone `GroqProvider` (`openai/gpt-oss-120b`).
4. **Structured Intelligence Output**:
   - **Simple Explanation**: High-level non-technical summary.
   - **Why It Matters**: Technical security concern based on evidence.
   - **Severity Interpretation**: Practical meaning of CVSS score and technical severity.
   - **Risk Factors**: Contributing environmental factors (asset criticality, exposure, CVSS, controls), explicitly marking default fallback assumptions if present.
   - **Potential Business Impact**: Disruption, unauthorized access, compliance exposure (clearly distinguishing inferred potential from verified facts).
   - **Tiered Remediation**:
     - *Immediate Mitigation*: Rapid exposure reduction using approved network security controls (avoiding unverified OS or iptables assumptions).
     - *Permanent Remediation*: Root-cause resolution (vendor updates, segmentation).
     - *Validation / Retesting*: Concrete verification steps (re-scan, service checks).
   - **Recommended Platform Controls**: Recommends controls from the platform catalog with rationales (does **not** auto-apply them).
   - **Confidence Score**: Normalized metric ($0.0 - 1.0$) reflecting input data completeness.
   - **Human Review Flag**: Boolean indicator with explicit reasons whenever high severity, production environment, missing data, or chain failover occurs.
5. **Full Auditability**: Every analysis is permanently logged in the `ai_risk_analyses` table with model identifier, timestamp, and context for historical compliance audit trails.
6. **Failure Isolation**: If all external LLMs are unavailable, the platform seamlessly falls through to the deterministic local analyzer; core scanning, risk calculations, and compliance workflows continue functioning uninterrupted.

---

## Getting Started

### 1. Database Migrations

Run non-destructive migrations in sequence:
```powershell
# Phase 2 (Asset Intelligence, Inherent/Residual Risk, Controls)
python scripts/migrate_phase2.py

# Phase 3 (Compliance Frameworks, Requirements, Control Mappings)
python scripts/migrate_phase3.py

# Phase 4 (AI Risk Analyses Audit Table)
python scripts/migrate_phase4.py
```

### 2. Backend Setup

1. Configure environment variables in `backend/.env` (see `.env.example`):
   ```env
   DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/ai_grc
   AI_PROVIDER=chain
   AI_PROVIDER_CHAIN=gemini,openai,groq
   GEMINI_API_KEY=your_gemini_api_key_here
   GEMINI_MODEL=gemini-3.8-flash
   GEMINI_TIMEOUT_SECONDS=8
   OPENAI_API_KEY=your_openai_api_key_here
   OPENAI_MODEL=gpt-4o-mini
   OPENAI_TIMEOUT_SECONDS=7
   GROQ_API_KEY=your_groq_api_key_here
   GROQ_MODEL=openai/gpt-oss-120b
   GROQ_TIMEOUT_SECONDS=5
   ```
2. Activate virtual environment and run development server:
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

- **Phase 2 Isolated Test Suite (11 Tests)**:
  ```powershell
  python tests/test_phase2_isolated.py
  ```

- **Phase 3 Isolated Test Suite (7 Tests)**:
  ```powershell
  python tests/test_phase3_isolated.py
  ```

- **Phase 4A Isolated Test Suite (14 Tests)**:
  ```powershell
  python tests/test_phase4_isolated.py
  ```

- **Phase 4C Multi-LLM Failover Test Suite (20 Tests)**:
  ```powershell
  python tests/test_phase4c_isolated.py
  ```

- **Live REST API Verification Scripts**:
  ```powershell
  # Phase 3 Compliance Mapping Verification
  python scripts/verify_phase3_api.py

  # Phase 4A AI Intelligence Verification
  python scripts/verify_phase4_api.py

  # Phase 4C Multi-LLM Failover Verification
  python scripts/verify_phase4c_api.py
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
| `POST` | `/risks/{id}/analyze` | **(Phase 4)** Trigger AI security intelligence analysis for a risk |
| `GET` | `/risks/{id}/analysis` | **(Phase 4)** Retrieve latest stored auditable AI analysis for a risk |
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
