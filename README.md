# AI-GRC Platform

An automated Governance, Risk Management, and Compliance (GRC) platform integrating network discovery, vulnerability scanning, CVE enrichment via the NVD REST API, asset intelligence, inherent and residual risk modeling, security controls catalog, and compliance framework mapping.

> **Core GRC Separation & Advisory AI Disclaimer**: The platform integrates an AI-Assisted Security & Risk Intelligence layer powered by an automated failover ProviderChain (Gemini → OpenAI → Groq → Rule-Assisted fallback). Official GRC risk scores, inherent/residual ratings, likelihood, impact, and compliance evaluations remain strictly authoritative and rule-based. AI intelligence provides purely advisory, transparent decision support under a mandatory human-in-the-loop governance model. Official risk ratings can never be modified by AI.

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
│  - AI Security & Risk Intelligence Explanations (On-Demand)              │
│  - Continuous Monitoring & Attack Surface Drift Center (Phase 5)         │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │ REST API (JSON)
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          FastAPI Backend Service                         │
│  - Asset Intelligence Management & Dynamic Recalculation                 │
│  - GRC Risk Calculation Engine (scanner/grc_engine.py)                    │
│  - Security Controls Catalog & Association Management                    │
│  - Compliance Mapping Engine & Implementation Coverage Calculator        │
│  - AI ProviderChain Multi-LLM Orchestrator (On-Demand Only)              │
│  - Monitoring API & Background Scan Job Manager (Phase 5)                │
│  - In-Process Background Scheduler (Single-Process Daemon)               │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                     ┌───────────────┼───────────────┐
                     ▼                               ▼
┌──────────────────────────────────────────┐ ┌─────────────────────────────┐
│           PostgreSQL Database            │ │  Monitoring & Scan Engine   │
│  - assets (with GRC Intel)               │ │  - ThreadPoolExecutor (max=3)│
│  - risks (Inherent/Residual)             │ │  - Stage 1: Ping Sweep (-sn)│
│  - controls (Catalog)                    │ │  - Stage 2: Top-100 Ports   │
│  - risk_controls (M2M)                   │ │  - CVE Lookup (NVD API 2.0) │
│  - compliance_frameworks                 │ │  - Vulnerability Pipeline   │
│  - compliance_requirements               │ │  - Drift Detector (5 Events)│
│  - control_compliance_mappings           │ │  - Authoritative GRC Engine │
│  - vulnerabilities                       │ └─────────────────────────────┘
│  - ai_risk_analyses (Audit Log)          │
│  - scan_jobs (Lifecycle & History)       │
│  - scan_schedules (Automated Intervals)  │
│  - drift_events (Attack Surface Drift)   │
└──────────────────────────────────────────┘
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

## Phase 5 — Continuous Network Monitoring, Automated Background Scanning, and Asset Drift Detection

Phase 5 introduces continuous attack surface monitoring, non-blocking asynchronous scan orchestration, an in-process scan scheduler, and a deterministic drift detection engine. It continuously tracks changes to network assets, open ports, and vulnerabilities, recalculating GRC risk posture while preserving strict boundaries around AI automation and system safety.

### Architecture & Pipeline Flow

```text
React Dashboard
      ↓
FastAPI Monitoring API
      ↓
Scan Job Manager
      ↓
ThreadPoolExecutor(max_workers=3)
      ↓
2-stage Network Monitoring
      ↓
Existing Vulnerability/CVE Pipeline
      ↓
Last Successful Scan Snapshot
      ↓
Drift Detection
      ↓
Authoritative GRC Risk Engine
      ↓
PostgreSQL
      ↓
Monitoring Dashboard

AI ProviderChain remains:

ON-DEMAND ONLY

It must NOT automatically run during background monitoring.
```

### Core Capabilities

1. **Continuous Network Monitoring**: Automated discovery and vulnerability assessment across authorized enterprise subnets.
2. **Asynchronous Scan Jobs**: Scans execute in the background without blocking FastAPI request threads. Clients receive immediate `HTTP 202 Accepted` with a Job ID and track execution progress asynchronously.
3. **Bounded Worker Pool (`ThreadPoolExecutor(max_workers=3)`)**:
   - Concurrency is strictly capped at 3 simultaneous background scan jobs.
   - Additional job requests remain in `Queued` state in the database until an execution worker becomes available. Jobs never fail simply due to worker saturation.
   - Each worker allocates an independent database session (`SessionLocal()`), committed and closed in `finally` blocks. Request-thread SQLAlchemy sessions are never leaked to workers.
4. **2-Stage Network Scanning Pipeline**:
   - **Stage 1 (Host Discovery)**: Fast ping sweep (`nmap -sn`) over the target subnet to identify live hosts without port probing overhead.
   - **Stage 2 (Port & Service Inspection)**: Port and service fingerprinting (`nmap --top-ports 100 -sV`) executed only against discovered live hosts.
   - **Optional OS Detection**: OS fingerprinting (`-O`) is optional and disabled by default during monitoring runs for operational stability and speed.
5. **Automated Scheduled Scans**:
   - Operator-defined recurring scan schedules with configurable intervals (minimum 15 minutes, e.g., 60m or 1440m).
   - Dynamic schedule management: activate, pause, modify interval, or delete.
6. **Scan History & Execution Metrics**:
   - Comprehensive audit log in `scan_jobs` tracking execution status (`Queued`, `Running`, `Completed`, `Failed`, `Cancelled`), start/completion timestamps, duration in seconds, discovered host/vulnerability counts, and error diagnostic messages.
7. **Deterministic Attack Surface Drift Detection**:
   - Evaluates the delta between the previous scan snapshot and the current scan snapshot for the monitored target scope.
   - Generates typed, severity-categorized drift events logged in `drift_events`.

### Attack Surface Drift Events

The drift detector categorizes changes across five deterministic event types:

| Event Type | Severity | Description | Trigger Condition |
|---|---|---|---|
| `NEW_ASSET` | High | New host discovered on network | Host IP present in current scan but absent in previous baseline |
| `PORT_OPENED` | Medium | New network service listening | Port open in current scan but previously closed/unobserved |
| `PORT_CLOSED` | Low | Service decommissioned/unreachable | Previously open port is no longer detected as open |
| `CVE_DETECTED` | High | Known vulnerability identified | CVE finding identified by vulnerability/NVD pipeline |
| `FINDING_RESOLVED` | Low | Vulnerability remediated | Previously open finding is absent or service port closed |

### Critical Architectural Boundaries & Constraints

#### 1. Drift Baseline Rule
- **Only the latest successfully completed scan (`status='Completed'`) becomes the drift baseline snapshot.**
- Failed, aborted, or cancelled scans **never** replace or corrupt the baseline snapshot.
- If no previous completed scan exists for a target, the current scan establishes the initial baseline without generating false "resolved" events.

#### 2. Unclassified New Asset Rule
- When a new host is discovered (`NEW_ASSET`), it is registered in the asset inventory with safe default values.
- **The system does NOT automatically assume or infer:**
  - `Medium` (or any non-default) Criticality
  - `Production` Environment
  - `Internal` Exposure
  - Asset Owner
  - Business Function
- A newly discovered asset remains **business-unclassified** from a GRC perspective until an authorized human operator reviews and assigns asset intelligence via the Asset Intelligence editor.

#### 3. CVE Applicability Boundary
- `CVE_DETECTED` events strictly represent findings confirmed by the existing vulnerability scanner and NVD CVE lookup pipeline (`scanner/vulnerability_scanner.py` and `scanner/cve_lookup.py`).
- Phase 5 does **not** introduce a new CVE applicability engine, speculative CVE matching, or heuristic overrides.

#### 4. AI ProviderChain Boundary (Strictly On-Demand)
- Continuous network monitoring and scheduled background scans **NEVER** automatically invoke the AI `ProviderChain`, Gemini, OpenAI, or Groq.
- AI risk intelligence remains strictly **ON-DEMAND ONLY** and human-triggered per risk entry. Background scans never consume LLM API quotas or generate automated AI risk determinations.

#### 5. Automatic Deterministic GRC Recalculation
- Findings and asset updates from monitoring scans feed directly into the authoritative, rule-based GRC risk engine (`scanner/grc_engine.py`).
- Official inherent and residual risk scores ($L \times I$) and risk levels are recalculated deterministically without external dependencies.

#### 6. Single-Process In-Process Scheduler Limitation
- The background scan scheduler runs as a lightweight in-process daemon thread within the single running FastAPI process.
- **Deployment Constraint**: Running multiple FastAPI worker processes (e.g. `uvicorn main:app --workers 4` or multi-pod container clusters) is **NOT supported** for this scheduler architecture, as each worker would independently spawn duplicate schedulers and create competing job dispatches.
- Distributed scheduling via Celery, Redis, or RabbitMQ is intentionally deferred as out of scope for Phase 5.

#### 7. Target Scope & Subnet Restrictions
- Scans are strictly restricted to private RFC 1918 subnets and the local loopback:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
  - `127.0.0.1/32`
- **Subnet Scope Limit**: Maximum network mask permitted is `/24` (256 addresses). Subnets wider than `/24` (e.g. `/16` or `/8`) are rejected with `HTTP 400 Bad Request` to prevent accidental network flooding.
- Target IP addresses and CIDR notations are validated strictly via Python's standard `ipaddress` module before command generation.

#### 8. Process Execution Security & Timeouts
- Subprocess invocations strictly use `shell=False` with argument lists (never shell strings), preventing command injection vulnerabilities.
- Multi-tier timeouts are enforced:
  - Stage 1 (Host Discovery): 120 seconds total.
  - Stage 2 (Service Fingerprinting): 180 seconds per individual host; 600 seconds total.
- **Cooperative Cancellation**: When an operator requests scan cancellation (`POST /monitoring/jobs/{id}/cancel`), a cancellation event is flagged. The background worker checks this flag between execution stages and host loops, actively terminates any running Nmap child subprocesses, and only marks the job as `Cancelled` once all subprocesses have exited cleanly. The system never reports `Cancelled` while an orphaned scanner process continues running.

### React Dashboard: Continuous Monitoring & Drift Center

The React 19 frontend provides an integrated **Continuous Monitoring & Drift Center** featuring:
- **KPI Summary Ribbon**: Live counts for Active Schedules, Monitored Assets, 24-Hour Drift Events, and Running Scans.
- **Manual Scan Trigger**: Safe target input with RFC 1918 validation and instant job dispatch.
- **Active Scans & Progress Tracker**: Real-time progress percentage bar, current execution stage indicator, and one-click cooperative cancellation.
- **Scan Schedules Manager**: Create recurring scan schedules with validated intervals, toggle active/paused states, or delete schedules.
- **Attack Surface Drift Feed**: Chronological stream of drift events with severity badges (`High`, `Medium`, `Low`), event type indicators (`NEW_ASSET`, `PORT_OPENED`, etc.), affected host details, and filtering by severity and event type.
- **Historical Scans Log**: Searchable audit log of past scan executions with execution durations, discovered asset and vulnerability tallies, and failure diagnostics.

### Phase 5 Non-Goals

To maintain high reliability and strict architectural boundaries, the following features are explicitly out of scope for Phase 5:
- External alerting integrations (Slack, Discord, PagerDuty, email, SMS, or outgoing webhooks).
- Distributed message brokers or external job queues (Redis, RabbitMQ, Celery).
- Role-Based Access Control (RBAC) or user authentication.
- Autonomous AI decision-making or automatic risk reclassification.
- Full 65,535-port scans (monitoring scans focus on the top 100 ports for operational safety).
- Arbitrary public Internet scanning.

---

## Phase 6 — Governance, Evidence, Reporting & Human Sign-Off

Phase 6 completes the platform with an enterprise governance, evidence management, regulatory reporting, and human-in-the-loop review architecture:

### 1. Phase 6A: Evidence Catalog & Tamper-Evident Audit Trail
- **Evidence Management**: Centralized repository of compliance and security evidence mapped to requirements, controls, and risks.
- **Tamper-Evident Audit Logging**: Synchronous recording of governance events (`RISK_REVIEW_SUBMITTED`, `RISK_REVIEW_STALE`, `TREATMENT_OVERRIDDEN`, `CONTROL_EFFECTIVENESS_VERIFIED`, `AI_ANALYSIS_RUN`, `REPORT_EXPORTED`).
- **Cryptographic Hygiene**: Deterministic SHA-256 integrity hash calculated over canonical event payloads with sensitive field redaction (passwords, tokens, API keys).
- **Integrity Guarantee**: Tamper-evident via application-level append-only constraints and hash validation (no UPDATE or DELETE endpoints exposed).

### 2. Phase 6B: Reporting & Multi-Format Export Engine
- **5 Comprehensive Report Types**:
  1. `executive_summary`: High-level GRC posture, KPI summary cards, active findings, and advisory AI insights.
  2. `technical_vulnerabilities`: Detailed vulnerability findings, CVSS scores, NVD CVE metadata, and asset targets.
  3. `compliance_gap`: Regulatory readiness breakdown, requirement statuses, mapped controls, and identified gaps.
  4. `risk_register`: Enterprise risk register, inherent vs residual scores, mitigation assignments, and treatments.
  5. `governance_audit`: Complete append-only audit trail with SHA-256 integrity verification hashes.
- **Export Formats**: JSON (`application/json`), CSV (`text/csv`), and HTML (`text/html` with print media formatting).
- **OWASP CSV Injection Defense**: Cells starting with `=, +, -, @, \t, \r` are prefixed with `'` to neutralize formula injection attacks.
- **Stored XSS Defense**: Strict HTML entity escaping across all dynamic fields.

### 3. Phase 6C: Human Review & Risk Sign-Off Workflow
- **Governance State Separation**: `Risk.review_status` (`Pending Review`, `Under Review`, `Approved`, `Rejected`, `Changes Requested`, `Stale`) is maintained strictly separate from operational `Risk.status`.
- **Single Active Review Invariant**: Enforced via a partial unique database index (`is_current = 1`). Historical reviews are permanently preserved.
- **Material Change & Stale Invalidation**: SHA-256 snapshot hashing captures vulnerabilities, CVSS scores, and controls. Vulnerability drift automatically invalidates approved reviews to `Stale` and emits a deduplicated `RISK_REVIEW_STALE` audit event.
- **Independent Treatment Override**: Human sign-off allows operators to independently modify or confirm the agreed risk treatment strategy (`Mitigate`, `Accept`, `Transfer`, `Avoid`).

### 4. Phase 6D: Governance Dashboard Integration
- **Governance Review Center**: Dedicated dashboard view in React 19.
- **Review KPIs Ribbon**: Real-time tallies for Pending Review, Stale Reviews, Changes Requested, and Approved Risks.
- **Attention Queue**: High-priority risks requiring immediate auditor or sign-off attention.
- **Interactive Review Modal**: Formal sign-off dialog with operator attribution, treatment confirmation, and optional AI acknowledgement.
- **Audit Trail Viewer**: Paginated, filterable governance timeline with payload diff inspection.
- **Direct Export Controls**: Instant generation and download of JSON, CSV, and HTML reports.

### 5. Phase 6E: Final Verification & Integration Baseline
- Complete end-to-end integration and regression verification suite consisting of **207 automated tests passing with 0 failures and 0 errors**.

---

## Prototype Disclaimers & Operational Guardrails

> [!IMPORTANT]
> **1. Prototype Authentication & Access Control**: Authentication and Role-Based Access Control (RBAC) are **not** implemented in this prototype. User and reviewer identities captured in sign-offs and audit logs represent session attribution metadata for tracking purposes and do not imply cryptographically authenticated authorization.
>
> **2. Reviewer Attribution**: The reviewer identity in review dialogs and audit records is captured as attribution metadata without role enforcement.
>
> **3. Compliance Non-Certification Disclaimer**: Compliance framework mappings (NIST CSF 2.0 and ISO/IEC 27001:2022) are internal readiness and gap-tracking tools. Mapping a control or achieving a percentage score **does not constitute formal regulatory certification, external audit accreditation, or legal compliance**.
>
> **4. Report & Legal Disclaimer**: Reports generated and exported by the platform are intended for internal risk-management, vulnerability prioritization, and compliance-tracking purposes only. They do not constitute formal legal counsel, regulatory certification, or guarantee of third-party audit attestation.
>
> **5. Advisory AI Non-Authoritative Guarantee**: The AI advisory intelligence layer provides supplementary decision support. It **cannot modify official risk scores, residual calculations, or compliance determinations**.

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

# Phase 5 (Continuous Monitoring, Scan Jobs, Schedules, Drift Events)
python scripts/migrate_phase5.py

# Phase 6A (Evidence Catalog & Audit Log Tables)
python scripts/migrate_phase6a.py

# Phase 6C (Risk Reviews Table & Governance State Indices)
python scripts/migrate_phase6c.py
```

### 2. Backend Setup

1. Configure environment variables in `backend/.env` (see `.env.example`):
   ```env
   DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/ai_grc
   AI_PROVIDER=chain
   AI_PROVIDER_CHAIN=gemini,openai,groq
   GEMINI_API_KEY=your_gemini_api_key_here
   GEMINI_MODEL=gemini-3.6-flash
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

### 4. Running Automated Tests

Run the full unified automated test suite:
```powershell
backend\venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
```

**Expected Baseline**: **207 tests passing (0 failures, 0 errors)** across 9 comprehensive suites:
- `test_phase2_isolated.py`: 16 tests (GRC scoring, matrix thresholds, control mitigations)
- `test_phase3_isolated.py`: 18 tests (NIST CSF 2.0 & ISO 27001 mappings, requirement semantics)
- `test_phase4_isolated.py`: 27 tests (Gemini structured outputs, schemas, immutability)
- `test_phase4c_isolated.py`: 23 tests (ProviderChain multi-LLM failover, credential sanitization)
- `test_phase5_isolated.py`: 37 tests (Scan jobs queue, scheduler, drift detection, cancellations)
- `test_phase6_isolated.py`: 24 tests (Evidence catalog, SHA-256 audit log, redactions)
- `test_phase6b_isolated.py`: 26 tests (5 report types, JSON/CSV/HTML exports, formula injection defenses)
- `test_phase6c_isolated.py`: 24 tests (Human review workflow, partial unique index, stale invalidations)
- `test_phase6e_integration.py`: 12 tests (End-to-end cross-phase lifecycle integration)

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check & database connection status |
| `POST` | `/scan?target=...` | Scan single IPv4 host, enrich findings, register GRC risks (synchronous legacy) |
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
| `POST` | `/monitoring/jobs` | **(Phase 5)** Dispatch asynchronous network scan job (HTTP 202 Accepted) |
| `GET` | `/monitoring/jobs` | **(Phase 5)** Retrieve paginated scan jobs history with status/metrics |
| `GET` | `/monitoring/jobs/{id}` | **(Phase 5)** Retrieve real-time progress and details for a specific scan job |
| `POST` | `/monitoring/jobs/{id}/cancel` | **(Phase 5)** Request cooperative cancellation for an active scan job |
| `GET` | `/monitoring/schedules` | **(Phase 5)** Retrieve all configured recurring scan schedules |
| `POST` | `/monitoring/schedules` | **(Phase 5)** Create new automated scan schedule (min 15-minute interval) |
| `GET` | `/monitoring/schedules/{id}` | **(Phase 5)** Retrieve a specific scan schedule |
| `PATCH` | `/monitoring/schedules/{id}` | **(Phase 5)** Update scan schedule interval or toggle active/paused state |
| `DELETE` | `/monitoring/schedules/{id}` | **(Phase 5)** Delete an automated scan schedule |
| `GET` | `/monitoring/drift` | **(Phase 5)** Retrieve attack surface drift feed with severity and type filters |
| `GET` | `/monitoring/metrics` | **(Phase 5)** Retrieve aggregated monitoring KPI metrics for the dashboard |
| `GET` | `/evidence` | **(Phase 6A)** Retrieve evidence catalog items with optional requirement/control filters |
| `POST` | `/evidence` | **(Phase 6A)** Register new evidence item in the governance catalog |
| `GET` | `/audit/logs` | **(Phase 6A)** Retrieve paginated, tamper-evident audit logs with action and entity filters |
| `GET` | `/reports/{report_type}` | **(Phase 6B)** Export report in `json`, `csv`, or `html` format |
| `GET` | `/risks/{id}/reviews` | **(Phase 6C)** Retrieve current human review, status, and historical review log |
| `POST` | `/risks/{id}/reviews` | **(Phase 6C)** Submit formal human sign-off review (APPROVED, REJECTED, CHANGES_REQUESTED) |
| `POST` | `/governance/reviews/evaluate-stale` | **(Phase 6C)** Trigger on-demand staleness evaluation across all current reviews |
| `GET` | `/governance/kpis` | **(Phase 6D)** Retrieve governance metrics (Pending, Stale, Changes Requested, Approved) |
