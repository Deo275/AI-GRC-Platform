import { useEffect, useState, useRef, Fragment } from "react";
import "./App.css";
import { authFetch, API_BASE } from "./api/client";
import { AuthProvider } from "./context/AuthContext";
import { useAuth } from "./context/useAuth";
import { LoginPage } from "./components/LoginPage";
import { AuthLoadingScreen } from "./components/AuthLoadingScreen";

const REPORT_TYPES = [
  {
    id: "executive_summary",
    title: "Executive Summary",
    category: "EXECUTIVE POSTURE",
    categoryKey: "EXECUTIVE",
    desc: "C-suite strategic overview of organization-wide risk posture, Inherent vs. Residual risk scores, top critical risks, and compliance coverage.",
    formats: ["json", "csv", "html"],
    dataPoints: ["Monitored Assets", "Inherent / Residual Scores", "Critical Risk Ratio", "Compliance Readiness %", "AI Advisory Context"],
    targetAudience: "Board of Directors, CISO, Executive Leadership",
  },
  {
    id: "technical_vulnerabilities",
    title: "Technical Vulnerabilities",
    category: "ATTACK SURFACE",
    categoryKey: "TECHNICAL",
    desc: "Complete technical inventory of hosts, open ports, correlated CVE findings, CVSS v3.1 scores, and automated vulnerability intelligence.",
    formats: ["json", "csv", "html"],
    dataPoints: ["Active IP Inventory", "Open Port Mappings", "CVE Identifiers", "CVSS v3.1 Base Scores", "Remediation Steps"],
    targetAudience: "Security Engineering, SOC Analysts, System Administrators",
  },
  {
    id: "compliance_gap",
    title: "Compliance Gap Analysis",
    category: "REGULATORY COMPLIANCE",
    categoryKey: "COMPLIANCE",
    desc: "Readiness assessment mapped against NIST CSF 2.0 and ISO/IEC 27001:2022, detailing control coverage, implemented safeguards, and open gaps.",
    formats: ["json", "csv", "html"],
    dataPoints: ["NIST CSF 2.0 Controls", "ISO/IEC 27001:2022 Controls", "Implementation State", "Identified Gaps", "Evidence References"],
    targetAudience: "Compliance Officers, Internal/External Auditors, GRC Teams",
  },
  {
    id: "risk_register",
    title: "Enterprise Risk Register",
    category: "RISK MANAGEMENT",
    categoryKey: "RISK",
    desc: "Comprehensive GRC risk register with Likelihood × Impact matrix coordinates, assigned mitigating controls, treatments, and governance review sign-offs.",
    formats: ["json", "csv", "html"],
    dataPoints: ["Likelihood × Impact Coordinates", "Mitigating Controls", "Treatment Strategy", "Assigned Owners", "Governance Sign-offs"],
    targetAudience: "Enterprise Risk Committees, Risk Owners, Security Officers",
  },
  {
    id: "governance_audit",
    title: "Governance Audit Trail",
    category: "AUDIT & EVIDENCE",
    categoryKey: "AUDIT",
    desc: "Append-only chronological audit log of all administrative actions, human risk reviews, state transitions, and deterministic SHA-256 integrity hashes.",
    formats: ["json", "csv", "html"],
    dataPoints: ["Chronological Milestones", "Actor Attribution", "Source Channels", "State Transitions", "SHA-256 Integrity Hashes"],
    targetAudience: "Forensic Investigators, External Regulators, Compliance Auditors",
  },
];

// ---------------------------------------------------------------------------
// Timestamp formatting utility
// Backend/database timestamps are in UTC without an explicit timezone suffix.
// We normalize ISO datetime strings to UTC so standard Date/Intl methods
// correctly convert them into the user's browser/local timezone.
// ---------------------------------------------------------------------------
const parseUtcDate = (val) => {
  if (!val) return null;
  if (val instanceof Date) return val;
  if (typeof val === "string") {
    let s = val.trim();
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(s)) {
      s = s.replace(" ", "T");
    }
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(s) && !/(Z|[+-]\d{2}(:?\d{2})?)$/i.test(s)) {
      s += "Z";
    }
    return new Date(s);
  }
  return new Date(val);
};

const formatDateTime = (iso, fallback = "—") => {
  if (!iso) return fallback;
  try {
    const d = parseUtcDate(iso);
    return !d || isNaN(d.getTime()) ? iso : d.toLocaleString();
  } catch {
    return iso;
  }
};

const calculateJobDuration = (startedAt, completedAt) => {
  if (!startedAt || !completedAt) return "—";
  try {
    const s = parseUtcDate(startedAt);
    const c = parseUtcDate(completedAt);
    if (!s || !c || isNaN(s.getTime()) || isNaN(c.getTime())) return "—";
    const diffMs = c.getTime() - s.getTime();
    if (diffMs < 0) return "—";
    const totalSec = Math.floor(diffMs / 1000);
    if (totalSec < 60) return `${totalSec}s`;
    const mins = Math.floor(totalSec / 60);
    const secs = totalSec % 60;
    if (mins < 60) return `${mins}m ${secs}s`;
    const hours = Math.floor(mins / 60);
    const remMins = mins % 60;
    return `${hours}h ${remMins}m`;
  } catch {
    return "—";
  }
};

// ---------------------------------------------------------------------------
// AIAnalysisPanel — Phase 4B: Pure display component for AI security intelligence
// Receives pre-fetched analysis data; no API calls, no GRC state mutations.
// ---------------------------------------------------------------------------
function AIAnalysisPanel({ loading, error, analysis, onReanalyze }) {
  if (loading) {
    return (
      <div className="ai-panel-loading">
        <span className="ai-spinner" />
        Generating AI security intelligence...
      </div>
    );
  }

  if (error) {
    return (
      <div className="ai-panel-error">
        <strong>⚠ Analysis Failed:</strong> {error}
        <button className="btn-link" onClick={onReanalyze} style={{ marginLeft: "12px" }}>
          Retry
        </button>
      </div>
    );
  }

  if (!analysis) return null;

  const confidencePct = Math.round((analysis.confidence || 0) * 100);
  const confClass = confidencePct >= 75 ? "high" : confidencePct >= 50 ? "med" : "low";

  const priorityBadgeClass = (p) => {
    switch ((p || "").toLowerCase()) {
      case "critical": return "badge-critical";
      case "high":     return "badge-high";
      case "medium":   return "badge-medium";
      case "low":      return "badge-low";
      default:         return "badge-neutral";
    }
  };

  const formatAnalysisDate = (iso) => formatDateTime(iso, "");

  return (
    <div className="ai-panel">

      {/* Human Review Warning */}
      {analysis.human_review_required && (
        <div className="ai-review-warning">
          <div className="ai-review-warning-header">
            ⚠&nbsp; Human Review Recommended — validate before making risk decisions based on this analysis
          </div>
          {analysis.human_review_reasons && analysis.human_review_reasons.length > 0 && (
            <ul className="ai-review-reasons">
              {analysis.human_review_reasons.map((r, i) => <li key={i}>{r}</li>)}
            </ul>
          )}
        </div>
      )}

      {/* Panel Header: AI priority + model name + timestamp + confidence + re-analyze */}
      <div className="ai-panel-header">
        <div className="ai-panel-header-left">
          <span className={`badge ${priorityBadgeClass(analysis.priority)} ai-priority-badge`}>
            AI Priority: {analysis.priority}
          </span>
          <span className="ai-model-tag" title="AI provider / model used for this analysis">
            {analysis.model_name}
          </span>
          {analysis.created_at && (
            <span className="ai-timestamp">
              Generated: {formatAnalysisDate(analysis.created_at)}
            </span>
          )}
        </div>
        <div className="ai-panel-header-right">
          <div className="ai-confidence-wrap">
            <span className="ai-conf-label">Confidence</span>
            <div className="ai-confidence-bar">
              <div
                className={`ai-confidence-fill ai-conf-fill-${confClass}`}
                style={{ width: `${confidencePct}%` }}
              />
            </div>
            <span className={`ai-conf-pct ai-conf-pct-${confClass}`}>{confidencePct}%</span>
          </div>
          <button
            type="button"
            className="btn-ai-reanalyze"
            disabled={loading}
            onClick={onReanalyze}
          >
            ↺ Re-analyze
          </button>
        </div>
      </div>

      {/* Simple Explanation — most prominent section */}
      {analysis.simple_explanation && (
        <div className="ai-simple-explanation">
          <div className="ai-card-title">AI Security Intelligence Summary</div>
          <p className="ai-simple-text">{analysis.simple_explanation}</p>
        </div>
      )}

      {/* Why It Matters + Severity Assessment — two-column grid */}
      <div className="ai-content-grid">
        {analysis.why_it_matters && (
          <div className="ai-card">
            <div className="ai-card-title">Why It Matters</div>
            <div className="ai-card-body">{analysis.why_it_matters}</div>
          </div>
        )}
        {analysis.severity_explanation && (
          <div className="ai-card">
            <div className="ai-card-title">Severity Assessment</div>
            <div className="ai-card-body">{analysis.severity_explanation}</div>
          </div>
        )}
      </div>

      {/* Risk Factors */}
      {analysis.risk_factors && analysis.risk_factors.length > 0 && (
        <div className="ai-section">
          <div className="ai-card-title">Risk Factors</div>
          <div className="ai-factors-list">
            {analysis.risk_factors.map((f, i) => (
              <span key={i} className="ai-factor-chip">{f}</span>
            ))}
          </div>
        </div>
      )}

      {/* Potential Business Impact */}
      {analysis.potential_business_impact && analysis.potential_business_impact.length > 0 && (
        <div className="ai-section">
          <div className="ai-card-title">Potential Business Impact</div>
          <ul className="ai-bullet-list">
            {analysis.potential_business_impact.map((item, i) => <li key={i}>{item}</li>)}
          </ul>
        </div>
      )}

      {/* Remediation Steps — 3-tier */}
      {analysis.remediation && (
        <div className="ai-section">
          <div className="ai-card-title">Remediation Steps</div>
          <div className="ai-remediation-grid">
            {analysis.remediation.immediate_mitigation && analysis.remediation.immediate_mitigation.length > 0 && (
              <div className="ai-remediation-tier ai-tier-immediate">
                <div className="ai-tier-label">🔴 Immediate Mitigation</div>
                <ul className="ai-bullet-list">
                  {analysis.remediation.immediate_mitigation.map((s, i) => <li key={i}>{s}</li>)}
                </ul>
              </div>
            )}
            {analysis.remediation.permanent_remediation && analysis.remediation.permanent_remediation.length > 0 && (
              <div className="ai-remediation-tier ai-tier-permanent">
                <div className="ai-tier-label">🔵 Permanent Remediation</div>
                <ul className="ai-bullet-list">
                  {analysis.remediation.permanent_remediation.map((s, i) => <li key={i}>{s}</li>)}
                </ul>
              </div>
            )}
            {analysis.remediation.validation && analysis.remediation.validation.length > 0 && (
              <div className="ai-remediation-tier ai-tier-validation">
                <div className="ai-tier-label">✅ Validation Steps</div>
                <ul className="ai-bullet-list">
                  {analysis.remediation.validation.map((s, i) => <li key={i}>{s}</li>)}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Recommended Platform Controls */}
      {analysis.recommended_controls && analysis.recommended_controls.length > 0 && (
        <div className="ai-section">
          <div className="ai-card-title">Recommended Platform Controls</div>
          <div className="ai-controls-rec-list">
            {analysis.recommended_controls.map((ctrl, i) => (
              <div key={i} className="ai-control-rec">
                <span className="ai-control-rec-name">{ctrl.name}</span>
                <span className="ai-control-rec-reason">{ctrl.reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      {analysis.recommendation && analysis.recommendation.length > 0 && (
        <div className="ai-section">
          <div className="ai-card-title">Recommendations</div>
          <ul className="ai-bullet-list">
            {analysis.recommendation.map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </div>
      )}

      {/* AI Disclaimer — always shown */}
      <div className="ai-disclaimer">
        <span className="info-icon">ℹ️</span>
        <span>
          <strong>AI Advisory Only:</strong> This output is supplementary intelligence and does not
          modify official GRC risk scores. The rule-based risk engine remains the authoritative source
          for inherent/residual risk ratings, likelihood, impact, treatment, and status.
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Phase 2: Security Overview Sub-Components
// ---------------------------------------------------------------------------

function RiskDistribution({ risks }) {
  if (!risks || risks.length === 0) {
    return (
      <div className="overview-widget">
        <div className="overview-widget-header">
          <div className="overview-widget-title">
            <span>⚖️</span> Risk Severity Distribution
          </div>
          <span className="overview-widget-subtitle">Risk Register</span>
        </div>
        <div className="overview-empty">
          <span className="overview-empty-icon">🛡️</span>
          No registered risks in the risk register.
        </div>
      </div>
    );
  }

  const total = risks.length;
  const critical = risks.filter(r => (r.inherent_risk_level || r.risk_level || "").toLowerCase() === "critical").length;
  const high = risks.filter(r => (r.inherent_risk_level || r.risk_level || "").toLowerCase() === "high").length;
  const medium = risks.filter(r => (r.inherent_risk_level || r.risk_level || "").toLowerCase() === "medium").length;
  const low = risks.filter(r => (r.inherent_risk_level || r.risk_level || "").toLowerCase() === "low").length;

  const pct = (cnt) => (total > 0 ? ((cnt / total) * 100).toFixed(1) : "0.0");
  const openCount = risks.filter(r => r.status === "Open").length;
  const resolvedCount = risks.filter(r => r.status === "Resolved").length;

  return (
    <div className="overview-widget">
      <div className="overview-widget-header">
        <div className="overview-widget-title">
          <span>⚖️</span> Risk Severity Distribution
        </div>
        <span className="overview-widget-subtitle">{total} Registered Risks</span>
      </div>

      {/* Segmented proportional bar */}
      <div className="segmented-bar" title={`Critical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low}`}>
        {critical > 0 && <div className="segmented-segment critical" style={{ width: `${pct(critical)}%` }} />}
        {high > 0 && <div className="segmented-segment high" style={{ width: `${pct(high)}%` }} />}
        {medium > 0 && <div className="segmented-segment medium" style={{ width: `${pct(medium)}%` }} />}
        {low > 0 && <div className="segmented-segment low" style={{ width: `${pct(low)}%` }} />}
      </div>

      <div className="breakdown-list">
        <div className="breakdown-row">
          <div className="breakdown-row-meta">
            <span className="breakdown-row-label">
              <span className="breakdown-dot critical" />
              Critical Risk
            </span>
            <div className="breakdown-row-counts">
              <span className="breakdown-count">{critical}</span>
              <span className="breakdown-pct">{pct(critical)}%</span>
            </div>
          </div>
          <div className="breakdown-bar-track">
            <div className="breakdown-bar-fill critical" style={{ width: `${pct(critical)}%` }} />
          </div>
        </div>

        <div className="breakdown-row">
          <div className="breakdown-row-meta">
            <span className="breakdown-row-label">
              <span className="breakdown-dot high" />
              High Risk
            </span>
            <div className="breakdown-row-counts">
              <span className="breakdown-count">{high}</span>
              <span className="breakdown-pct">{pct(high)}%</span>
            </div>
          </div>
          <div className="breakdown-bar-track">
            <div className="breakdown-bar-fill high" style={{ width: `${pct(high)}%` }} />
          </div>
        </div>

        <div className="breakdown-row">
          <div className="breakdown-row-meta">
            <span className="breakdown-row-label">
              <span className="breakdown-dot medium" />
              Medium Risk
            </span>
            <div className="breakdown-row-counts">
              <span className="breakdown-count">{medium}</span>
              <span className="breakdown-pct">{pct(medium)}%</span>
            </div>
          </div>
          <div className="breakdown-bar-track">
            <div className="breakdown-bar-fill medium" style={{ width: `${pct(medium)}%` }} />
          </div>
        </div>

        <div className="breakdown-row">
          <div className="breakdown-row-meta">
            <span className="breakdown-row-label">
              <span className="breakdown-dot low" />
              Low Risk
            </span>
            <div className="breakdown-row-counts">
              <span className="breakdown-count">{low}</span>
              <span className="breakdown-pct">{pct(low)}%</span>
            </div>
          </div>
          <div className="breakdown-bar-track">
            <div className="breakdown-bar-fill low" style={{ width: `${pct(low)}%` }} />
          </div>
        </div>
      </div>

      <div className="overview-widget-footer">
        <span>Lifecycle: {openCount} Open • {resolvedCount} Resolved</span>
        <span>Authoritative GRC Matrix</span>
      </div>
    </div>
  );
}

function VulnerabilityDistribution({ vulnerabilities }) {
  if (!vulnerabilities || vulnerabilities.length === 0) {
    return (
      <div className="overview-widget">
        <div className="overview-widget-header">
          <div className="overview-widget-title">
            <span>🎯</span> Vulnerability Severity Distribution
          </div>
          <span className="overview-widget-subtitle">Technical Findings</span>
        </div>
        <div className="overview-empty">
          <span className="overview-empty-icon">🔍</span>
          No vulnerability findings available.
        </div>
      </div>
    );
  }

  const total = vulnerabilities.length;
  const critical = vulnerabilities.filter(v => (v.severity || "").toLowerCase() === "critical").length;
  const high = vulnerabilities.filter(v => (v.severity || "").toLowerCase() === "high").length;
  const medium = vulnerabilities.filter(v => (v.severity || "").toLowerCase() === "medium").length;
  const low = vulnerabilities.filter(v => (v.severity || "").toLowerCase() === "low").length;

  const pct = (cnt) => (total > 0 ? ((cnt / total) * 100).toFixed(1) : "0.0");

  return (
    <div className="overview-widget">
      <div className="overview-widget-header">
        <div className="overview-widget-title">
          <span>🎯</span> Vulnerability Severity Distribution
        </div>
        <span className="overview-widget-subtitle">{total} Total Findings</span>
      </div>

      {/* Segmented proportional bar */}
      <div className="segmented-bar" title={`Critical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low}`}>
        {critical > 0 && <div className="segmented-segment critical" style={{ width: `${pct(critical)}%` }} />}
        {high > 0 && <div className="segmented-segment high" style={{ width: `${pct(high)}%` }} />}
        {medium > 0 && <div className="segmented-segment medium" style={{ width: `${pct(medium)}%` }} />}
        {low > 0 && <div className="segmented-segment low" style={{ width: `${pct(low)}%` }} />}
      </div>

      <div className="breakdown-list">
        <div className="breakdown-row">
          <div className="breakdown-row-meta">
            <span className="breakdown-row-label">
              <span className="breakdown-dot critical" />
              Critical (CVSS 9.0–10.0)
            </span>
            <div className="breakdown-row-counts">
              <span className="breakdown-count">{critical}</span>
              <span className="breakdown-pct">{pct(critical)}%</span>
            </div>
          </div>
          <div className="breakdown-bar-track">
            <div className="breakdown-bar-fill critical" style={{ width: `${pct(critical)}%` }} />
          </div>
        </div>

        <div className="breakdown-row">
          <div className="breakdown-row-meta">
            <span className="breakdown-row-label">
              <span className="breakdown-dot high" />
              High (CVSS 7.0–8.9)
            </span>
            <div className="breakdown-row-counts">
              <span className="breakdown-count">{high}</span>
              <span className="breakdown-pct">{pct(high)}%</span>
            </div>
          </div>
          <div className="breakdown-bar-track">
            <div className="breakdown-bar-fill high" style={{ width: `${pct(high)}%` }} />
          </div>
        </div>

        <div className="breakdown-row">
          <div className="breakdown-row-meta">
            <span className="breakdown-row-label">
              <span className="breakdown-dot medium" />
              Medium (CVSS 4.0–6.9)
            </span>
            <div className="breakdown-row-counts">
              <span className="breakdown-count">{medium}</span>
              <span className="breakdown-pct">{pct(medium)}%</span>
            </div>
          </div>
          <div className="breakdown-bar-track">
            <div className="breakdown-bar-fill medium" style={{ width: `${pct(medium)}%` }} />
          </div>
        </div>

        <div className="breakdown-row">
          <div className="breakdown-row-meta">
            <span className="breakdown-row-label">
              <span className="breakdown-dot low" />
              Low (CVSS 0.1–3.9)
            </span>
            <div className="breakdown-row-counts">
              <span className="breakdown-count">{low}</span>
              <span className="breakdown-pct">{pct(low)}%</span>
            </div>
          </div>
          <div className="breakdown-bar-track">
            <div className="breakdown-bar-fill low" style={{ width: `${pct(low)}%` }} />
          </div>
        </div>
      </div>

      <div className="overview-widget-footer">
        <span>Technical vulnerability findings by severity</span>
        <span>NVD / NIST CVSS v3.1</span>
      </div>
    </div>
  );
}

function RiskHeatMap({ risks }) {
  const [selectedCell, setSelectedCell] = useState(null);

  if (!risks || risks.length === 0) {
    return (
      <div className="overview-widget">
        <div className="overview-widget-header">
          <div className="overview-widget-title">
            <span>🗺️</span> Risk Heat Map (4×4 Matrix)
          </div>
          <span className="overview-widget-subtitle">Likelihood × Impact</span>
        </div>
        <div className="overview-empty">
          <span className="overview-empty-icon">📊</span>
          No risk data available to plot heat map.
        </div>
      </div>
    );
  }

  // Model: Likelihood 1–4, Impact 1–4
  // Y-axis: Likelihood rows from 4 (Frequent) down to 1 (Rare)
  // X-axis: Impact columns from 1 (Low) up to 4 (Critical)
  const likelihoodLevels = [
    { level: 4, label: "4 — Frequent" },
    { level: 3, label: "3 — Likely" },
    { level: 2, label: "2 — Possible" },
    { level: 1, label: "1 — Rare" },
  ];

  const impactLevels = [
    { level: 1, label: "1 — Low" },
    { level: 2, label: "2 — Moderate" },
    { level: 3, label: "3 — Major" },
    { level: 4, label: "4 — Critical" },
  ];

  const parseScore = (val) => {
    if (val === null || val === undefined || val === "") return null;
    const num = Number(val);
    return Number.isInteger(num) && num >= 1 && num <= 4 ? num : null;
  };

  const getValidLikelihood = (r) => {
    const val = r.likelihood_score !== undefined && r.likelihood_score !== null ? r.likelihood_score : r.likelihood;
    return parseScore(val);
  };

  const getValidImpact = (r) => {
    const val = r.impact_score !== undefined && r.impact_score !== null ? r.impact_score : r.impact;
    return parseScore(val);
  };

  const plottableRisks = risks.filter((r) => getValidLikelihood(r) !== null && getValidImpact(r) !== null);
  const excludedCount = risks.length - plottableRisks.length;

  const getCellSeverityClass = (score) => {
    if (score >= 12) return "heatmap-cell-critical";
    if (score >= 7) return "heatmap-cell-high";
    if (score >= 4) return "heatmap-cell-medium";
    return "heatmap-cell-low";
  };

  const getCellRisks = (l, i) => {
    return plottableRisks.filter((r) => getValidLikelihood(r) === l && getValidImpact(r) === i);
  };

  const getBadgeClass = (lvl) => {
    switch (lvl?.toLowerCase()) {
      case "critical": return "badge-critical";
      case "high": return "badge-high";
      case "medium": return "badge-medium";
      case "low": return "badge-low";
      default: return "badge-neutral";
    }
  };

  const selectedCellRisks = selectedCell ? getCellRisks(selectedCell.l, selectedCell.i) : [];
  const selectedScore = selectedCell ? selectedCell.l * selectedCell.i : 0;
  const selectedLhObj = selectedCell ? likelihoodLevels.find((l) => l.level === selectedCell.l) : null;
  const selectedImpObj = selectedCell ? impactLevels.find((i) => i.level === selectedCell.i) : null;

  return (
    <div className="overview-widget">
      <div className="overview-widget-header">
        <div className="overview-widget-title">
          <span>🗺️</span> Risk Heat Map (4×4 Matrix)
        </div>
        <span className="overview-widget-subtitle">
          {plottableRisks.length} Plotted / {risks.length} Total Risks
        </span>
      </div>

      <div className="heatmap-container">
        <div className="heatmap-layout">
          <div className="heatmap-y-axis">
            <span className="heatmap-y-label">LIKELIHOOD</span>
          </div>

          <div className="heatmap-matrix-wrap">
            <div className="heatmap-grid">
              {/* Top-left empty corner */}
              <div className="heatmap-header-cell" />
              {impactLevels.map((imp) => (
                <div key={imp.level} className="heatmap-header-cell">
                  {imp.label}
                </div>
              ))}

              {/* Rows */}
              {likelihoodLevels.map((lh) => (
                <Fragment key={lh.level}>
                  <div className="heatmap-row-header">{lh.label}</div>
                  {impactLevels.map((imp) => {
                    const cellRisks = getCellRisks(lh.level, imp.level);
                    const count = cellRisks.length;
                    const score = lh.level * imp.level;
                    const sevClass = getCellSeverityClass(score);
                    const isSelected = selectedCell?.l === lh.level && selectedCell?.i === imp.level;

                    return (
                      <div
                        key={`${lh.level}-${imp.level}`}
                        className={`heatmap-cell ${sevClass} ${count > 0 ? "active" : "empty"}${isSelected ? " selected" : ""}`}
                        onClick={() =>
                          setSelectedCell(isSelected ? null : { l: lh.level, i: imp.level })
                        }
                        role="button"
                        tabIndex={0}
                        aria-label={`Likelihood ${lh.level}, Impact ${imp.level}, Score ${score}, ${count} risks`}
                      >
                        <span className="heatmap-cell-val">
                          {count} {count === 1 ? "Risk" : "Risks"}
                        </span>
                        <span className="heatmap-cell-coord">
                          L{lh.level} × I{imp.level}
                        </span>
                        <span className="heatmap-cell-score">
                          Score {score}
                        </span>
                      </div>
                    );
                  })}
                </Fragment>
              ))}
            </div>

            <div className="heatmap-x-label">IMPACT</div>
          </div>
        </div>

        <div className="heatmap-legend">
          <span className="heatmap-legend-item">
            <span className="heatmap-legend-chip" style={{ background: "#22c55e" }} />
            <strong>Low</strong> (1–3)
          </span>
          <span className="heatmap-legend-item">
            <span className="heatmap-legend-chip" style={{ background: "#eab308" }} />
            <strong>Medium</strong> (4–6)
          </span>
          <span className="heatmap-legend-item">
            <span className="heatmap-legend-chip" style={{ background: "#f97316" }} />
            <strong>High</strong> (7–11)
          </span>
          <span className="heatmap-legend-item">
            <span className="heatmap-legend-chip" style={{ background: "#ef4444" }} />
            <strong>Critical</strong> (12–16)
          </span>
        </div>

        {excludedCount > 0 && (
          <div className="heatmap-excluded-note">
            * {excludedCount} {excludedCount === 1 ? "risk" : "risks"} excluded from heat map due to missing likelihood/impact scoring.
          </div>
        )}

        {/* Selected Cell Inspector */}
        {selectedCell && (
          <div className="heatmap-inspector" style={{ marginTop: "12px" }}>
            <div className="heatmap-inspector-header">
              <div className="heatmap-inspector-title">
                Likelihood: {selectedCell.l} ({selectedLhObj ? selectedLhObj.label.split(" — ")[1] : selectedCell.l}) • Impact: {selectedCell.i} ({selectedImpObj ? selectedImpObj.label.split(" — ")[1] : selectedCell.i}) • Score: {selectedScore} • Risks in this cell: {selectedCellRisks.length}
              </div>
              <button
                type="button"
                className="btn-secondary btn-sm"
                onClick={() => setSelectedCell(null)}
              >
                Clear Selection
              </button>
            </div>

            {selectedCellRisks.length === 0 ? (
              <div className="empty-cell" style={{ textAlign: "center", padding: "12px", fontSize: "12px" }}>
                No plotted risks located at these coordinates.
              </div>
            ) : (
              <div className="heatmap-cell-risk-list">
                {selectedCellRisks.map((r) => (
                  <div key={r.id} className="heatmap-cell-risk-row">
                    <span className="font-mono text-xs text-slate">#{r.id}</span>
                    <span className="heatmap-cell-risk-title">{r.title}</span>
                    <span className={`badge ${getBadgeClass(r.inherent_risk_level || r.risk_level)}`}>
                      {r.inherent_risk_level || r.risk_level || "Medium"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ComplianceCoverageWidget({ complianceSummary, requirements }) {
  let displaySummaries = complianceSummary;

  if ((!displaySummaries || displaySummaries.length === 0) && requirements && requirements.length > 0) {
    const fwNames = Array.from(new Set(requirements.map(r => r.framework_name).filter(Boolean)));
    displaySummaries = fwNames.map((name, idx) => {
      const fwReqs = requirements.filter(r => r.framework_name === name);
      const total = fwReqs.length;
      const implemented = fwReqs.filter(r => r.status === "Implemented").length;
      const partially_implemented = fwReqs.filter(r => r.status === "Partially Implemented").length;
      const not_implemented = fwReqs.filter(r => r.status === "Not Implemented").length;
      const not_assessed = fwReqs.filter(r => r.status === "Not Assessed" || !r.status).length;
      const not_applicable = fwReqs.filter(r => r.status === "Not Applicable").length;
      const applicable = total - not_applicable;
      const coverage = applicable > 0 ? Number((((implemented + 0.5 * partially_implemented) / applicable) * 100).toFixed(1)) : 0.0;
      return {
        framework_id: idx + 1,
        framework_name: name,
        total_requirements: total,
        implemented,
        partially_implemented,
        not_implemented,
        not_assessed,
        not_applicable,
        implementation_coverage: coverage,
      };
    });
  }

  if (!displaySummaries || displaySummaries.length === 0) {
    return (
      <div className="overview-widget">
        <div className="overview-widget-header">
          <div className="overview-widget-title">
            <span>📜</span> Compliance Implementation Coverage
          </div>
          <span className="overview-widget-subtitle">Regulatory Frameworks</span>
        </div>
        <div className="overview-empty">
          <span className="overview-empty-icon">📜</span>
          No compliance framework data available.
        </div>
      </div>
    );
  }

  return (
    <div className="overview-widget">
      <div className="overview-widget-header">
        <div className="overview-widget-title">
          <span>📜</span> Compliance Implementation Coverage
        </div>
        <span className="overview-widget-subtitle">Framework Controls Posture</span>
      </div>

      <div className="compliance-framework-grid">
        {displaySummaries.map((fw) => {
          const total = fw.total_requirements || 1;
          const implPct = ((fw.implemented / total) * 100).toFixed(1);
          const partPct = ((fw.partially_implemented / total) * 100).toFixed(1);
          const notImplPct = ((fw.not_implemented / total) * 100).toFixed(1);
          const notAssessedPct = ((fw.not_assessed / total) * 100).toFixed(1);
          const naPct = ((fw.not_applicable / total) * 100).toFixed(1);

          return (
            <div key={fw.framework_id || fw.framework_name} className="compliance-fw-card">
              <div className="compliance-fw-header">
                <div>
                  <span className="compliance-fw-title">{fw.framework_name}</span>
                  {fw.framework_version && (
                    <span className="compliance-fw-version">v{fw.framework_version}</span>
                  )}
                </div>
                <span className="compliance-fw-pct">
                  {fw.implementation_coverage}% <span style={{ fontSize: "11px", fontWeight: "normal", color: "#94a3b8" }}>Coverage</span>
                </span>
              </div>

              {/* Multi-segment progress bar */}
              <div
                className="compliance-progress-bar"
                title={`Implemented: ${fw.implemented}, Partially: ${fw.partially_implemented}, Not Implemented: ${fw.not_implemented}, Not Assessed: ${fw.not_assessed}, N/A: ${fw.not_applicable}`}
              >
                {fw.implemented > 0 && (
                  <div className="compliance-seg-implemented" style={{ width: `${implPct}%` }} />
                )}
                {fw.partially_implemented > 0 && (
                  <div className="compliance-seg-partial" style={{ width: `${partPct}%` }} />
                )}
                {fw.not_implemented > 0 && (
                  <div className="compliance-seg-not-impl" style={{ width: `${notImplPct}%` }} />
                )}
                {fw.not_assessed > 0 && (
                  <div className="compliance-seg-not-assessed" style={{ width: `${notAssessedPct}%` }} />
                )}
                {fw.not_applicable > 0 && (
                  <div className="compliance-seg-na" style={{ width: `${naPct}%` }} />
                )}
              </div>

              <div className="compliance-counts-row">
                <span className="compliance-count-pill">
                  <span className="breakdown-dot low" /> Implemented: <strong>{fw.implemented}</strong>
                </span>
                <span className="compliance-count-pill">
                  <span className="breakdown-dot medium" /> Partially: <strong>{fw.partially_implemented}</strong>
                </span>
                <span className="compliance-count-pill">
                  <span className="breakdown-dot critical" /> Not Implemented: <strong>{fw.not_implemented}</strong>
                </span>
                <span className="compliance-count-pill">
                  <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#64748b" }} /> Not Assessed: <strong>{fw.not_assessed}</strong>
                </span>
                {fw.not_applicable > 0 && (
                  <span className="compliance-count-pill">
                    <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#334155" }} /> N/A: <strong>{fw.not_applicable}</strong>
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <div className="compliance-disclaimer-note">
        * Implementation Coverage is an internal GRC tracking metric for evaluated baseline requirements and does not constitute formal regulatory certification.
      </div>
    </div>
  );
}

function RecentSecurityActivity({ auditLogs, driftEvents, monitoringJobs, govReviews }) {
  // Aggregate real events from existing feeds
  const activities = [];

  (auditLogs || []).forEach((log) => {
    activities.push({
      id: `audit-${log.id}`,
      timestamp: log.timestamp,
      title: log.action ? log.action.replace(/_/g, " ") : "Audit Action",
      category: log.resource_type || "System",
      desc: log.actor ? `Actor: ${log.actor}` : "System event",
      icon: "📋",
      badge: log.action,
    });
  });

  (driftEvents || []).forEach((ev) => {
    activities.push({
      id: `drift-${ev.id}`,
      timestamp: ev.detected_at,
      title: `Drift: ${ev.event_type || "Attack Surface Change"}`,
      category: "Monitoring",
      desc: ev.details?.message || ev.details?.summary || (ev.asset_ip ? `Asset ${ev.asset_ip}` : "Baseline delta"),
      icon: "🛰️",
      badge: ev.severity || "medium",
    });
  });

  (monitoringJobs || []).slice(0, 10).forEach((job) => {
    activities.push({
      id: `job-${job.id}`,
      timestamp: job.completed_at || job.created_at,
      title: `Scan Job #${job.id}: ${job.status}`,
      category: "Scanner",
      desc: `Target: ${job.target} • ${job.scan_type === "subnet_discovery" ? "Subnet Sweep" : "Single Host"}`,
      icon: "⚡",
      badge: job.status,
    });
  });

  (govReviews || []).forEach((item, idx) => {
    const r = item.risk || {};
    const rev = item.current_review;
    const ts = rev?.created_at || r.created_at;
    if (ts) {
      activities.push({
        id: `gov-${r.id || rev?.id || item.id || idx}-${ts}`,
        timestamp: ts,
        title: `Risk Review: ${rev?.decision || item.review_status || r.review_status || "Pending"}`,
        category: "Governance",
        desc: `Risk #${r.id || "—"} ${r.title ? `"${r.title}"` : ""} by ${rev?.reviewer_name || "Analyst"}`,
        icon: "✍️",
        badge: rev?.decision || item.review_status || "Review",
      });
    }
  });

  // Sort descending by timestamp, take top 6
  const sorted = activities
    .filter((a) => a.timestamp)
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 6);

  if (sorted.length === 0) {
    return (
      <div className="overview-widget">
        <div className="overview-widget-header">
          <div className="overview-widget-title">
            <span>⚡</span> Recent Audit & Security Activity
          </div>
          <span className="overview-widget-subtitle">Audit Trail, Drift Center, Scan Jobs & Governance</span>
        </div>
        <div className="overview-empty">
          <span className="overview-empty-icon">⏱️</span>
          No recent security activity recorded yet.
        </div>
      </div>
    );
  }

  return (
    <div className="overview-widget">
      <div className="overview-widget-header">
        <div className="overview-widget-title">
          <span>⚡</span> Recent Audit & Security Activity
        </div>
        <span className="overview-widget-subtitle">Recent events from Audit Trail, Drift Center, Scan Jobs & Governance</span>
      </div>

      <div className="activity-feed">
        {sorted.map((item) => (
          <div key={item.id} className="activity-item">
            <div className="activity-icon-wrap">{item.icon}</div>
            <div className="activity-content">
              <div className="activity-header">
                <span className="activity-title">{item.title}</span>
                <span className="activity-time">{formatDateTime(item.timestamp)}</span>
              </div>
              <div className="activity-desc">{item.desc}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="overview-widget-footer">
        <span>Recent events from Audit Trail, Drift Center, Scan Jobs & Governance</span>
        <span>Append-only chronological log</span>
      </div>
    </div>
  );
}

function AuthenticatedDashboard() {
  const {
    user,
    logout,
    permissionNotice,
    clearPermissionNotice,
    isReviewer,
  } = useAuth();
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [target, setTarget] = useState("192.168.127.1");

  const [assets, setAssets] = useState([]);
  const [risks, setRisks] = useState([]);
  const [controls, setControls] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);

  // Phase 3 & 6: Compliance State
  const [frameworks, setFrameworks] = useState([]);
  const [selectedFramework] = useState("NIST CSF");
  const [complianceSummary, setComplianceSummary] = useState([]);
  const [requirements, setRequirements] = useState([]);

  // Phase 6: Compliance Sub-tabs, Filters, Search & Details Modal State
  const [complianceSubTab, setComplianceSubTab] = useState("overview"); // "overview" | "nist" | "iso"
  const [complianceSearchQuery, setComplianceSearchQuery] = useState("");
  const [complianceFrameworkFilter, setComplianceFrameworkFilter] = useState("All");
  const [complianceStatusFilter, setComplianceStatusFilter] = useState("All");
  const [complianceFunctionFilter, setComplianceFunctionFilter] = useState("All");
  const [complianceStrengthFilter, setComplianceStrengthFilter] = useState("All");
  const [viewingRequirement, setViewingRequirement] = useState(null);

  // Phase 4B: AI Analysis State — per-risk keyed maps, isolated from authoritative GRC data
  const [aiAnalysis, setAiAnalysis] = useState({});          // { [riskId]: analysisObject }
  const [aiLoading, setAiLoading] = useState({});            // { [riskId]: boolean }
  const [aiError, setAiError] = useState({});                // { [riskId]: string | null }
  const [expandedAiPanel, setExpandedAiPanel] = useState(null); // riskId | null (one panel open at a time)

  // Phase 11: AI Copilot Drawer State
  const [showCopilotDrawer, setShowCopilotDrawer] = useState(false);
  const [copilotSelectedRiskId, setCopilotSelectedRiskId] = useState(null);
  const [copilotActiveSection, setCopilotActiveSection] = useState("all"); // "all" | "remediation" | "controls" | "impact"

  // Modals state
  const [editingAsset, setEditingAsset] = useState(null);
  const [viewingAsset, setViewingAsset] = useState(null);
  const [editingRisk, setEditingRisk] = useState(null);
  const [showAddControlModal, setShowAddControlModal] = useState(false);
  const [assigningRiskId, setAssigningRiskId] = useState(null);
  const [editingRequirement, setEditingRequirement] = useState(null);

  // Phase 3: Assets Page Filters & Search
  const [assetSearchQuery, setAssetSearchQuery] = useState("");
  const [assetEnvFilter, setAssetEnvFilter] = useState("All");
  const [assetCritFilter, setAssetCritFilter] = useState("All");
  const [assetExpFilter, setAssetExpFilter] = useState("All");

  // Phase 4: Vulnerabilities Page Filters, Search & Details Modal
  const [vulnSearchQuery, setVulnSearchQuery] = useState("");
  const [vulnSeverityFilter, setVulnSeverityFilter] = useState("All");
  const [vulnStatusFilter, setVulnStatusFilter] = useState("All");
  const [viewingVuln, setViewingVuln] = useState(null);

  // Phase 5: Risk Management Sub-tabs, Filters, Search, Heatmap & Details Modal
  const [riskSubTab, setRiskSubTab] = useState("register"); // "register" | "heatmap" | "controls"
  const [riskSearchQuery, setRiskSearchQuery] = useState("");
  const [riskLevelFilter, setRiskLevelFilter] = useState("All");
  const [riskStatusFilter, setRiskStatusFilter] = useState("All");
  const [riskTreatmentFilter, setRiskTreatmentFilter] = useState("All");
  const [riskReviewFilter, setRiskReviewFilter] = useState("All");
  const [viewingRisk, setViewingRisk] = useState(null);
  const [selectedHeatmapCell, setSelectedHeatmapCell] = useState(null); // { l: number, i: number } | null
  const [heatmapMatrixType, setHeatmapMatrixType] = useState("inherent"); // "inherent" | "residual"

  // Form states
  const [assetForm, setAssetForm] = useState({
    criticality: "Medium",
    environment: "Production",
    exposure: "Internal",
    owner: "",
    business_function: ""
  });

  const [riskForm, setRiskForm] = useState({
    treatment: "Mitigate",
    risk_owner: "",
    due_date: "",
    status: "Open"
  });

  const [controlForm, setControlForm] = useState({
    name: "",
    description: "",
    category: "Preventive",
    framework: "NIST CSF",
    effectiveness: "Medium",
    status: "Implemented"
  });

  const [requirementForm, setRequirementForm] = useState({
    status: "Not Assessed",
    notes: ""
  });

  // Selected control for assigning to risk
  const [selectedControlId, setSelectedControlId] = useState("");

  // ----------------------------------------
  // Phase 5: Continuous Monitoring State
  // ----------------------------------------
  const [monitoringJobs, setMonitoringJobs] = useState([]);
  const [monitoringJobsLoading, setMonitoringJobsLoading] = useState(false);
  const [monitoringJobsError, setMonitoringJobsError] = useState(null);
  const lastTerminalJobSigRef = useRef(null);

  const [monitoringSchedules, setMonitoringSchedules] = useState([]);
  const [monitoringSchedulesLoading, setMonitoringSchedulesLoading] = useState(false);
  const [monitoringSchedulesError, setMonitoringSchedulesError] = useState(null);

  const [driftEvents, setDriftEvents] = useState([]);
  const [driftEventsLoading, setDriftEventsLoading] = useState(false);
  const [driftEventsError, setDriftEventsError] = useState(null);
  const [driftTotal, setDriftTotal] = useState(0);
  const [driftSeverityFilter, setDriftSeverityFilter] = useState("All");
  const [driftTypeFilter, setDriftTypeFilter] = useState("All");
  const [driftLimit] = useState(20);
  const [driftOffset, setDriftOffset] = useState(0);

  const [monitoringActiveTab, setMonitoringActiveTab] = useState("jobs"); // "jobs" | "schedules" | "drift"
  const [monitoringJobStatusFilter, setMonitoringJobStatusFilter] = useState("All");

  // New Scan Job Trigger
  const [newJobTarget, setNewJobTarget] = useState("192.168.127.0/24");
  const [newJobType, setNewJobType] = useState("subnet_discovery");
  const [submittingJob, setSubmittingJob] = useState(false);
  const [jobActionError, setJobActionError] = useState(null);
  const [cancellingJobId, setCancellingJobId] = useState(null);

  // Schedule Modal / Form
  const [showScheduleModal, setShowScheduleModal] = useState(false);
  const [editingSchedule, setEditingSchedule] = useState(null);
  const [scheduleForm, setScheduleForm] = useState({
    name: "",
    target: "192.168.127.0/24",
    interval_minutes: 60,
  });
  const [scheduleActionError, setScheduleActionError] = useState(null);
  const [submittingSchedule, setSubmittingSchedule] = useState(false);

  // ----------------------------------------
  // Governance & Review Queue State
  // ----------------------------------------

  // 1. Governance Review Queue
  const [govReviews, setGovReviews] = useState([]);
  const [govReviewsLoading, setGovReviewsLoading] = useState(false);
  const [govReviewsError, setGovReviewsError] = useState(null);

  // Phase 8: Reviews & Sign-off State
  const [reviewsSubTab, setReviewsSubTab] = useState("queue"); // "queue" | "all"
  const [reviewsSearchQuery, setReviewsSearchQuery] = useState("");
  const [reviewsStatusFilter, setReviewsStatusFilter] = useState("All");
  const [reviewsLevelFilter, setReviewsLevelFilter] = useState("All");
  const [reviewsTreatmentFilter, setReviewsTreatmentFilter] = useState("All");

  // 2. Audit Trail
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState(null);
  const [auditLimit, setAuditLimit] = useState(25);
  const [auditOffset, setAuditOffset] = useState(0);
  const [auditSourceFilter, setAuditSourceFilter] = useState("All");
  const [auditActionFilter, setAuditActionFilter] = useState("All");
  const [auditEntityFilter, setAuditEntityFilter] = useState("All");
  const [auditSearchQuery, setAuditSearchQuery] = useState("");

  // Audit Detail Modal State (Phase 9)
  const [viewingAuditLog, setViewingAuditLog] = useState(null);
  const [auditDetailLoading, setAuditDetailLoading] = useState(false);
  const [auditDetailError, setAuditDetailError] = useState(null);
  const [hashCopied, setHashCopied] = useState(false);

  // 3. Review Submission Modal State
  const [reviewingRisk, setReviewingRisk] = useState(null);
  const [reviewForm, setReviewForm] = useState({
    reviewer_name: user?.display_name || user?.username || "Security Analyst",
    reviewer_role: user?.role || "GRC Operator",
    decision: "APPROVED",
    agreed_treatment: "Mitigate",
    comments: "",
    ai_analysis_acknowledged: false,
  });

  useEffect(() => {
    if (user) {
      setReviewForm((prev) => ({
        ...prev,
        reviewer_name: user.display_name || user.username || "Security Analyst",
        reviewer_role: user.role || "GRC Operator",
      }));
    }
  }, [user]);
  const [submittingReview, setSubmittingReview] = useState(false);
  const [reviewSubmitError, setReviewSubmitError] = useState(null);

  // 4. Review History Modal State
  const [historyRisk, setHistoryRisk] = useState(null);
  const [historyData, setHistoryData] = useState(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState(null);

  // 5. Reports Export Center State
  const [downloadingReport, setDownloadingReport] = useState(null); // { type, format } | null
  const [reportDownloadError, setReportDownloadError] = useState(null);
  const [reportSearchQuery, setReportSearchQuery] = useState("");
  const [reportCategoryFilter, setReportCategoryFilter] = useState("ALL");
  const [lastExportedReport, setLastExportedReport] = useState(null); // { filename, reportType, format, timestamp } | null

  // ----------------------------------------
  // Navigation State
  // ----------------------------------------
  const [activePage, setActivePage] = useState("overview");

  // ----------------------------------------
  // Data Fetching Functions
  // ----------------------------------------

  const fetchAssets = async () => {
    try {
      const response = await authFetch(`${API_BASE}/assets`);
      if (response.ok) {
        const data = await response.json();
        setAssets(data.assets || []);
      }
    } catch (error) {
      console.error("Unable to fetch asset inventory:", error);
    }
  };

  const fetchRisks = async () => {
    try {
      const response = await authFetch(`${API_BASE}/risks`);
      if (response.ok) {
        const data = await response.json();
        setRisks(data.risks || []);
      }
    } catch (error) {
      console.error("Unable to fetch risk register:", error);
    }
  };

  const fetchControls = async () => {
    try {
      const response = await authFetch(`${API_BASE}/controls`);
      if (response.ok) {
        const data = await response.json();
        setControls(data.controls || []);
      }
    } catch (error) {
      console.error("Unable to fetch controls catalog:", error);
    }
  };

  const fetchVulnerabilities = async () => {
    try {
      const response = await authFetch(`${API_BASE}/vulnerabilities`);
      if (response.ok) {
        const data = await response.json();
        setVulnerabilities(data.vulnerabilities || []);
      }
    } catch (error) {
      console.error("Unable to fetch vulnerability findings:", error);
    }
  };

  const fetchComplianceFrameworks = async () => {
    try {
      const response = await authFetch(`${API_BASE}/compliance/frameworks`);
      if (response.ok) {
        const data = await response.json();
        setFrameworks(data.frameworks || []);
      }
    } catch (error) {
      console.error("Unable to fetch compliance frameworks:", error);
    }
  };

  const fetchComplianceSummary = async () => {
    try {
      const response = await authFetch(`${API_BASE}/compliance/summary`);
      if (response.ok) {
        const data = await response.json();
        setComplianceSummary(data.summary || []);
      }
    } catch (error) {
      console.error("Unable to fetch compliance summary:", error);
    }
  };

  const fetchComplianceRequirements = async () => {
    try {
      const response = await authFetch(`${API_BASE}/compliance/requirements`);
      if (response.ok) {
        const data = await response.json();
        setRequirements(data.requirements || []);
      }
    } catch (error) {
      console.error("Unable to fetch compliance requirements:", error);
    }
  };

  // ----------------------------------------
  // Phase 5: Continuous Monitoring Fetchers & Handlers
  // ----------------------------------------

  const fetchMonitoringJobs = async () => {
    setMonitoringJobsLoading(true);
    try {
      const response = await authFetch(`${API_BASE}/monitoring/jobs?limit=50&offset=0`);
      if (response.ok) {
        const data = await response.json();
        setMonitoringJobs(data.jobs || []);
        setMonitoringJobsError(null);
        return data.jobs || [];
      } else {
        const err = await response.json().catch(() => null);
        setMonitoringJobsError(err?.detail || "Failed to load scan jobs");
      }
    } catch {
      setMonitoringJobsError("Unable to connect to monitoring service");
    } finally {
      setMonitoringJobsLoading(false);
    }
    return [];
  };

  const fetchMonitoringSchedules = async () => {
    setMonitoringSchedulesLoading(true);
    try {
      const response = await authFetch(`${API_BASE}/monitoring/schedules`);
      if (response.ok) {
        const data = await response.json();
        setMonitoringSchedules(data.schedules || []);
        setMonitoringSchedulesError(null);
      } else {
        const err = await response.json().catch(() => null);
        setMonitoringSchedulesError(err?.detail || "Failed to load scan schedules");
      }
    } catch {
      setMonitoringSchedulesError("Unable to connect to schedules service");
    } finally {
      setMonitoringSchedulesLoading(false);
    }
  };

  const fetchDriftEvents = async (customOffset = driftOffset, customSev = driftSeverityFilter, customType = driftTypeFilter) => {
    setDriftEventsLoading(true);
    try {
      let url = `${API_BASE}/monitoring/drift?limit=${driftLimit}&offset=${customOffset}`;
      if (customSev && customSev !== "All") url += `&severity=${encodeURIComponent(customSev)}`;
      if (customType && customType !== "All") url += `&event_type=${encodeURIComponent(customType)}`;

      const response = await authFetch(url);
      if (response.ok) {
        const data = await response.json();
        setDriftEvents(data.events || []);
        setDriftTotal(data.total || 0);
        setDriftEventsError(null);
      } else {
        const err = await response.json().catch(() => null);
        setDriftEventsError(err?.detail || "Failed to load drift events");
      }
    } catch {
      setDriftEventsError("Unable to connect to drift feed service");
    } finally {
      setDriftEventsLoading(false);
    }
  };

  // ----------------------------------------
  // Phase 6: Governance Fetchers
  // ----------------------------------------

  const fetchGovReviews = async () => {
    setGovReviewsLoading(true);
    try {
      const response = await authFetch(`${API_BASE}/governance/reviews/pending?limit=200`);
      if (response.ok) {
        const data = await response.json();
        setGovReviews(data.risks || []);
        setGovReviewsError(null);
      } else {
        const err = await response.json().catch(() => null);
        setGovReviewsError(err?.detail || "Failed to load governance review queue");
      }
    } catch {
      setGovReviewsError("Unable to connect to governance review service");
    } finally {
      setGovReviewsLoading(false);
    }
  };

  const fetchAuditLogs = async (
    customOffset = auditOffset,
    customSource = auditSourceFilter,
    customAction = auditActionFilter,
    customEntity = auditEntityFilter,
    customLimit = auditLimit
  ) => {
    if (!isReviewer) {
      setAuditLogs([]);
      setAuditTotal(0);
      return;
    }
    setAuditLoading(true);
    try {
      let url = `${API_BASE}/audit-logs?limit=${customLimit}&offset=${customOffset}`;
      if (customSource && customSource !== "All") {
        url += `&source=${encodeURIComponent(customSource)}`;
      }
      if (customAction && customAction !== "All") {
        url += `&action=${encodeURIComponent(customAction)}`;
      }
      if (customEntity && customEntity !== "All") {
        url += `&entity_type=${encodeURIComponent(customEntity)}`;
      }
      const response = await authFetch(url);
      if (response.ok) {
        const data = await response.json();
        setAuditLogs(data.logs || []);
        setAuditTotal(data.total || 0);
        setAuditError(null);
      } else {
        const err = await response.json().catch(() => null);
        setAuditError(err?.detail || "Failed to load audit logs");
      }
    } catch {
      setAuditError("Unable to connect to audit logging service");
    } finally {
      setAuditLoading(false);
    }
  };

  const openAuditDetailModal = async (log) => {
    setViewingAuditLog(log);
    setAuditDetailLoading(true);
    setAuditDetailError(null);
    setHashCopied(false);
    try {
      const response = await authFetch(`${API_BASE}/audit-logs/${log.id}`);
      if (response.ok) {
        const fullLog = await response.json();
        setViewingAuditLog(fullLog);
      } else {
        const err = await response.json().catch(() => null);
        setAuditDetailError(err?.detail || `Failed to fetch complete event details (Status ${response.status})`);
      }
    } catch (err) {
      setAuditDetailError(err.message || "Network error loading audit event details");
    } finally {
      setAuditDetailLoading(false);
    }
  };

  const copyIntegrityHash = (hash) => {
    if (!hash) return;
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(hash).then(() => {
        setHashCopied(true);
        setTimeout(() => setHashCopied(false), 2000);
      }).catch(() => {});
    }
  };

  // Phase 11 & 12: Universal Escape key handler — closes topmost open modal or drawer
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        if (showCopilotDrawer) { setShowCopilotDrawer(false); return; }
        if (viewingAuditLog) { setViewingAuditLog(null); return; }
        if (historyRisk) { setHistoryRisk(null); return; }
        if (reviewingRisk) { setReviewingRisk(null); return; }
        if (showScheduleModal) { setShowScheduleModal(false); return; }
        if (editingRequirement) { setEditingRequirement(null); return; }
        if (viewingRequirement) { setViewingRequirement(null); return; }
        if (showAddControlModal) { setShowAddControlModal(false); return; }
        if (editingRisk) { setEditingRisk(null); return; }
        if (editingAsset) { setEditingAsset(null); return; }
        if (viewingRisk) { setViewingRisk(null); return; }
        if (viewingVuln) { setViewingVuln(null); return; }
        if (viewingAsset) { setViewingAsset(null); return; }
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [
    showCopilotDrawer,
    viewingAuditLog,
    historyRisk,
    reviewingRisk,
    showScheduleModal,
    editingRequirement,
    viewingRequirement,
    showAddControlModal,
    editingRisk,
    editingAsset,
    viewingRisk,
    viewingVuln,
    viewingAsset,
  ]);

  const submitNewJob = async (e) => {
    if (e) e.preventDefault();
    setSubmittingJob(true);
    setJobActionError(null);
    try {
      const response = await authFetch(`${API_BASE}/monitoring/jobs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: newJobTarget.trim(),
          scan_type: newJobType,
        }),
      });
      const data = await response.json().catch(() => null);
      if (!response.ok) {
        setJobActionError(data?.detail || "Failed to queue scan job");
        return;
      }
      setMonitoringJobs((prev) => [data, ...prev.filter((j) => j.id !== data.id)]);
      fetchMonitoringJobs();
    } catch (error) {
      setJobActionError(error.message || "Failed to submit scan job");
    } finally {
      setSubmittingJob(false);
    }
  };

  const cancelJob = async (jobId) => {
    setCancellingJobId(jobId);
    setJobActionError(null);
    try {
      const response = await authFetch(`${API_BASE}/monitoring/jobs/${jobId}/cancel`, {
        method: "POST",
      });
      const data = await response.json().catch(() => null);
      if (!response.ok) {
        setJobActionError(data?.detail || `Failed to cancel job #${jobId}`);
        return;
      }
      await fetchMonitoringJobs();
    } catch (error) {
      setJobActionError(error.message || `Error cancelling job #${jobId}`);
    } finally {
      setCancellingJobId(null);
    }
  };

  const openAddScheduleModal = () => {
    setEditingSchedule(null);
    setScheduleForm({
      name: "",
      target: "192.168.127.0/24",
      interval_minutes: 60,
    });
    setScheduleActionError(null);
    setShowScheduleModal(true);
  };

  const openEditScheduleModal = (sched) => {
    setEditingSchedule(sched);
    setScheduleForm({
      name: sched.name,
      target: sched.target,
      interval_minutes: sched.interval_minutes,
    });
    setScheduleActionError(null);
    setShowScheduleModal(true);
  };

  const handleSaveSchedule = async (e) => {
    e.preventDefault();
    setSubmittingSchedule(true);
    setScheduleActionError(null);

    if (Number(scheduleForm.interval_minutes) < 15) {
      setScheduleActionError("Schedule interval must be at least 15 minutes");
      setSubmittingSchedule(false);
      return;
    }

    try {
      let response;
      if (editingSchedule) {
        response = await authFetch(`${API_BASE}/monitoring/schedules/${editingSchedule.id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: scheduleForm.name.trim(),
            target: scheduleForm.target.trim(),
            interval_minutes: Number(scheduleForm.interval_minutes),
          }),
        });
      } else {
        response = await authFetch(`${API_BASE}/monitoring/schedules`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: scheduleForm.name.trim(),
            target: scheduleForm.target.trim(),
            interval_minutes: Number(scheduleForm.interval_minutes),
          }),
        });
      }

      const data = await response.json().catch(() => null);
      if (!response.ok) {
        setScheduleActionError(data?.detail || "Failed to save scan schedule");
        return;
      }

      setShowScheduleModal(false);
      await fetchMonitoringSchedules();
    } catch (error) {
      setScheduleActionError(error.message || "Failed to save schedule");
    } finally {
      setSubmittingSchedule(false);
    }
  };

  const toggleScheduleActive = async (sched) => {
    try {
      const response = await authFetch(`${API_BASE}/monitoring/schedules/${sched.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ is_active: !sched.is_active }),
      });
      if (response.ok) {
        await fetchMonitoringSchedules();
      } else {
        const err = await response.json().catch(() => null);
        alert(err?.detail || "Failed to update schedule status");
      }
    } catch (error) {
      alert("Error updating schedule: " + error.message);
    }
  };

  const deleteSchedule = async (schedId) => {
    if (!window.confirm("Are you sure you want to delete this automated scan schedule?")) return;
    try {
      const response = await authFetch(`${API_BASE}/monitoring/schedules/${schedId}`, {
        method: "DELETE",
      });
      if (response.ok) {
        await fetchMonitoringSchedules();
      } else {
        const err = await response.json().catch(() => null);
        alert(err?.detail || "Failed to delete schedule");
      }
    } catch (error) {
      alert("Error deleting schedule: " + error.message);
    }
  };

  // formatDateTime is defined at module scope for reuse across all views

  const getJobStatusBadge = (status) => {
    switch (status) {
      case "Queued":
        return <span className="badge badge-queued"><span className="status-indicator-dot dot-amber" />Queued</span>;
      case "Running":
        return <span className="badge badge-running"><span className="status-indicator-dot dot-pulse" />Running</span>;
      case "Completed":
        return <span className="badge badge-low"><span className="status-indicator-dot dot-green" />Completed</span>;
      case "Failed":
        return <span className="badge badge-critical"><span className="status-indicator-dot dot-red" />Failed</span>;
      case "Cancelled":
        return <span className="badge badge-neutral"><span className="status-indicator-dot dot-gray" />Cancelled</span>;
      default:
        return <span className="badge badge-neutral">{status}</span>;
    }
  };

  const getDriftSeverityBadge = (severity) => {
    switch ((severity || "").toLowerCase()) {
      case "critical":
        return <span className="badge badge-critical">Critical</span>;
      case "high":
        return <span className="badge badge-high">High</span>;
      case "medium":
        return <span className="badge badge-medium">Medium</span>;
      case "low":
        return <span className="badge badge-low">Low</span>;
      default:
        return <span className="badge badge-neutral">{severity || "Info"}</span>;
    }
  };

  const getDriftEventTypeBadge = (type) => {
    switch (type) {
      case "NEW_ASSET":
        return <span className="badge badge-new-asset">New Asset</span>;
      case "PORT_OPENED":
        return <span className="badge badge-high">Port Opened</span>;
      case "PORT_CLOSED":
        return <span className="badge badge-neutral">Port Closed</span>;
      case "CVE_DETECTED":
        return <span className="badge badge-critical">CVE Detected</span>;
      case "FINDING_RESOLVED":
        return <span className="badge badge-low">Finding Cleared</span>;
      default:
        return <span className="badge badge-neutral">{type}</span>;
    }
  };

  const refreshAll = async () => {
    await Promise.all([
      fetchAssets(),
      fetchRisks(),
      fetchControls(),
      fetchVulnerabilities(),
      fetchComplianceFrameworks(),
      fetchComplianceSummary(),
      fetchComplianceRequirements(),
      fetchMonitoringJobs(),
      fetchMonitoringSchedules(),
      fetchDriftEvents(driftOffset, driftSeverityFilter, driftTypeFilter),
    ]);
  };

  useEffect(() => {
    refreshAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Phase 6: Dedicated initial load for Governance reviews and audit trail
  // Independent of Phase 5 adaptive polling and refreshAll()
  useEffect(() => {
    fetchGovReviews();
    fetchAuditLogs(0, "All", "All");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Adaptive polling for monitoring data (5s if active job; 30s otherwise)
  useEffect(() => {
    const hasActiveJobs = monitoringJobs.some(
      (job) => job.status === "Queued" || job.status === "Running"
    );
    const pollInterval = hasActiveJobs ? 5000 : 30000;

    const timer = setInterval(async () => {
      try {
        const res = await authFetch(`${API_BASE}/monitoring/jobs?limit=50&offset=0`);
        if (res.ok) {
          const data = await res.json();
          const newJobs = data.jobs || [];

          // Deterministically sort completed jobs by completed_at descending, with job ID tie-breaker
          const completedJobs = newJobs
            .filter((j) => j.status === "Completed")
            .sort((a, b) => {
              const timeA = a.completed_at ? new Date(a.completed_at).getTime() : 0;
              const timeB = b.completed_at ? new Date(b.completed_at).getTime() : 0;
              if (timeB !== timeA) {
                return timeB - timeA;
              }
              return (b.id || 0) - (a.id || 0);
            });

          const latestCompleted = completedJobs[0] || null;
          const terminalSig = latestCompleted
            ? `Completed-${latestCompleted.id}-${latestCompleted.completed_at || ""}`
            : null;

          const needsStateRefresh =
            terminalSig &&
            lastTerminalJobSigRef.current !== terminalSig;

          if (terminalSig) {
            lastTerminalJobSigRef.current = terminalSig;
          }

          setMonitoringJobs(newJobs);
          setMonitoringJobsError(null);

          if (needsStateRefresh) {
            fetchAssets();
            fetchVulnerabilities();
            fetchRisks();
            fetchDriftEvents(driftOffset, driftSeverityFilter, driftTypeFilter);
            fetchMonitoringSchedules();
          }
        }
      } catch {
        // network polling error handled gracefully
      }
    }, pollInterval);

    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [monitoringJobs, driftOffset, driftSeverityFilter, driftTypeFilter]);

  // Refresh assets, risks, and drift events when tab becomes visible
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        fetchAssets();
        fetchRisks();
        fetchDriftEvents(driftOffset, driftSeverityFilter, driftTypeFilter);
      }
    };

    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [driftOffset, driftSeverityFilter, driftTypeFilter]);

  // ----------------------------------------
  // Network Scanning
  // ----------------------------------------

  const runScan = async () => {
    setScanning(true);
    try {
      const response = await authFetch(
        `${API_BASE}/scan?target=${encodeURIComponent(target)}`,
        { method: "POST" }
      );
      const data = await response.json().catch(() => null);

      if (!response.ok) {
        const errorMessage = data?.detail || `Scan failed with status ${response.status}`;
        alert(errorMessage);
        return;
      }

      setResult(data);
      await refreshAll();
    } catch (error) {
      alert("Backend is not running. Please start FastAPI: " + (error?.message || ""));
    } finally {
      setScanning(false);
    }
  };

  // ----------------------------------------
  // Asset Intelligence Handlers
  // ----------------------------------------

  const openAssetModal = (asset) => {
    setEditingAsset(asset);
    setAssetForm({
      criticality: asset.criticality || "Medium",
      environment: asset.environment || "Production",
      exposure: asset.exposure || "Internal",
      owner: asset.owner || "",
      business_function: asset.business_function || ""
    });
  };

  const saveAsset = async () => {
    if (!editingAsset) return;
    try {
      const response = await authFetch(`${API_BASE}/assets/${editingAsset.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(assetForm)
      });
      if (response.ok) {
        setEditingAsset(null);
        await refreshAll();
      } else {
        const err = await response.json();
        alert(`Error updating asset: ${err?.detail || "Unknown error"}`);
      }
    } catch (error) {
      alert("Failed to update asset: " + error.message);
    }
  };

  // ----------------------------------------
  // Risk Register Handlers
  // ----------------------------------------

  const openRiskModal = (risk) => {
    setEditingRisk(risk);
    setRiskForm({
      treatment: risk.treatment || "Mitigate",
      risk_owner: risk.risk_owner || "",
      due_date: risk.due_date ? risk.due_date.substring(0, 10) : "",
      status: risk.status || "Open"
    });
  };

  const saveRisk = async () => {
    if (!editingRisk) return;
    try {
      const payload = {
        treatment: riskForm.treatment,
        risk_owner: riskForm.risk_owner,
        status: riskForm.status,
        due_date: riskForm.due_date ? new Date(riskForm.due_date).toISOString() : null
      };

      const response = await authFetch(`${API_BASE}/risks/${editingRisk.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      if (response.ok) {
        setEditingRisk(null);
        await refreshAll();
      } else {
        const err = await response.json();
        alert(`Error updating risk: ${err?.detail || "Unknown error"}`);
      }
    } catch (error) {
      alert("Failed to update risk: " + error.message);
    }
  };

  // ----------------------------------------
  // Control Assignment Handlers
  // ----------------------------------------

  const handleAssignControl = async (riskId) => {
    if (!selectedControlId) return;
    try {
      const response = await authFetch(`${API_BASE}/risks/${riskId}/controls/${selectedControlId}`, {
        method: "POST"
      });
      if (response.ok) {
        setAssigningRiskId(null);
        setSelectedControlId("");
        await refreshAll();
      } else {
        const err = await response.json();
        alert(`Error assigning control: ${err?.detail || "Unknown error"}`);
      }
    } catch (error) {
      alert("Failed to assign control: " + error.message);
    }
  };

  const handleDetachControl = async (riskId, controlId) => {
    try {
      const response = await authFetch(`${API_BASE}/risks/${riskId}/controls/${controlId}`, {
        method: "DELETE"
      });
      if (response.ok) {
        await refreshAll();
      } else {
        const err = await response.json();
        alert(`Error detaching control: ${err?.detail || "Unknown error"}`);
      }
    } catch (error) {
      alert("Failed to detach control: " + error.message);
    }
  };

  // ----------------------------------------
  // Add Control Catalog Handler
  // ----------------------------------------

  const saveNewControl = async () => {
    if (!controlForm.name.trim()) {
      alert("Control name is required");
      return;
    }
    try {
      const response = await authFetch(`${API_BASE}/controls`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(controlForm)
      });
      if (response.ok) {
        setShowAddControlModal(false);
        setControlForm({
          name: "",
          description: "",
          category: "Preventive",
          framework: "NIST CSF",
          effectiveness: "Medium",
          status: "Implemented"
        });
        await refreshAll();
      } else {
        const err = await response.json();
        alert(`Error creating control: ${err?.detail || "Unknown error"}`);
      }
    } catch (error) {
      alert("Failed to create control: " + error.message);
    }
  };

  // ----------------------------------------
  // Phase 3: Compliance Requirement Assessment Handlers
  // ----------------------------------------

  const openRequirementModal = (req) => {
    setEditingRequirement(req);
    setRequirementForm({
      status: req.status || "Not Assessed",
      notes: req.notes || ""
    });
  };

  const saveRequirementAssessment = async () => {
    if (!editingRequirement) return;
    try {
      const response = await authFetch(`${API_BASE}/compliance/requirements/${editingRequirement.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requirementForm)
      });
      if (response.ok) {
        setEditingRequirement(null);
        await Promise.all([fetchComplianceSummary(), fetchComplianceRequirements()]);
      } else {
        const err = await response.json();
        alert(`Error updating requirement: ${err?.detail || "Unknown error"}`);
      }
    } catch (error) {
      alert("Failed to update requirement assessment: " + error.message);
    }
  };

  // ----------------------------------------
  // Phase 4B: AI Analysis Handlers
  // GET-first (stored analysis) → POST-on-404 (trigger new analysis)
  // Never calls refreshAll() — AI state is isolated from GRC risk data.
  // ----------------------------------------

  const handleAnalyzeRisk = async (riskId, skipToggle = false) => {
    if (aiLoading[riskId]) return;
    setCopilotSelectedRiskId(riskId);
    // Toggle panel closed if already open for this risk (unless skipToggle is true)
    if (!skipToggle && expandedAiPanel === riskId) {
      setExpandedAiPanel(null);
      return;
    }
    // Open panel immediately; serve from cache if available
    setExpandedAiPanel(riskId);
    if (aiAnalysis[riskId]) return;

    // GET stored analysis first; fall back to POST (new analysis) on 404
    setAiLoading(prev => ({ ...prev, [riskId]: true }));
    setAiError(prev => ({ ...prev, [riskId]: null }));
    try {
      const getRes = await authFetch(`${API_BASE}/risks/${riskId}/analysis`);
      if (getRes.ok) {
        const data = await getRes.json();
        setAiAnalysis(prev => ({ ...prev, [riskId]: data.analysis }));
        return;
      }
      if (getRes.status === 404) {
        const postRes = await authFetch(`${API_BASE}/risks/${riskId}/analyze`, {
          method: "POST",
        });
        const postData = await postRes.json().catch(() => null);
        if (!postRes.ok) {
          setAiError(prev => ({ ...prev, [riskId]: postData?.detail || `Analysis failed (${postRes.status})` }));
        } else {
          setAiAnalysis(prev => ({ ...prev, [riskId]: postData.analysis }));
        }
      } else {
        const errData = await getRes.json().catch(() => null);
        setAiError(prev => ({ ...prev, [riskId]: errData?.detail || "Failed to load analysis" }));
      }
    } catch (err) {
      setAiError(prev => ({ ...prev, [riskId]: "Network error: " + (err?.message || String(err)) }));
    } finally {
      setAiLoading(prev => ({ ...prev, [riskId]: false }));
    }
  };

  const handleReanalyzeRisk = async (riskId) => {
    if (aiLoading[riskId]) return;
    // Always force a fresh POST, replacing any cached analysis
    setAiLoading(prev => ({ ...prev, [riskId]: true }));
    setAiError(prev => ({ ...prev, [riskId]: null }));
    setAiAnalysis(prev => { const n = { ...prev }; delete n[riskId]; return n; });
    try {
      const res = await authFetch(`${API_BASE}/risks/${riskId}/analyze`, {
        method: "POST",
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        setAiError(prev => ({ ...prev, [riskId]: data?.detail || `Analysis failed (${res.status})` }));
      } else {
        setAiAnalysis(prev => ({ ...prev, [riskId]: data.analysis }));
      }
    } catch (err) {
      setAiError(prev => ({ ...prev, [riskId]: "Network error: " + (err?.message || String(err)) }));
    } finally {
      setAiLoading(prev => ({ ...prev, [riskId]: false }));
    }
  };

  // ----------------------------------------
  // Helper classes & formatters
  // ----------------------------------------

  const isAssetUnclassified = (asset) => {
    if (!asset) return false;
    if (!asset.criticality) return true;
    const crit = String(asset.criticality).trim().toLowerCase();
    if (crit === "unclassified" || crit === "none") return true;
    if (asset.is_criticality_default === true) return true;
    return false;
  };

  const parsePortsList = (openPortsStr) => {
    if (!openPortsStr || typeof openPortsStr !== "string") return [];
    return openPortsStr
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
  };

  const getRiskClass = (level) => {
    switch (level?.toLowerCase()) {
      case "critical":
        return "badge-critical";
      case "high":
        return "badge-high";
      case "medium":
        return "badge-medium";
      case "low":
        return "badge-low";
      default:
        return "badge-neutral";
    }
  };

  const getStatusClass = (status) => {
    switch (status?.toLowerCase()) {
      case "open":
        return "status-open";
      case "resolved":
        return "status-resolved";
      case "accepted":
        return "status-accepted";
      case "under review":
        return "status-review";
      default:
        return "status-neutral";
    }
  };

  const getComplianceStatusClass = (status) => {
    switch (status) {
      case "Implemented":
        return "badge-low";
      case "Partially Implemented":
        return "badge-medium";
      case "Not Implemented":
        return "badge-critical";
      case "Not Applicable":
        return "badge-na";
      case "Not Assessed":
      default:
        return "badge-neutral";
    }
  };

  // Compliance summary metrics for the Overview page
  const currentFwRequirements = requirements.filter(r => r.framework_name === selectedFramework);

  const activeSummary = complianceSummary.find(s => s.framework_name === selectedFramework) || {
    total_requirements: currentFwRequirements.length,
    implemented: currentFwRequirements.filter(r => r.status === "Implemented").length,
    partially_implemented: currentFwRequirements.filter(r => r.status === "Partially Implemented").length,
    not_implemented: currentFwRequirements.filter(r => r.status === "Not Implemented").length,
    not_assessed: currentFwRequirements.filter(r => r.status === "Not Assessed" || !r.status).length,
    not_applicable: currentFwRequirements.filter(r => r.status === "Not Applicable").length,
    implementation_coverage: 0.0,
    metric_label: "Implementation Coverage"
  };

  // ----------------------------------------
  // Phase 6: Governance Review & Reporting Handlers
  // ----------------------------------------

  const openSubmitReviewModal = (risk) => {
    setReviewingRisk(risk);
    setReviewForm({
      reviewer_name: user?.display_name || user?.username || "Security Analyst",
      reviewer_role: user?.role || "GRC Operator",
      decision: "APPROVED",
      agreed_treatment: risk.treatment || "Mitigate",
      comments: "",
      ai_analysis_acknowledged: false,
    });
    setReviewSubmitError(null);
  };

  const handleReviewSubmit = async (e) => {
    if (e) e.preventDefault();
    if (!reviewingRisk) return;

    if (!reviewForm.comments || reviewForm.comments.trim().length < 5) {
      setReviewSubmitError("Comments must be at least 5 characters in length.");
      return;
    }

    setSubmittingReview(true);
    setReviewSubmitError(null);
    try {
      const response = await authFetch(`${API_BASE}/risks/${reviewingRisk.id}/reviews`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          decision: reviewForm.decision,
          agreed_treatment: reviewForm.agreed_treatment,
          comments: reviewForm.comments.trim(),
          ai_analysis_acknowledged: Boolean(reviewForm.ai_analysis_acknowledged),
        }),
      });

      const data = await response.json().catch(() => null);
      if (!response.ok) {
        setReviewSubmitError(data?.detail || `Review submission failed (${response.status})`);
        return;
      }

      // Successful submission: close modal and perform targeted governance refresh
      setReviewingRisk(null);
      await Promise.all([fetchGovReviews(), fetchRisks()]);
    } catch (error) {
      setReviewSubmitError(error.message || "Network error while submitting review");
    } finally {
      setSubmittingReview(false);
    }
  };

  const openReviewHistoryModal = async (risk) => {
    setHistoryRisk(risk);
    setHistoryLoading(true);
    setHistoryError(null);
    setHistoryData(null);
    try {
      const response = await authFetch(`${API_BASE}/risks/${risk.id}/reviews`);
      if (response.ok) {
        const data = await response.json();
        setHistoryData(data);
      } else {
        const err = await response.json().catch(() => null);
        setHistoryError(err?.detail || `Failed to load review history (${response.status})`);
      }
    } catch (error) {
      setHistoryError(error.message || "Network error loading review history");
    } finally {
      setHistoryLoading(false);
    }
  };

  const handleExportReport = async (reportType, format) => {
    setDownloadingReport({ type: reportType, format });
    setReportDownloadError(null);
    try {
      const response = await authFetch(`${API_BASE}/reports/${reportType}?format=${format}`);

      if (!response.ok) {
        const err = await response.json().catch(() => null);
        throw new Error(err?.detail || `Export failed with status ${response.status}`);
      }

      const blob = await response.blob();
      let filename = `${reportType}.${format}`;
      const disposition = response.headers.get("Content-Disposition");
      if (disposition && disposition.includes("filename=")) {
        const match = disposition.match(/filename="?([^";]+)"?/);
        if (match && match[1]) {
          filename = match[1];
        }
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setLastExportedReport({
        filename,
        reportType,
        format,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      setReportDownloadError(`Download failed for ${reportType} (${format}): ${err.message}`);
    } finally {
      setDownloadingReport(null);
    }
  };

  const getReviewStatusBadge = (status) => {
    switch (status) {
      case "Pending Review":
        return <span className="badge badge-pending-review"><span className="status-indicator-dot dot-amber" />Pending Review</span>;
      case "Approved":
        return <span className="badge badge-approved"><span className="status-indicator-dot dot-green" />Approved</span>;
      case "Rejected":
        return <span className="badge badge-rejected"><span className="status-indicator-dot dot-red" />Rejected</span>;
      case "Stale":
        return <span className="badge badge-stale"><span className="status-indicator-dot dot-stale" />Stale</span>;
      case "Changes Requested":
        return <span className="badge badge-changes-requested"><span className="status-indicator-dot dot-orange" />Changes Requested</span>;
      default:
        return <span className="badge badge-neutral">{status || "Pending Review"}</span>;
    }
  };

  const getAuditSourceBadge = (source) => {
    switch (source) {
      case "USER": return <span className="badge badge-source-user">USER</span>;
      case "SYSTEM": return <span className="badge badge-source-system">SYSTEM</span>;
      case "AI": return <span className="badge badge-source-ai">AI</span>;
      case "SCANNER": return <span className="badge badge-source-scanner">SCANNER</span>;
      case "SCHEDULER": return <span className="badge badge-source-scheduler">SCHEDULER</span>;
      case "API": return <span className="badge badge-source-api">API</span>;
      default: return <span className="badge badge-neutral">{source || "API"}</span>;
    }
  };

  const getAuditActionBadge = (action) => {
    switch (action) {
      case "RISK_REVIEW_SUBMITTED":
        return <span className="badge badge-action-review">Review Submitted</span>;
      case "RISK_REVIEW_STALE":
        return <span className="badge badge-action-stale">Review Stale</span>;
      case "EXPORT":
        return <span className="badge badge-action-export">Export</span>;
      case "CREATE":
        return <span className="badge badge-low">Create</span>;
      case "UPDATE":
        return <span className="badge badge-medium">Update</span>;
      case "DELETE":
        return <span className="badge badge-critical">Delete</span>;
      case "SCAN_COMPLETED":
        return <span className="badge badge-low">Scan Done</span>;
      case "SCAN_TRIGGERED":
        return <span className="badge badge-action-trigger">Scan Trigger</span>;
      default:
        return <span className="badge badge-neutral">{action}</span>;
    }
  };

  // ----------------------------------------
  // Navigation Helpers
  // ----------------------------------------
  const handleNavClick = (page) => {
    setActivePage(page);
    if (page === "reviews") {
      setReviewsSubTab("queue");
    }
    else if (page === "audit") {
      if (auditLogs.length === 0) fetchAuditLogs(0, auditSourceFilter, auditActionFilter, auditEntityFilter, auditLimit);
    }
  };

  const PAGE_META = {
    overview: { title: "Security Overview", desc: "Executive security posture dashboard" },
    assets: { title: "Asset Inventory", desc: "Infrastructure discovery and business context management" },
    vulnerabilities: { title: "Vulnerability Findings", desc: "Technical security findings with CVE/NVD correlation" },
    "risk-management": { title: "Risk Management", desc: "Enterprise risk register, heat map, controls & treatment" },
    compliance: { title: "Compliance", desc: "Framework mapping and implementation tracking" },
    monitoring: { title: "Continuous Monitoring", desc: "Automated scanning, schedules, and drift detection" },
    reviews: { title: "Reviews & Sign-off", desc: "Human governance risk review queue" },
    audit: { title: "Audit Trail", desc: "Tamper-evident chronological event log" },
    reports: { title: "Reports", desc: "Regulatory and compliance report exports" },
  };
  const currentPageMeta = PAGE_META[activePage] || PAGE_META.overview;

  return (
    <div className="app-layout">
      {/* ================================ */}
      {/* SIDEBAR NAVIGATION              */}
      {/* ================================ */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="sidebar-logo">🛡</div>
          <div>
            <div className="sidebar-title">AI-GRC</div>
            <div className="sidebar-subtitle">Governance · Risk · Compliance</div>
          </div>
        </div>
        <nav className="sidebar-nav">
          <div className="nav-group-label">CORE</div>
          <button className={`nav-item${activePage === "overview" ? " active" : ""}`} onClick={() => handleNavClick("overview")}>
            <span className="nav-icon">🏠</span><span className="nav-label">Overview</span>
          </button>
          <button className={`nav-item${activePage === "assets" ? " active" : ""}`} onClick={() => handleNavClick("assets")}>
            <span className="nav-icon">🖥</span><span className="nav-label">Assets</span>
          </button>
          <button className={`nav-item${activePage === "vulnerabilities" ? " active" : ""}`} onClick={() => handleNavClick("vulnerabilities")}>
            <span className="nav-icon">🛡</span><span className="nav-label">Vulnerabilities</span>
          </button>
          <button className={`nav-item${activePage === "risk-management" ? " active" : ""}`} onClick={() => handleNavClick("risk-management")}>
            <span className="nav-icon">⚠</span><span className="nav-label">Risk Management</span>
          </button>
          <button className={`nav-item${activePage === "compliance" ? " active" : ""}`} onClick={() => handleNavClick("compliance")}>
            <span className="nav-icon">📋</span><span className="nav-label">Compliance</span>
          </button>
          <button className={`nav-item${activePage === "monitoring" ? " active" : ""}`} onClick={() => handleNavClick("monitoring")}>
            <span className="nav-icon">📡</span><span className="nav-label">Continuous Monitoring</span>
          </button>

          <div className="nav-group-label">GOVERNANCE</div>
          <button className={`nav-item${activePage === "reviews" ? " active" : ""}`} onClick={() => handleNavClick("reviews")}>
            <span className="nav-icon">✅</span><span className="nav-label">Reviews & Sign-off</span>
          </button>
          <button className={`nav-item${activePage === "audit" ? " active" : ""}`} onClick={() => handleNavClick("audit")}>
            <span className="nav-icon">🧾</span><span className="nav-label">Audit Trail</span>
          </button>

          <div className="nav-group-label">OUTPUT</div>
          <button className={`nav-item${activePage === "reports" ? " active" : ""}`} onClick={() => handleNavClick("reports")}>
            <span className="nav-icon">📊</span><span className="nav-label">Reports</span>
          </button>
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-user-card">
            <div className="sidebar-user-header">
              <div className="sidebar-user-avatar">
                {(user?.display_name || user?.username || "U")[0].toUpperCase()}
              </div>
              <div className="sidebar-user-info">
                <div className="sidebar-user-name" title={user?.display_name || user?.username}>
                  {user?.display_name || user?.username}
                </div>
                <div className="sidebar-user-role">
                  <span className={`role-badge ${
                    user?.role === "Administrator" ? "role-badge-admin" :
                    user?.role === "GRC Reviewer" ? "role-badge-reviewer" :
                    "role-badge-analyst"
                  }`}>
                    {user?.role}
                  </span>
                </div>
              </div>
            </div>
            <div style={{ marginTop: "10px" }}>
              <button
                type="button"
                className="sidebar-logout-btn"
                onClick={logout}
                title="Sign out of current session"
              >
                <span>🚪 Sign Out</span>
              </button>
            </div>
          </div>
          <div className="sidebar-status">
            <span className="pulse-dot"></span>
            <span>System Online</span>
          </div>
        </div>
      </aside>

      {/* ================================ */}
      {/* MAIN CONTENT AREA               */}
      {/* ================================ */}
      <div className="main-content">
        <header className="top-bar">
          <div className="top-bar-left">
            <h1 className="top-bar-title">{currentPageMeta.title}</h1>
            <p className="top-bar-desc">{currentPageMeta.desc}</p>
          </div>
          <div className="top-bar-right" style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div className="top-bar-user-pill">
              <span style={{ fontSize: "14px" }}>👤</span>
              <span style={{ fontWeight: 600 }}>{user?.display_name || user?.username}</span>
              <span className={`role-badge ${
                user?.role === "Administrator" ? "role-badge-admin" :
                user?.role === "GRC Reviewer" ? "role-badge-reviewer" :
                "role-badge-analyst"
              }`}>
                {user?.role}
              </span>
            </div>
            <button
              type="button"
              className={`ai-copilot-btn ai-copilot-available${showCopilotDrawer ? " ai-copilot-active" : ""}`}
              title="Open AI Copilot — Security & Risk Intelligence Workspace"
              onClick={() => {
                setShowCopilotDrawer((prev) => !prev);
                if (!copilotSelectedRiskId && risks.length > 0) {
                  setCopilotSelectedRiskId(viewingRisk ? viewingRisk.id : risks[0].id);
                }
              }}
            >
              <span className="ai-copilot-icon">✦</span>
              <span className="ai-copilot-label">AI Copilot</span>
              <span className="ai-copilot-status-dot" />
            </button>
          </div>
        </header>

        <div className="page-content">
        {permissionNotice && (
          <div className="permission-toast" role="alert">
            <span>⛔ {permissionNotice}</span>
            <button
              type="button"
              className="permission-toast-close"
              onClick={clearPermissionNotice}
              title="Dismiss"
            >
              ✕
            </button>
          </div>
        )}

      {/* -------------------------------- */}
      {/* OVERVIEW PAGE                   */}
      {/* -------------------------------- */}
      {activePage === "overview" && (
      <>
        {/* Executive Posture Banner */}
        <div className="overview-banner">
          <div className="overview-banner-left">
            <div className="overview-banner-icon">🛡️</div>
            <div>
              <div className="overview-banner-title">Executive Security & Posture Overview</div>
              <div className="overview-banner-desc">
                Continuous attack surface intelligence, authoritative GRC risk distribution, and regulatory implementation coverage.
              </div>
            </div>
          </div>
          <div className="overview-banner-badge">
            <span className="status-indicator-dot dot-green" /> Authoritative GRC Engine Active
          </div>
        </div>

        {/* 1. Security Posture KPI Cards */}
        <section className="cards cards-six">
          <div className="card">
            <div className="card-label">Monitored Assets</div>
            <div className="card-val">{assets.length}</div>
            <div className="card-sub">
              {assets.filter(a => (a.environment || "").toLowerCase() === "production").length} Production • {assets.filter(a => (a.exposure || "").toLowerCase() === "external").length} External
            </div>
          </div>

          <div className="card">
            <div className="card-label">Vulnerabilities</div>
            <div className="card-val highlight-orange">{vulnerabilities.length}</div>
            <div className="card-sub">
              {vulnerabilities.filter(v => ["critical", "high"].includes((v.severity || "").toLowerCase())).length} Critical / High Findings
            </div>
          </div>

          <div className="card">
            <div className="card-label">Open Risks</div>
            <div className="card-val highlight-amber">
              {risks.filter(r => r.status === "Open").length}
            </div>
            <div className="card-sub">
              of {risks.length} registered risks ({risks.filter(r => r.status === "Resolved").length} resolved)
            </div>
          </div>

          <div className="card">
            <div className="card-label">Critical / High Risks</div>
            <div className="card-val highlight-critical">
              {risks.filter(r => ["critical", "high"].includes((r.inherent_risk_level || r.risk_level || "").toLowerCase())).length}
            </div>
            <div className="card-sub">
              {risks.filter(r => (r.inherent_risk_level || r.risk_level || "").toLowerCase() === "critical").length} Critical • {risks.filter(r => (r.inherent_risk_level || r.risk_level || "").toLowerCase() === "high").length} High
            </div>
          </div>

          <div className="card">
            <div className="card-label">Implementation Coverage</div>
            <div className="card-val highlight-green">{activeSummary.implementation_coverage}%</div>
            <div className="card-sub">{selectedFramework} (Internal metric)</div>
          </div>

          <div className="card">
            <div className="card-label">Continuous Monitoring</div>
            <div className="card-val highlight-blue">
              {monitoringSchedules.filter(s => s.is_active).length} Active
            </div>
            <div className="card-sub">
              {driftTotal} Drift events • {monitoringJobs.filter(j => j.status === "Running" || j.status === "Queued").length} Active jobs
            </div>
          </div>
        </section>

        {/* 2 & 5. Middle Row: Risk Severity Distribution & Risk Heat Map (4x4) */}
        <div className="overview-grid-2col">
          <RiskDistribution risks={risks} />
          <RiskHeatMap risks={risks} />
        </div>

        {/* 3 & 4. Third Row: Vulnerability Severity Distribution & Compliance Implementation Coverage */}
        <div className="overview-grid-2col">
          <VulnerabilityDistribution vulnerabilities={vulnerabilities} />
          <ComplianceCoverageWidget complianceSummary={complianceSummary} requirements={requirements} />
        </div>

        {/* 6. Fourth Row: Recent Security Activity */}
        <div className="overview-grid-2col" style={{ gridTemplateColumns: "1fr" }}>
          <RecentSecurityActivity
            auditLogs={auditLogs}
            driftEvents={driftEvents}
            monitoringJobs={monitoringJobs}
            govReviews={govReviews}
          />
        </div>

        {/* Preserved Network Scanner & Discovery */}
        <section className="panel overview-quick-scan">
          <div className="panel-header">
            <div>
              <h2>Network Scanner & Discovery</h2>
              <p className="panel-desc">
                Scan target assets to detect services, correlate findings, and register GRC risks.
              </p>
            </div>
          </div>

          <div className="scan-controls">
            <input
              id="target-ip-input"
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Enter target IP (e.g. 192.168.127.1)"
            />
            <button
              id="run-scan-btn"
              className="btn-primary"
              onClick={runScan}
              disabled={scanning}
            >
              {scanning ? "Scanning Target..." : "Run Network Scan"}
            </button>
          </div>

          {result && (
            <div className="scan-result-box">
              <div className="scan-result-summary">
                <strong>Scan Completed for: {result.ip_address}</strong> — Risk Score: {result.risk_score} ({result.risk_level})
              </div>
              <div className="scan-result-ports">Open Ports: {result.open_ports}</div>
            </div>
          )}
        </section>
      </>)}

      {/* ------------------------------------------------ */}
      {/* CONTINUOUS MONITORING (PHASE 7 REDESIGN)         */}
      {/* ------------------------------------------------ */}
      {activePage === "monitoring" && (() => {
        // Derive real metrics from authoritative state
        const runningJobs = monitoringJobs.filter((j) => j.status === "Running");
        const queuedJobs = monitoringJobs.filter((j) => j.status === "Queued");
        const activeSchedules = monitoringSchedules.filter((s) => s.is_active);
        const unclassifiedDrift = driftEvents.filter((e) => e.event_type === "NEW_ASSET");

        // Deterministically sorted completed jobs
        const completedJobs = monitoringJobs
          .filter((j) => j.status === "Completed")
          .sort((a, b) => {
            const timeA = a.completed_at ? new Date(a.completed_at).getTime() : 0;
            const timeB = b.completed_at ? new Date(b.completed_at).getTime() : 0;
            if (timeB !== timeA) return timeB - timeA;
            return (b.id || 0) - (a.id || 0);
          });
        const latestCompletedJob = completedJobs[0] || null;

        // Honest monitoring status based strictly on existing state
        let monitoringStatus = "No Active Scan";
        let monitoringStatusSub = "No recurring schedule enabled";
        let monitoringStatusColor = "text-muted";
        let monitoringStatusDot = "dot-gray";

        if (runningJobs.length > 0) {
          monitoringStatus = "Running";
          monitoringStatusSub = `${runningJobs.length} scan${runningJobs.length > 1 ? "s" : ""} in progress`;
          monitoringStatusColor = "text-accent";
          monitoringStatusDot = "dot-pulse";
        } else if (activeSchedules.length > 0) {
          monitoringStatus = "Enabled";
          monitoringStatusSub = `${activeSchedules.length} active recurring schedule${activeSchedules.length > 1 ? "s" : ""}`;
          monitoringStatusColor = "text-green";
          monitoringStatusDot = "dot-green";
        } else if (monitoringSchedules.length > 0) {
          monitoringStatus = "Disabled";
          monitoringStatusSub = "All configured schedules paused";
          monitoringStatusColor = "text-yellow";
          monitoringStatusDot = "dot-amber";
        }

        // Filter scan jobs
        const filteredJobs = monitoringJobs.filter((job) => {
          if (monitoringJobStatusFilter !== "All" && job.status !== monitoringJobStatusFilter) {
            return false;
          }
          return true;
        });

        // Most recent active job (if running or queued)
        const primaryActiveJob = runningJobs[0] || queuedJobs[0] || null;

        return (
          <section className="panel monitoring-panel">
            {/* Header with Title, Tag & Refresh Action */}
            <div className="panel-header monitoring-page-header">
              <div>
                <div className="section-tag">CONTINUOUS MONITORING (PHASE 7)</div>
                <h2>Continuous Monitoring</h2>
                <p className="panel-desc">
                  Network discovery, scheduled scans, and infrastructure drift detection
                </p>
              </div>
              <div className="monitoring-header-actions">
                <button
                  className="btn-secondary btn-sm"
                  onClick={() => {
                    fetchMonitoringJobs();
                    fetchMonitoringSchedules();
                    fetchDriftEvents(driftOffset, driftSeverityFilter, driftTypeFilter);
                  }}
                  title="Refresh all monitoring data"
                >
                  <span className="monitoring-refresh-icon">↻</span> Refresh Feeds
                </button>
              </div>
            </div>

            {/* Top KPI Grid (5 Cards strictly using real state) */}
            <div className="monitoring-kpi-grid">
              <div className="monitoring-kpi-card">
                <div className="monitoring-kpi-header">
                  <span className="monitoring-kpi-label">Monitoring Status</span>
                  <span className="monitoring-kpi-icon">📡</span>
                </div>
                <div className={`monitoring-kpi-val ${monitoringStatusColor}`}>
                  <span className={`status-indicator-dot ${monitoringStatusDot}`} />
                  {monitoringStatus}
                </div>
                <div className="monitoring-kpi-sub">{monitoringStatusSub}</div>
              </div>

              <div className="monitoring-kpi-card">
                <div className="monitoring-kpi-header">
                  <span className="monitoring-kpi-label">Running Scans</span>
                  <span className="monitoring-kpi-icon">⚡</span>
                </div>
                <div className={`monitoring-kpi-val ${runningJobs.length > 0 ? "text-accent" : "text-light"}`}>
                  {runningJobs.length}
                </div>
                <div className="monitoring-kpi-sub">
                  {queuedJobs.length} scan{queuedJobs.length !== 1 ? "s" : ""} queued in pool
                </div>
              </div>

              <div className="monitoring-kpi-card">
                <div className="monitoring-kpi-header">
                  <span className="monitoring-kpi-label">Scheduled Scans</span>
                  <span className="monitoring-kpi-icon">⏱</span>
                </div>
                <div className="monitoring-kpi-val text-light">
                  {activeSchedules.length} <span className="monitoring-kpi-denom">/ {monitoringSchedules.length}</span>
                </div>
                <div className="monitoring-kpi-sub">Active recurring schedules</div>
              </div>

              <div className="monitoring-kpi-card">
                <div className="monitoring-kpi-header">
                  <span className="monitoring-kpi-label">Recent Drift Events</span>
                  <span className="monitoring-kpi-icon">🛰</span>
                </div>
                <div className="monitoring-kpi-val text-orange">
                  {driftTotal}
                </div>
                <div className="monitoring-kpi-sub">
                  {unclassifiedDrift.length} unclassified asset{unclassifiedDrift.length !== 1 ? "s" : ""}
                </div>
              </div>

              <div className="monitoring-kpi-card">
                <div className="monitoring-kpi-header">
                  <span className="monitoring-kpi-label">Last Successful Scan</span>
                  <span className="monitoring-kpi-icon">🛡</span>
                </div>
                <div
                  className="monitoring-kpi-val text-light"
                  style={{ fontSize: latestCompletedJob ? "15px" : "24px", fontWeight: 700 }}
                  title={latestCompletedJob ? formatDateTime(latestCompletedJob.completed_at) : undefined}
                >
                  {latestCompletedJob ? formatDateTime(latestCompletedJob.completed_at) : "None"}
                </div>
                <div className="monitoring-kpi-sub">
                  {latestCompletedJob
                    ? `Job #${latestCompletedJob.id} (${latestCompletedJob.target})`
                    : "No completed scans recorded"}
                </div>
              </div>
            </div>

            {/* Sub-Navigation Tabs */}
            <div className="monitoring-sub-nav">
              <button
                className={`monitoring-sub-nav-btn ${monitoringActiveTab === "jobs" ? "active" : ""}`}
                onClick={() => {
                  setMonitoringActiveTab("jobs");
                  fetchMonitoringJobs();
                }}
              >
                <span>Scan Jobs</span>
                <span className="monitoring-sub-nav-badge">{monitoringJobs.length}</span>
              </button>
              <button
                className={`monitoring-sub-nav-btn ${monitoringActiveTab === "schedules" ? "active" : ""}`}
                onClick={() => {
                  setMonitoringActiveTab("schedules");
                  fetchMonitoringSchedules();
                }}
              >
                <span>Schedules</span>
                <span className="monitoring-sub-nav-badge">{monitoringSchedules.length}</span>
              </button>
              <button
                className={`monitoring-sub-nav-btn ${monitoringActiveTab === "drift" ? "active" : ""}`}
                onClick={() => {
                  setMonitoringActiveTab("drift");
                  fetchDriftEvents(driftOffset, driftSeverityFilter, driftTypeFilter);
                }}
              >
                <span>Drift Feed</span>
                <span className="monitoring-sub-nav-badge">{driftTotal}</span>
              </button>
            </div>

            {/* Action Error Banner */}
            {jobActionError && (
              <div className="monitoring-error-banner">
                <span>⚠ {jobActionError}</span>
                <button className="btn-link" onClick={() => setJobActionError(null)}>Dismiss</button>
              </div>
            )}

            {/* ========================================================================= */}
            {/* SUB-VIEW 1: SCAN JOBS                                                     */}
            {/* ========================================================================= */}
            {monitoringActiveTab === "jobs" && (
              <div className="monitoring-tab-content">
                {/* Active Scan Spotlight if any scan is running or queued */}
                {primaryActiveJob && (
                  <div className="active-scan-spotlight">
                    <div className="active-scan-header">
                      <div className="active-scan-badge-wrap">
                        <span className="active-scan-live-tag">
                          <span className="status-indicator-dot dot-pulse" />
                          ACTIVE SCAN EXECUTION
                        </span>
                        <span className="active-scan-id">Job #{primaryActiveJob.id}</span>
                      </div>
                      <div className="active-scan-actions">
                        {getJobStatusBadge(primaryActiveJob.status)}
                        <button
                          className="btn-cancel-job"
                          onClick={() => cancelJob(primaryActiveJob.id)}
                          disabled={cancellingJobId === primaryActiveJob.id}
                          title="Terminate subprocess safely"
                        >
                          {cancellingJobId === primaryActiveJob.id ? "Cancelling..." : "Cancel Scan"}
                        </button>
                      </div>
                    </div>

                    <div className="active-scan-details">
                      <div className="active-scan-detail-item">
                        <span className="detail-label">Target Scope</span>
                        <strong className="detail-value ip-text">{primaryActiveJob.target}</strong>
                      </div>
                      <div className="active-scan-detail-item">
                        <span className="detail-label">Strategy</span>
                        <span className="detail-value">
                          {primaryActiveJob.scan_type === "subnet_discovery"
                            ? "Subnet Sweep (Ping + Service)"
                            : "Single Host (Top 100 ports)"}
                        </span>
                      </div>
                      <div className="active-scan-detail-item">
                        <span className="detail-label">Started</span>
                        <span className="detail-value text-slate">
                          {formatDateTime(primaryActiveJob.started_at || primaryActiveJob.created_at)}
                        </span>
                      </div>
                      <div className="active-scan-detail-item progress-item">
                        <div className="progress-info-row">
                          <span className="detail-label">Progress</span>
                          <strong className="progress-pct-text">{primaryActiveJob.progress_percent ?? 0}%</strong>
                        </div>
                        <div className="active-scan-progress-bar">
                          <div
                            className="active-scan-progress-fill"
                            style={{ width: `${Math.min(100, Math.max(0, primaryActiveJob.progress_percent ?? 0))}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Queue New Scan Job Launcher */}
                <div className="monitoring-launcher-card">
                  <div className="launcher-title">
                    <div className="launcher-title-row">
                      <strong>Queue Continuous Scan Job</strong>
                      <span className="launcher-badge">RFC 1918 Private Scope</span>
                    </div>
                    <span className="launcher-hint">
                      Non-blocking background scan executed by bounded ThreadPoolExecutor (max 3 concurrent; excess jobs wait safely in queue).
                    </span>
                  </div>

                  <form onSubmit={submitNewJob} className="launcher-form">
                    <div className="launcher-field">
                      <label>Target Scope (RFC 1918 Private, Max /24)</label>
                      <input
                        type="text"
                        value={newJobTarget}
                        onChange={(e) => setNewJobTarget(e.target.value)}
                        placeholder="e.g. 192.168.127.0/24 or 192.168.1.50"
                        disabled={submittingJob}
                        required
                      />
                    </div>
                    <div className="launcher-field">
                      <label>Scan Strategy</label>
                      <select
                        value={newJobType}
                        onChange={(e) => setNewJobType(e.target.value)}
                        disabled={submittingJob}
                      >
                        <option value="subnet_discovery">Subnet Discovery (Ping sweep + Service scan)</option>
                        <option value="single_host">Single Host (Targeted top 100 ports)</option>
                      </select>
                    </div>
                    <button
                      type="submit"
                      className="btn-primary launcher-btn"
                      disabled={submittingJob}
                    >
                      {submittingJob ? "Queueing Job..." : "+ Queue Scan Job"}
                    </button>
                  </form>
                </div>

                {/* Filter and Summary Bar */}
                <div className="monitoring-controls-bar">
                  <div className="monitoring-filter-group">
                    <label>Filter Status:</label>
                    <select
                      className="select-filter"
                      value={monitoringJobStatusFilter}
                      onChange={(e) => setMonitoringJobStatusFilter(e.target.value)}
                    >
                      <option value="All">All Statuses ({monitoringJobs.length})</option>
                      <option value="Running">Running ({monitoringJobs.filter((j) => j.status === "Running").length})</option>
                      <option value="Queued">Queued ({monitoringJobs.filter((j) => j.status === "Queued").length})</option>
                      <option value="Completed">Completed ({monitoringJobs.filter((j) => j.status === "Completed").length})</option>
                      <option value="Failed">Failed ({monitoringJobs.filter((j) => j.status === "Failed").length})</option>
                      <option value="Cancelled">Cancelled ({monitoringJobs.filter((j) => j.status === "Cancelled").length})</option>
                    </select>
                  </div>
                  <div className="monitoring-results-count">
                    Showing <strong>{filteredJobs.length}</strong> of <strong>{monitoringJobs.length}</strong> scan jobs
                  </div>
                </div>

                {/* Scan Jobs Table */}
                {monitoringJobsLoading && monitoringJobs.length === 0 ? (
                  <div className="monitoring-loading-box">
                    <span className="ai-spinner" /> Loading scan jobs...
                  </div>
                ) : monitoringJobsError ? (
                  <div className="monitoring-error-box">
                    <div>⚠ {monitoringJobsError}</div>
                    <button className="btn-secondary btn-sm" onClick={fetchMonitoringJobs}>Retry</button>
                  </div>
                ) : (
                  <div className="table-responsive">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Job ID</th>
                          <th>Target Scope</th>
                          <th>Strategy</th>
                          <th>Status</th>
                          <th>Progress</th>
                          <th>Discovered</th>
                          <th>Started / Completed</th>
                          <th>Duration</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredJobs.length === 0 ? (
                          <tr>
                            <td colSpan="9" className="empty-cell">
                              <div className="monitoring-empty-state">
                                <div className="empty-icon">📡</div>
                                <strong>No monitoring scans have been executed yet.</strong>
                                <span className="text-slate text-xs">
                                  {monitoringJobStatusFilter !== "All"
                                    ? `No scan jobs with status "${monitoringJobStatusFilter}" found.`
                                    : "Configure a private target scope above and queue a scan to discover network hosts and identify drift."}
                                </span>
                              </div>
                            </td>
                          </tr>
                        ) : (
                          filteredJobs.map((job) => (
                            <tr key={job.id}>
                              <td>
                                <strong className="job-id-text">#{job.id}</strong>
                              </td>
                              <td>
                                <strong className="ip-text">{job.target}</strong>
                                <span className="rfc1918-tag">RFC 1918</span>
                              </td>
                              <td>
                                <span className="strategy-badge">
                                  {job.scan_type === "subnet_discovery" ? "Subnet Sweep" : "Single Host"}
                                </span>
                              </td>
                              <td>
                                {getJobStatusBadge(job.status)}
                                {job.error_message && (
                                  <div className="job-error-msg" title={job.error_message}>
                                    ⚠ {job.error_message}
                                  </div>
                                )}
                              </td>
                              <td>
                                <div className="job-progress-cell">
                                  <div className="progress-bar-bg" style={{ width: "90px", margin: "4px 0" }}>
                                    <div
                                      className="progress-bar-fill"
                                      style={{
                                        width: `${Math.min(100, Math.max(0, job.progress_percent ?? 0))}%`,
                                        background: job.status === "Failed" ? "#ef4444" : undefined,
                                      }}
                                    />
                                  </div>
                                  <span className="text-xs text-slate">{job.progress_percent ?? 0}%</span>
                                </div>
                              </td>
                              <td>
                                <div className="job-metrics-stack">
                                  <span className="metric-pill" title="Discovered hosts">
                                    {job.discovered_assets_count ?? 0} host{job.discovered_assets_count !== 1 ? "s" : ""}
                                  </span>
                                  <span className="metric-pill" title="Discovered vulnerabilities">
                                    {job.discovered_vulns_count ?? 0} vuln{job.discovered_vulns_count !== 1 ? "s" : ""}
                                  </span>
                                </div>
                              </td>
                              <td>
                                <div className="text-xs">
                                  <div>
                                    <span className="text-slate">Started:</span> {formatDateTime(job.started_at || job.created_at)}
                                  </div>
                                  {job.completed_at && (
                                    <div>
                                      <span className="text-slate">Done:</span> {formatDateTime(job.completed_at)}
                                    </div>
                                  )}
                                </div>
                              </td>
                              <td>
                                <span className="duration-pill">
                                  {calculateJobDuration(job.started_at || job.created_at, job.completed_at)}
                                </span>
                              </td>
                              <td>
                                {(job.status === "Queued" || job.status === "Running") && (
                                  <button
                                    className="btn-cancel-job"
                                    onClick={() => cancelJob(job.id)}
                                    disabled={cancellingJobId === job.id}
                                    title="Request cooperative cancellation (terminates subprocess safely)"
                                  >
                                    {cancellingJobId === job.id ? "Cancelling..." : "Cancel"}
                                  </button>
                                )}
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* ========================================================================= */}
            {/* SUB-VIEW 2: AUTOMATED SCHEDULES                                           */}
            {/* ========================================================================= */}
            {monitoringActiveTab === "schedules" && (
              <div className="monitoring-tab-content">
                <div className="schedules-header-bar">
                  <div>
                    <h3 className="section-subtitle">Automated Scan Schedules</h3>
                    <p className="tab-subtitle">
                      Automated background recurring sweeps executed by the single-process in-process scheduler.
                    </p>
                  </div>
                  <button
                    className="btn-primary btn-sm"
                    onClick={() => isReviewer && openAddScheduleModal()}
                    disabled={!isReviewer}
                    title={isReviewer ? "Add Scan Schedule" : "GRC Reviewer or Administrator required to add scan schedules"}
                  >
                    + Add Scan Schedule
                  </button>
                </div>

                {monitoringSchedulesLoading && monitoringSchedules.length === 0 ? (
                  <div className="monitoring-loading-box">
                    <span className="ai-spinner" /> Loading automated schedules...
                  </div>
                ) : monitoringSchedulesError ? (
                  <div className="monitoring-error-box">
                    <div>⚠ {monitoringSchedulesError}</div>
                    <button className="btn-secondary btn-sm" onClick={fetchMonitoringSchedules}>Retry</button>
                  </div>
                ) : (
                  <div className="table-responsive">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Schedule Name</th>
                          <th>Target Scope</th>
                          <th>Interval</th>
                          <th>Schedule State</th>
                          <th>Last Run</th>
                          <th>Next Scheduled Run</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {monitoringSchedules.length === 0 ? (
                          <tr>
                            <td colSpan="7" className="empty-cell">
                              <div className="monitoring-empty-state">
                                <div className="empty-icon">⏱</div>
                                <strong>No monitoring schedules are configured.</strong>
                                <span className="text-slate text-xs">
                                  Click "+ Add Scan Schedule" above to set up automated recurring attack surface scans.
                                </span>
                              </div>
                            </td>
                          </tr>
                        ) : (
                          monitoringSchedules.map((sched) => (
                            <tr key={sched.id}>
                              <td>
                                <strong>{sched.name}</strong>
                                <div className="sub-text">Schedule ID #{sched.id}</div>
                              </td>
                              <td>
                                <strong className="ip-text">{sched.target}</strong>
                                <span className="rfc1918-tag">RFC 1918</span>
                              </td>
                              <td>
                                <span className="badge badge-neutral">Every {sched.interval_minutes}m</span>
                              </td>
                              <td>
                                <button
                                  className={`toggle-pill ${sched.is_active ? "toggle-active" : "toggle-inactive"}`}
                                  onClick={() => toggleScheduleActive(sched)}
                                  title={sched.is_active ? "Click to pause schedule" : "Click to activate schedule"}
                                >
                                  <span className={`toggle-dot ${sched.is_active ? "dot-active" : ""}`} />
                                  {sched.is_active ? "Active" : "Paused"}
                                </button>
                              </td>
                              <td>
                                <span className="text-xs text-slate">{formatDateTime(sched.last_run_at)}</span>
                              </td>
                              <td>
                                <span className="text-xs" style={{ color: sched.is_active ? "#38bdf8" : "#64748b" }}>
                                  {sched.is_active ? formatDateTime(sched.next_run_at) : "Paused"}
                                </span>
                              </td>
                              <td>
                                <div className="action-buttons-group">
                                  <button
                                    className="btn-action"
                                    onClick={() => openEditScheduleModal(sched)}
                                    title="Edit schedule details"
                                  >
                                    Edit
                                  </button>
                                  <button
                                    className="btn-action btn-action-danger"
                                    onClick={() => deleteSchedule(sched.id)}
                                    title="Delete schedule"
                                  >
                                    Delete
                                  </button>
                                </div>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* ========================================================================= */}
            {/* SUB-VIEW 3: NETWORK DRIFT & AUDIT FEED                                    */}
            {/* ========================================================================= */}
            {monitoringActiveTab === "drift" && (
              <div className="monitoring-tab-content">
                <div className="drift-filter-bar">
                  <div className="filter-group">
                    <label>Severity:</label>
                    <select
                      className="select-filter"
                      value={driftSeverityFilter}
                      onChange={(e) => {
                        const newSev = e.target.value;
                        setDriftSeverityFilter(newSev);
                        setDriftOffset(0);
                        fetchDriftEvents(0, newSev, driftTypeFilter);
                      }}
                    >
                      <option value="All">All Severities</option>
                      <option value="Critical">Critical</option>
                      <option value="High">High</option>
                      <option value="Medium">Medium</option>
                      <option value="Low">Low</option>
                    </select>
                  </div>

                  <div className="filter-group">
                    <label>Event Type:</label>
                    <select
                      className="select-filter"
                      value={driftTypeFilter}
                      onChange={(e) => {
                        const newType = e.target.value;
                        setDriftTypeFilter(newType);
                        setDriftOffset(0);
                        fetchDriftEvents(0, driftSeverityFilter, newType);
                      }}
                    >
                      <option value="All">All Event Types</option>
                      <option value="NEW_ASSET">New Asset (Unclassified)</option>
                      <option value="PORT_OPENED">Port Opened</option>
                      <option value="PORT_CLOSED">Port Closed</option>
                      <option value="CVE_DETECTED">CVE Detected</option>
                      <option value="FINDING_RESOLVED">Finding Resolved</option>
                    </select>
                  </div>

                  <div className="drift-count-summary">
                    Showing <strong>{driftEvents.length}</strong> of <strong>{driftTotal}</strong> drift events (newest first)
                  </div>
                </div>

                {driftEventsLoading && driftEvents.length === 0 ? (
                  <div className="monitoring-loading-box">
                    <span className="ai-spinner" /> Loading drift events feed...
                  </div>
                ) : driftEventsError ? (
                  <div className="monitoring-error-box">
                    <div>⚠ {driftEventsError}</div>
                    <button
                      className="btn-secondary btn-sm"
                      onClick={() => fetchDriftEvents(driftOffset, driftSeverityFilter, driftTypeFilter)}
                    >
                      Retry
                    </button>
                  </div>
                ) : (
                  <div className="drift-events-list">
                    {driftEvents.length === 0 ? (
                      <div className="drift-empty-box">
                        <div className="empty-icon">🛡</div>
                        <div><strong>No infrastructure drift has been recorded.</strong></div>
                        <div className="sub-text">
                          Subsequent automated background scans will compare against the last successful baseline and record new assets, port changes, and CVE detections here.
                        </div>
                      </div>
                    ) : (
                      driftEvents.map((event) => {
                        const matchedAsset = event.asset_id
                          ? (assets || []).find((a) => a.id === event.asset_id)
                          : null;

                        return (
                          <div key={event.id} className="drift-event-card">
                            <div className="drift-card-header">
                              <div className="drift-header-left">
                                {getDriftSeverityBadge(event.severity)}
                                {getDriftEventTypeBadge(event.event_type)}
                                <span className="drift-time">{formatDateTime(event.detected_at)}</span>
                              </div>
                              <div className="drift-header-right">
                                <span className="drift-job-tag">Scan Job #{event.scan_job_id}</span>
                                {event.asset_id && (
                                  <span className="drift-asset-tag">
                                    Asset #{event.asset_id}
                                    {matchedAsset?.ip_address ? ` (${matchedAsset.ip_address})` : ""}
                                  </span>
                                )}
                              </div>
                            </div>

                            <div className="drift-card-body">
                              <div className="drift-card-title">{event.title}</div>
                              <p className="drift-card-desc">{event.description}</p>

                              {/* CRITICAL: Unclassified Asset Warning Callout for NEW_ASSET */}
                              {event.event_type === "NEW_ASSET" && (
                                <div className="drift-unclassified-callout">
                                  <span className="unclassified-pill">Unclassified asset</span>
                                  <span className="unclassified-text">
                                    Newly discovered host awaiting GRC assignment. Business criticality, environment, exposure, and ownership remain unassigned until an operator classifies them.
                                  </span>
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })
                    )}

                    {/* Pagination Controls */}
                    {driftTotal > driftLimit && (
                      <div className="drift-pagination-bar">
                        <button
                          className="btn-secondary btn-sm"
                          disabled={driftOffset === 0}
                          onClick={() => {
                            const newOffset = Math.max(0, driftOffset - driftLimit);
                            setDriftOffset(newOffset);
                            fetchDriftEvents(newOffset, driftSeverityFilter, driftTypeFilter);
                          }}
                        >
                          ← Previous Page
                        </button>
                        <span className="pagination-info">
                          Page {Math.floor(driftOffset / driftLimit) + 1} of {Math.ceil(driftTotal / driftLimit)}
                        </span>
                        <button
                          className="btn-secondary btn-sm"
                          disabled={driftOffset + driftLimit >= driftTotal}
                          onClick={() => {
                            const newOffset = driftOffset + driftLimit;
                            setDriftOffset(newOffset);
                            fetchDriftEvents(newOffset, driftSeverityFilter, driftTypeFilter);
                          }}
                        >
                          Next Page →
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </section>
        );
      })()}

      {/* -------------------------------- */}
      {/* ASSET INVENTORY & POSTURE (Phase 3) */}
      {/* -------------------------------- */}
      {activePage === "assets" && (() => {
        const totalAssetsCount = assets.length;
        const criticalAssetsCount = assets.filter(
          (a) => (a.criticality || "").toLowerCase() === "critical" && !a.is_criticality_default
        ).length;
        const productionAssetsCount = assets.filter(
          (a) => (a.environment || "").toLowerCase() === "production"
        ).length;
        const externalAssetsCount = assets.filter(
          (a) => (a.exposure || "").toLowerCase() === "external"
        ).length;
        const unclassifiedAssets = assets.filter(isAssetUnclassified);
        const unclassifiedCount = unclassifiedAssets.length;

        const filteredAssets = assets.filter((asset) => {
          // Search matching
          if (assetSearchQuery.trim()) {
            const q = assetSearchQuery.toLowerCase().trim();
            const ip = (asset.ip_address || "").toLowerCase();
            const host = (asset.hostname || "").toLowerCase();
            const owner = (asset.owner || "").toLowerCase();
            const fn = (asset.business_function || "").toLowerCase();
            const os = (asset.operating_system || "").toLowerCase();
            if (!ip.includes(q) && !host.includes(q) && !owner.includes(q) && !fn.includes(q) && !os.includes(q)) {
              return false;
            }
          }

          // Environment filter
          if (assetEnvFilter !== "All") {
            if ((asset.environment || "").toLowerCase() !== assetEnvFilter.toLowerCase()) {
              return false;
            }
          }

          // Criticality filter
          if (assetCritFilter !== "All") {
            if (assetCritFilter === "Unclassified") {
              if (!isAssetUnclassified(asset)) return false;
            } else {
              if (isAssetUnclassified(asset)) return false;
              if ((asset.criticality || "").toLowerCase() !== assetCritFilter.toLowerCase()) return false;
            }
          }

          // Exposure filter
          if (assetExpFilter !== "All") {
            if ((asset.exposure || "").toLowerCase() !== assetExpFilter.toLowerCase()) {
              return false;
            }
          }

          return true;
        });

        const hasActiveAssetFilters =
          assetSearchQuery.trim() !== "" ||
          assetEnvFilter !== "All" ||
          assetCritFilter !== "All" ||
          assetExpFilter !== "All";

        const resetAssetFilters = () => {
          setAssetSearchQuery("");
          setAssetEnvFilter("All");
          setAssetCritFilter("All");
          setAssetExpFilter("All");
        };

        return (
          <>
            {/* 1. ASSET SUMMARY: Compact KPI Cards */}
            <section className="cards cards-five">
              <div className="card">
                <div className="card-label">Total Assets</div>
                <div className="card-val">{totalAssetsCount}</div>
                <div className="card-sub">
                  {assets.filter((a) => (a.status || "Active").toLowerCase() === "active").length} Active in scope
                </div>
              </div>

              <div className="card">
                <div className="card-label">Critical Assets</div>
                <div className="card-val highlight-critical">{criticalAssetsCount}</div>
                <div className="card-sub">Tier-1 business impact</div>
              </div>

              <div className="card">
                <div className="card-label">Production Assets</div>
                <div className="card-val highlight-blue">{productionAssetsCount}</div>
                <div className="card-sub">
                  {totalAssetsCount > 0 ? Math.round((productionAssetsCount / totalAssetsCount) * 100) : 0}% of infrastructure
                </div>
              </div>

              <div className="card">
                <div className="card-label">External Assets</div>
                <div className="card-val highlight-amber">{externalAssetsCount}</div>
                <div className="card-sub">Public-facing perimeter</div>
              </div>

              <div className="card">
                <div className="card-label">Unclassified Assets</div>
                <div className={`card-val ${unclassifiedCount > 0 ? "highlight-orange" : "highlight-green"}`}>
                  {unclassifiedCount}
                </div>
                <div className="card-sub">
                  {unclassifiedCount > 0 ? "Requires review" : "All categorized"}
                </div>
              </div>
            </section>

            {/* 6. UNCLASSIFIED ASSET CALLOUT */}
            {unclassifiedCount > 0 && (
              <div className="asset-unclassified-banner">
                <div className="asset-unclassified-icon">⚠️</div>
                <div className="asset-unclassified-content">
                  <div className="asset-unclassified-title">
                    {unclassifiedCount} {unclassifiedCount === 1 ? "asset requires" : "assets require"} classification
                  </div>
                  <div className="asset-unclassified-desc">
                    These newly discovered hosts currently lack criticality classification and/or assigned ownership. In accordance with enterprise GRC policy, newly discovered infrastructure remains unclassified until reviewed by security operations to prevent biased risk ratings.
                  </div>
                </div>
                <div className="asset-unclassified-actions">
                  <button
                    type="button"
                    className="btn-action-view"
                    onClick={() => {
                      setAssetCritFilter("Unclassified");
                      setAssetSearchQuery("");
                    }}
                  >
                    View Unclassified ({unclassifiedCount})
                  </button>
                </div>
              </div>
            )}

            {/* 2. ASSET INVENTORY & SECURITY POSTURE */}
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Asset Inventory & Security Posture</h2>
                  <p className="panel-desc">
                    Continuous infrastructure inventory with correlated technical findings, GRC risks, and business criticality.
                  </p>
                </div>
                <div>
                  <button
                    type="button"
                    className="btn-secondary btn-sm"
                    onClick={() => fetchAssets()}
                    title="Refresh assets from backend"
                  >
                    ↻ Refresh Assets
                  </button>
                </div>
              </div>

              {/* 3 & 4. SEARCH & FILTERS TOOLBAR */}
              <div className="asset-toolbar">
                <div className="asset-search-box">
                  <span className="search-icon">🔍</span>
                  <input
                    type="text"
                    className="asset-search-input"
                    placeholder="Search by IP, hostname, owner, or business function..."
                    value={assetSearchQuery}
                    onChange={(e) => setAssetSearchQuery(e.target.value)}
                  />
                  {assetSearchQuery && (
                    <button
                      type="button"
                      className="asset-search-clear"
                      onClick={() => setAssetSearchQuery("")}
                      title="Clear search"
                    >
                      ×
                    </button>
                  )}
                </div>

                <div className="asset-filter-group">
                  <div className="asset-filter-item">
                    <label htmlFor="asset-env-filter">Env:</label>
                    <select
                      id="asset-env-filter"
                      className="asset-select"
                      value={assetEnvFilter}
                      onChange={(e) => setAssetEnvFilter(e.target.value)}
                    >
                      <option value="All">All Environments</option>
                      <option value="Production">Production</option>
                      <option value="Development">Development</option>
                      <option value="Testing">Testing</option>
                    </select>
                  </div>

                  <div className="asset-filter-item">
                    <label htmlFor="asset-crit-filter">Criticality:</label>
                    <select
                      id="asset-crit-filter"
                      className="asset-select"
                      value={assetCritFilter}
                      onChange={(e) => setAssetCritFilter(e.target.value)}
                    >
                      <option value="All">All Criticalities</option>
                      <option value="Critical">Critical</option>
                      <option value="High">High</option>
                      <option value="Medium">Medium</option>
                      <option value="Low">Low</option>
                      <option value="Unclassified">Unclassified</option>
                    </select>
                  </div>

                  <div className="asset-filter-item">
                    <label htmlFor="asset-exp-filter">Exposure:</label>
                    <select
                      id="asset-exp-filter"
                      className="asset-select"
                      value={assetExpFilter}
                      onChange={(e) => setAssetExpFilter(e.target.value)}
                    >
                      <option value="All">All Exposures</option>
                      <option value="Internal">Internal</option>
                      <option value="DMZ">DMZ</option>
                      <option value="External">External</option>
                    </select>
                  </div>

                  {hasActiveAssetFilters && (
                    <button
                      type="button"
                      className="btn-secondary btn-sm asset-reset-btn"
                      onClick={resetAssetFilters}
                      title="Clear all filters and search"
                    >
                      Reset Filters
                    </button>
                  )}
                </div>
              </div>

              {/* Status bar */}
              <div className="asset-table-meta">
                <span className="asset-count-info">
                  Showing <strong>{filteredAssets.length}</strong> of <strong>{assets.length}</strong> assets
                  {hasActiveAssetFilters && " (filtered)"}
                </span>
              </div>

              {/* Data Table */}
              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>IP Address</th>
                      <th>Hostname / OS</th>
                      <th>Environment</th>
                      <th>Criticality</th>
                      <th>Exposure</th>
                      <th>Owner / Function</th>
                      <th>Open Ports</th>
                      <th>Security Posture</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assets.length === 0 ? (
                      <tr>
                        <td colSpan="9" className="empty-cell">
                          No assets discovered yet. Run a network scan to populate asset inventory.
                        </td>
                      </tr>
                    ) : filteredAssets.length === 0 ? (
                      <tr>
                        <td colSpan="9" className="empty-cell">
                          No assets match the active search and filter criteria.{" "}
                          <button
                            type="button"
                            className="btn-link"
                            onClick={resetAssetFilters}
                          >
                            Reset filters
                          </button>
                        </td>
                      </tr>
                    ) : (
                      filteredAssets.map((asset) => {
                        const ports = parsePortsList(asset.open_ports);
                        const assetVulns = vulnerabilities.filter((v) => v.asset_id === asset.id);
                        const critHighVulns = assetVulns.filter((v) =>
                          ["critical", "high"].includes((v.severity || "").toLowerCase())
                        ).length;
                        const assetRisks = risks.filter((r) => r.asset_id === asset.id);
                        const openRisks = assetRisks.filter(
                          (r) => (r.status || "Open").toLowerCase() === "open"
                        );
                        const unclassified = isAssetUnclassified(asset);

                        return (
                          <tr key={asset.id}>
                            <td>
                              <div className="ip-cell">
                                <span className={`status-indicator-dot ${asset.status === "Active" || !asset.status ? "dot-green" : "dot-gray"}`} />
                                <div>
                                  <strong className="ip-text">{asset.ip_address}</strong>
                                  <div className="sub-text">ID #{asset.id}</div>
                                </div>
                              </div>
                            </td>
                            <td>
                              <div>{asset.hostname || <span className="text-muted">Not Available</span>}</div>
                              <div className="sub-text">{asset.operating_system || "OS not identified"}</div>
                            </td>
                            <td>
                              <span className="badge badge-neutral">
                                {asset.environment || "Not Specified"}
                              </span>
                            </td>
                            <td>
                              {unclassified ? (
                                <span className="badge badge-unclassified" title="Awaiting GRC classification">
                                  Unclassified
                                </span>
                              ) : (
                                <span className={`badge ${getRiskClass(asset.criticality)}`}>
                                  {asset.criticality}
                                </span>
                              )}
                            </td>
                            <td>
                              <span className="badge badge-exposure">
                                {asset.exposure || "Not Specified"}
                              </span>
                            </td>
                            <td>
                              <div>{asset.owner || <span className="text-muted">Not Assigned</span>}</div>
                              <div className="sub-text">{asset.business_function || "Not Specified"}</div>
                            </td>
                            <td>
                              {ports.length === 0 ? (
                                <span className="text-muted">None</span>
                              ) : (
                                <div>
                                  <span className="port-count-pill" title={ports.join(", ")}>
                                    {ports.length} Open
                                  </span>
                                  <div className="ports-preview">
                                    {ports.slice(0, 2).map((p, idx) => (
                                      <span key={idx} className="port-tag">
                                        {p}
                                      </span>
                                    ))}
                                    {ports.length > 2 && (
                                      <span className="port-tag-more" title={ports.slice(2).join(", ")}>
                                        +{ports.length - 2}
                                      </span>
                                    )}
                                  </div>
                                </div>
                              )}
                            </td>
                            <td>
                              <div className="posture-tags-wrap">
                                <div className="posture-row">
                                  {assetVulns.length === 0 ? (
                                    <span className="posture-chip posture-clean">0 Vulns</span>
                                  ) : (
                                    <span
                                      className={`posture-chip ${critHighVulns > 0 ? "posture-danger" : "posture-warn"}`}
                                      title={`${assetVulns.length} vulnerabilities (${critHighVulns} Critical/High)`}
                                    >
                                      {assetVulns.length} Vuln{assetVulns.length === 1 ? "" : "s"}
                                      {critHighVulns > 0 ? ` (${critHighVulns} C/H)` : ""}
                                    </span>
                                  )}
                                  {openRisks.length === 0 ? (
                                    <span className="posture-chip posture-clean">0 Risks</span>
                                  ) : (
                                    <span className="posture-chip posture-risk" title={`${openRisks.length} open risks`}>
                                      {openRisks.length} Risk{openRisks.length === 1 ? "" : "s"}
                                    </span>
                                  )}
                                </div>
                                <div className="posture-risk-rating">
                                  <span className={`badge ${getRiskClass(asset.risk_level)}`}>
                                    {asset.risk_level} ({asset.risk_score})
                                  </span>
                                </div>
                              </div>
                            </td>
                            <td>
                              <div className="asset-actions-cell">
                                <button
                                  type="button"
                                  className="btn-action-view"
                                  onClick={() => setViewingAsset(asset)}
                                  title="View Asset Details"
                                >
                                  Details
                                </button>
                                <button
                                  type="button"
                                  className="btn-action"
                                  onClick={() => isReviewer && openAssetModal(asset)}
                                  disabled={!isReviewer}
                                  title={isReviewer ? "Edit Asset Intelligence" : "GRC Reviewer or Administrator required to edit assets"}
                                >
                                  Edit
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        );
      })()}

      {/* -------------------------------- */}
      {/* RISK MANAGEMENT                */}
      {/* -------------------------------- */}
      {activePage === "risk-management" && (() => {
        // Coordinate validator: strictly enforces integers 1-4
        const parseScore = (val) => {
          if (val === null || val === undefined || val === "") return null;
          const num = Number(val);
          return Number.isInteger(num) && num >= 1 && num <= 4 ? num : null;
        };

        const getValidLikelihood = (r) => {
          const val = r.likelihood_score !== undefined && r.likelihood_score !== null ? r.likelihood_score : r.likelihood;
          return parseScore(val);
        };

        const getValidImpact = (r) => {
          const val = r.impact_score !== undefined && r.impact_score !== null ? r.impact_score : r.impact;
          return parseScore(val);
        };

        // KPI metrics from real risk data
        const totalRisksCount = risks.length;
        const openRisksCount = risks.filter((r) => (r.status || "").toLowerCase() === "open").length;
        const criticalRisksCount = risks.filter((r) => (r.inherent_risk_level || r.risk_level || "").toLowerCase() === "critical").length;
        const highRisksCount = risks.filter((r) => (r.inherent_risk_level || r.risk_level || "").toLowerCase() === "high").length;
        const mediumRisksCount = risks.filter((r) => (r.inherent_risk_level || r.risk_level || "").toLowerCase() === "medium").length;
        const lowRisksCount = risks.filter((r) => (r.inherent_risk_level || r.risk_level || "").toLowerCase() === "low").length;
        const unknownRiskLevelCount = risks.filter((r) => {
          const lvl = (r.inherent_risk_level || r.risk_level || "").toLowerCase();
          return !["critical", "high", "medium", "low"].includes(lvl);
        }).length;
        const reviewActionCount = risks.filter((r) => {
          const rs = (r.review_status || "").toLowerCase();
          return rs === "pending review" || rs === "changes requested" || rs === "stale" || rs === "under review";
        }).length;

        // Proportional distribution
        const critPct = totalRisksCount > 0 ? (criticalRisksCount / totalRisksCount) * 100 : 0;
        const highPct = totalRisksCount > 0 ? (highRisksCount / totalRisksCount) * 100 : 0;
        const medPct = totalRisksCount > 0 ? (mediumRisksCount / totalRisksCount) * 100 : 0;
        const lowPct = totalRisksCount > 0 ? (lowRisksCount / totalRisksCount) * 100 : 0;
        const unkPct = totalRisksCount > 0 ? (unknownRiskLevelCount / totalRisksCount) * 100 : 0;

        // Filtering for the Risk Register
        const filteredRisks = risks.filter((risk) => {
          if (riskSearchQuery.trim()) {
            const q = riskSearchQuery.toLowerCase();
            const asset = assets.find((a) => a.id === risk.asset_id);
            const matchesId = String(risk.id).toLowerCase().includes(q);
            const matchesTitle = (risk.title || "").toLowerCase().includes(q);
            const matchesDesc = (risk.description || "").toLowerCase().includes(q);
            const matchesRec = (risk.recommendation || "").toLowerCase().includes(q);
            const matchesOwner = (risk.risk_owner || "").toLowerCase().includes(q);
            const matchesFw = (risk.compliance_framework || "").toLowerCase().includes(q);
            const matchesCtrl = (risk.compliance_control || "").toLowerCase().includes(q);
            const matchesTreatment = (risk.treatment || "").toLowerCase().includes(q);
            const matchesStatus = (risk.status || "").toLowerCase().includes(q);
            const matchesIp = (asset?.ip_address || "").toLowerCase().includes(q);
            const matchesHost = (asset?.hostname || "").toLowerCase().includes(q);
            const matchesFunc = (asset?.business_function || "").toLowerCase().includes(q);

            if (
              !matchesId &&
              !matchesTitle &&
              !matchesDesc &&
              !matchesRec &&
              !matchesOwner &&
              !matchesFw &&
              !matchesCtrl &&
              !matchesTreatment &&
              !matchesStatus &&
              !matchesIp &&
              !matchesHost &&
              !matchesFunc
            ) {
              return false;
            }
          }

          if (riskLevelFilter !== "All") {
            const lvl = (risk.inherent_risk_level || risk.risk_level || "").toLowerCase();
            if (lvl !== riskLevelFilter.toLowerCase()) return false;
          }

          if (riskStatusFilter !== "All") {
            if ((risk.status || "").toLowerCase() !== riskStatusFilter.toLowerCase()) return false;
          }

          if (riskTreatmentFilter !== "All") {
            if ((risk.treatment || "").toLowerCase() !== riskTreatmentFilter.toLowerCase()) return false;
          }

          if (riskReviewFilter !== "All") {
            if ((risk.review_status || "").toLowerCase() !== riskReviewFilter.toLowerCase()) return false;
          }

          return true;
        });

        const activeRiskFiltersCount =
          (riskSearchQuery ? 1 : 0) +
          (riskLevelFilter !== "All" ? 1 : 0) +
          (riskStatusFilter !== "All" ? 1 : 0) +
          (riskTreatmentFilter !== "All" ? 1 : 0) +
          (riskReviewFilter !== "All" ? 1 : 0);

        const handleResetRiskFilters = () => {
          setRiskSearchQuery("");
          setRiskLevelFilter("All");
          setRiskStatusFilter("All");
          setRiskTreatmentFilter("All");
          setRiskReviewFilter("All");
        };

        // Heat Map coordinate plotting
        const plottableInherentRisks = risks.filter((r) => getValidLikelihood(r) !== null && getValidImpact(r) !== null);
        const plottableResidualRisks = risks.filter((r) => parseScore(r.residual_likelihood) !== null && parseScore(r.residual_impact) !== null);

        const activePlottableRisks = heatmapMatrixType === "inherent" ? plottableInherentRisks : plottableResidualRisks;
        const heatmapExcludedCount = risks.length - activePlottableRisks.length;

        const likelihoodLevels = [
          { level: 4, label: "4 — Frequent" },
          { level: 3, label: "3 — Likely" },
          { level: 2, label: "2 — Possible" },
          { level: 1, label: "1 — Rare" },
        ];

        const impactLevels = [
          { level: 1, label: "1 — Low" },
          { level: 2, label: "2 — Moderate" },
          { level: 3, label: "3 — Major" },
          { level: 4, label: "4 — Critical" },
        ];

        const getCellSeverityClass = (score) => {
          if (score >= 12) return "heatmap-cell-critical";
          if (score >= 7) return "heatmap-cell-high";
          if (score >= 4) return "heatmap-cell-medium";
          return "heatmap-cell-low";
        };

        const getCellRisks = (l, i) => {
          if (heatmapMatrixType === "inherent") {
            return plottableInherentRisks.filter((r) => getValidLikelihood(r) === l && getValidImpact(r) === i);
          }
          return plottableResidualRisks.filter((r) => parseScore(r.residual_likelihood) === l && parseScore(r.residual_impact) === i);
        };

        const selectedCellRisks = selectedHeatmapCell ? getCellRisks(selectedHeatmapCell.l, selectedHeatmapCell.i) : [];

        // Treatment summary counts
        const mitigateCount = risks.filter((r) => (r.treatment || "mitigate").toLowerCase() === "mitigate").length;
        const acceptCount = risks.filter((r) => (r.treatment || "").toLowerCase() === "accept").length;
        const transferCount = risks.filter((r) => (r.treatment || "").toLowerCase() === "transfer").length;
        const avoidCount = risks.filter((r) => (r.treatment || "").toLowerCase() === "avoid").length;

        return (
          <>
            {/* Sub-Navigation: Internal Sections */}
            <div className="risk-subnav">
              <button
                type="button"
                className={`risk-subnav-btn${riskSubTab === "register" ? " active" : ""}`}
                onClick={() => setRiskSubTab("register")}
              >
                <span>📋</span> Risk Register
                <span className="risk-subnav-badge">{risks.length}</span>
              </button>
              <button
                type="button"
                className={`risk-subnav-btn${riskSubTab === "heatmap" ? " active" : ""}`}
                onClick={() => setRiskSubTab("heatmap")}
              >
                <span>🗺️</span> Heat Map (4×4 Matrix)
                <span className="risk-subnav-badge">{activePlottableRisks.length}</span>
              </button>
              <button
                type="button"
                className={`risk-subnav-btn${riskSubTab === "controls" ? " active" : ""}`}
                onClick={() => setRiskSubTab("controls")}
              >
                <span>🛡️</span> Controls & Treatment
                <span className="risk-subnav-badge">{controls.length}</span>
              </button>
            </div>

            {/* KPI Summary Cards */}
            <div className="risk-kpi-grid">
              <div className="risk-kpi-card">
                <div className="risk-kpi-label">Total Open Risks</div>
                <div className="risk-kpi-val text-accent">{openRisksCount}</div>
                <div className="risk-kpi-sub">
                  {openRisksCount} open of {totalRisksCount} registered risks
                </div>
              </div>

              <div className="risk-kpi-card">
                <div className="risk-kpi-label">Critical Inherent</div>
                <div className="risk-kpi-val text-red">{criticalRisksCount}</div>
                <div className="risk-kpi-sub">Score 12–16 • Urgent escalation</div>
              </div>

              <div className="risk-kpi-card">
                <div className="risk-kpi-label">High Inherent</div>
                <div className="risk-kpi-val text-orange">{highRisksCount}</div>
                <div className="risk-kpi-sub">Score 7–11 • Target remediation</div>
              </div>

              <div className="risk-kpi-card">
                <div className="risk-kpi-label">Medium Inherent</div>
                <div className="risk-kpi-val text-yellow">{mediumRisksCount}</div>
                <div className="risk-kpi-sub">Score 4–6 • Planned controls</div>
              </div>

              <div className="risk-kpi-card">
                <div className="risk-kpi-label">Low Inherent</div>
                <div className="risk-kpi-val text-green">{lowRisksCount}</div>
                <div className="risk-kpi-sub">Score 1–3 • Baseline monitoring</div>
              </div>

              <div className="risk-kpi-card">
                <div className="risk-kpi-label">Requires Review / Action</div>
                <div className="risk-kpi-val text-purple">{reviewActionCount}</div>
                <div className="risk-kpi-sub">Awaiting governance sign-off</div>
              </div>
            </div>

            {/* Inherent Risk Severity Distribution Bar */}
            <div className="vuln-dist-panel">
              <div className="vuln-dist-header">
                <div>
                  <div className="vuln-dist-title">Inherent Risk Severity Distribution</div>
                  <div className="vuln-dist-desc">
                    Proportional breakdown of enterprise risks by authoritative inherent risk level.
                  </div>
                </div>
                <span className="text-xs text-slate font-mono">
                  {totalRisksCount} Total Registered Finding{totalRisksCount !== 1 ? "s" : ""}
                </span>
              </div>

              {totalRisksCount === 0 ? (
                <div className="empty-cell" style={{ padding: "16px", textAlign: "center" }}>
                  No enterprise risk findings registered in the system.
                </div>
              ) : (
                <>
                  <div className="vuln-dist-bar-track">
                    {critPct > 0 && (
                      <div
                        className="vuln-dist-seg seg-critical"
                        style={{ width: `${critPct}%` }}
                        title={`Critical: ${criticalRisksCount} (${critPct.toFixed(1)}%)`}
                      />
                    )}
                    {highPct > 0 && (
                      <div
                        className="vuln-dist-seg seg-high"
                        style={{ width: `${highPct}%` }}
                        title={`High: ${highRisksCount} (${highPct.toFixed(1)}%)`}
                      />
                    )}
                    {medPct > 0 && (
                      <div
                        className="vuln-dist-seg seg-medium"
                        style={{ width: `${medPct}%` }}
                        title={`Medium: ${mediumRisksCount} (${medPct.toFixed(1)}%)`}
                      />
                    )}
                    {lowPct > 0 && (
                      <div
                        className="vuln-dist-seg seg-low"
                        style={{ width: `${lowPct}%` }}
                        title={`Low: ${lowRisksCount} (${lowPct.toFixed(1)}%)`}
                      />
                    )}
                    {unkPct > 0 && (
                      <div
                        className="vuln-dist-seg seg-unknown"
                        style={{ width: `${unkPct}%` }}
                        title={`Unknown: ${unknownRiskLevelCount} (${unkPct.toFixed(1)}%)`}
                      />
                    )}
                  </div>

                  <div className="vuln-dist-legend">
                    <span className="vuln-legend-item">
                      <span className="vuln-legend-dot dot-critical" />
                      Critical: <strong>{criticalRisksCount}</strong> ({critPct.toFixed(1)}%)
                    </span>
                    <span className="vuln-legend-item">
                      <span className="vuln-legend-dot dot-high" />
                      High: <strong>{highRisksCount}</strong> ({highPct.toFixed(1)}%)
                    </span>
                    <span className="vuln-legend-item">
                      <span className="vuln-legend-dot dot-medium" />
                      Medium: <strong>{mediumRisksCount}</strong> ({medPct.toFixed(1)}%)
                    </span>
                    <span className="vuln-legend-item">
                      <span className="vuln-legend-dot dot-low" />
                      Low: <strong>{lowRisksCount}</strong> ({lowPct.toFixed(1)}%)
                    </span>
                    {unknownRiskLevelCount > 0 && (
                      <span className="vuln-legend-item">
                        <span className="vuln-legend-dot dot-unknown" />
                        Unknown: <strong>{unknownRiskLevelCount}</strong> ({unkPct.toFixed(1)}%)
                      </span>
                    )}
                  </div>
                </>
              )}
            </div>

            {/* TAB 1: RISK REGISTER */}
            {riskSubTab === "register" && (
              <section className="panel">
                <div className="panel-header">
                  <div>
                    <h2>GRC Enterprise Risk Register</h2>
                    <p className="panel-desc">
                      Authoritative risk catalog tracking Inherent Risk (Likelihood × Impact) to Residual Risk mitigated by defensive controls.
                    </p>
                  </div>
                </div>

                {/* Search & Filter Toolbar */}
                <div className="asset-filter-bar">
                  <div className="asset-search-wrap">
                    <span className="search-icon">🔍</span>
                    <input
                      type="text"
                      className="asset-search-input"
                      placeholder="Search risk ID, title, owner, framework, control, asset IP, hostname..."
                      value={riskSearchQuery}
                      onChange={(e) => setRiskSearchQuery(e.target.value)}
                    />
                    {riskSearchQuery && (
                      <button
                        type="button"
                        className="search-clear-btn"
                        onClick={() => setRiskSearchQuery("")}
                        title="Clear search"
                      >
                        ×
                      </button>
                    )}
                  </div>

                  <div className="asset-selects-row">
                    <div className="filter-group">
                      <label>Risk Level:</label>
                      <select
                        className="select-filter"
                        value={riskLevelFilter}
                        onChange={(e) => setRiskLevelFilter(e.target.value)}
                      >
                        <option value="All">All Levels</option>
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                      </select>
                    </div>

                    <div className="filter-group">
                      <label>Lifecycle Status:</label>
                      <select
                        className="select-filter"
                        value={riskStatusFilter}
                        onChange={(e) => setRiskStatusFilter(e.target.value)}
                      >
                        <option value="All">All Statuses</option>
                        <option value="Open">Open</option>
                        <option value="Under Review">Under Review</option>
                        <option value="Accepted">Accepted</option>
                        <option value="Resolved">Resolved</option>
                      </select>
                    </div>

                    <div className="filter-group">
                      <label>Treatment:</label>
                      <select
                        className="select-filter"
                        value={riskTreatmentFilter}
                        onChange={(e) => setRiskTreatmentFilter(e.target.value)}
                      >
                        <option value="All">All Treatments</option>
                        <option value="Mitigate">Mitigate</option>
                        <option value="Accept">Accept</option>
                        <option value="Transfer">Transfer</option>
                        <option value="Avoid">Avoid</option>
                      </select>
                    </div>

                    <div className="filter-group">
                      <label>Governance Review:</label>
                      <select
                        className="select-filter"
                        value={riskReviewFilter}
                        onChange={(e) => setRiskReviewFilter(e.target.value)}
                      >
                        <option value="All">All Reviews</option>
                        <option value="Pending Review">Pending Review</option>
                        <option value="Under Review">Under Review</option>
                        <option value="Approved">Approved</option>
                        <option value="Changes Requested">Changes Requested</option>
                        <option value="Rejected">Rejected</option>
                        <option value="Stale">Stale</option>
                      </select>
                    </div>

                    {activeRiskFiltersCount > 0 && (
                      <button
                        type="button"
                        className="btn-secondary btn-reset-filters"
                        onClick={handleResetRiskFilters}
                        title="Reset all filters and search query"
                      >
                        Reset ({activeRiskFiltersCount})
                      </button>
                    )}
                  </div>
                </div>

                {/* Filter Results Counter */}
                <div className="asset-results-bar">
                  <span className="results-count">
                    Showing <strong>{filteredRisks.length}</strong> of <strong>{risks.length}</strong> enterprise risks
                  </span>
                  {activeRiskFiltersCount > 0 && (
                    <span className="filtered-indicator-tag">
                      Filters Active ({activeRiskFiltersCount})
                    </span>
                  )}
                </div>

                {/* Risk Table */}
                <div className="table-responsive">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Risk Finding</th>
                        <th>Asset</th>
                        <th>Inherent Risk</th>
                        <th>Residual Risk</th>
                        <th>Mitigating Controls</th>
                        <th>Treatment</th>
                        <th>Owner & Due Date</th>
                        <th>Status & Governance</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredRisks.length === 0 ? (
                        <tr>
                          <td colSpan="9" className="empty-cell" style={{ textAlign: "center", padding: "32px" }}>
                            {risks.length === 0 ? (
                              "No risks registered in the catalog yet."
                            ) : (
                              <div>
                                <div style={{ marginBottom: "8px" }}>No risks match the active search and filter criteria.</div>
                                <button type="button" className="btn-secondary btn-sm" onClick={handleResetRiskFilters}>
                                  Reset Filters
                                </button>
                              </div>
                            )}
                          </td>
                        </tr>
                      ) : (
                        filteredRisks.map((risk) => {
                          const asset = assets.find((a) => a.id === risk.asset_id);
                          return (
                            <Fragment key={risk.id}>
                              <tr>
                                <td style={{ minWidth: "220px" }}>
                                  <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                                    <span className="text-slate font-mono text-xs">#{risk.id}</span>
                                    <strong>{risk.title}</strong>
                                  </div>
                                  <div className="sub-text">{risk.recommendation || risk.description}</div>
                                  {risk.compliance_framework && (
                                    <div className="framework-tag">
                                      {risk.compliance_framework} ({risk.compliance_control || "Control"})
                                    </div>
                                  )}
                                </td>
                                <td>
                                  <span className="ip-pill">{asset ? asset.ip_address : `Asset #${risk.asset_id}`}</span>
                                  {asset?.hostname && <div className="sub-text font-mono">{asset.hostname}</div>}
                                </td>
                                <td>
                                  <span className={`badge ${getRiskClass(risk.inherent_risk_level || risk.risk_level)}`}>
                                    {risk.inherent_risk_level || risk.risk_level || "Medium"} ({risk.inherent_risk_score || risk.risk_score})
                                  </span>
                                  <div className="sub-calc">
                                    L: {risk.likelihood_score || risk.likelihood || 2} × I: {risk.impact_score || risk.impact || 2}
                                  </div>
                                </td>
                                <td>
                                  <span className={`badge ${getRiskClass(risk.residual_risk_level)}`}>
                                    {risk.residual_risk_level ? `${risk.residual_risk_level}${risk.residual_risk_score != null ? ` (${risk.residual_risk_score})` : ""}` : "Not Available"}
                                  </span>
                                  <div className="sub-calc">
                                    Res L: {risk.residual_likelihood != null ? risk.residual_likelihood : "—"} × I: {risk.residual_impact != null ? risk.residual_impact : "—"}
                                  </div>
                                  {risk.inherent_risk_score != null && risk.residual_risk_score != null && (
                                    <div className="risk-trajectory" title="Inherent to Residual score trajectory">
                                      <span className="trajectory-arrow">→</span> Score: {risk.inherent_risk_score} to {risk.residual_risk_score}
                                    </div>
                                  )}
                                </td>
                                <td style={{ minWidth: "220px" }}>
                                  <div className="controls-list">
                                    {risk.controls && risk.controls.length > 0 ? (
                                      risk.controls.map((c) => (
                                        <span key={c.id} className="control-chip">
                                          {c.name}
                                          <button
                                            type="button"
                                            className="chip-remove"
                                            onClick={() => handleDetachControl(risk.id, c.id)}
                                            title="Detach Control"
                                          >
                                            ×
                                          </button>
                                        </span>
                                      ))
                                    ) : (
                                      <span className="text-muted text-xs">No controls assigned</span>
                                    )}
                                  </div>

                                  {assigningRiskId === risk.id ? (
                                    <div className="assign-box">
                                      <select
                                        value={selectedControlId}
                                        onChange={(e) => setSelectedControlId(e.target.value)}
                                        className="select-mini"
                                      >
                                        <option value="">Select Control...</option>
                                        {controls
                                          .filter((c) => !risk.controls?.some((rc) => rc.id === c.id))
                                          .map((c) => (
                                            <option key={c.id} value={c.id}>
                                              {c.name} ({c.effectiveness} Eff)
                                            </option>
                                          ))}
                                      </select>
                                      <div className="assign-actions">
                                        <button
                                          type="button"
                                          className="btn-mini btn-save"
                                          onClick={() => handleAssignControl(risk.id)}
                                          disabled={!selectedControlId}
                                        >
                                          Save
                                        </button>
                                        <button
                                          type="button"
                                          className="btn-mini btn-cancel"
                                          onClick={() => {
                                            setAssigningRiskId(null);
                                            setSelectedControlId("");
                                          }}
                                        >
                                          Cancel
                                        </button>
                                      </div>
                                    </div>
                                  ) : (
                                    <button
                                      type="button"
                                      className="btn-link"
                                      onClick={() => {
                                        setAssigningRiskId(risk.id);
                                        setSelectedControlId("");
                                      }}
                                    >
                                      + Assign Control
                                    </button>
                                  )}
                                </td>
                                <td>
                                  <span className="badge badge-treatment">
                                    {risk.treatment || "Mitigate"}
                                  </span>
                                </td>
                                <td>
                                  <div>{risk.risk_owner || <span className="text-muted">Unassigned</span>}</div>
                                  <div className="sub-text">
                                    {risk.due_date ? formatDateTime(risk.due_date) : "No due date"}
                                  </div>
                                </td>
                                <td>
                                  <span className={`status-pill ${getStatusClass(risk.status)}`}>
                                    {risk.status || "Open"}
                                  </span>
                                  <div style={{ marginTop: "6px" }}>
                                    {getReviewStatusBadge(risk.review_status || "Pending Review")}
                                  </div>
                                </td>
                                <td>
                                  <div className="action-stack">
                                    <button
                                      type="button"
                                      className="btn-action"
                                      onClick={() => setViewingRisk(risk)}
                                      title="Inspect Complete Risk Record"
                                    >
                                      Details
                                    </button>
                                    <button
                                      type="button"
                                      className="btn-action"
                                      onClick={() => openRiskModal(risk)}
                                      title="Manage Risk Treatment & Ownership"
                                    >
                                      Manage
                                    </button>
                                    <button
                                      type="button"
                                      className="btn-action"
                                      onClick={() => openSubmitReviewModal(risk)}
                                      title="Submit Human Governance Sign-Off"
                                    >
                                      Sign-Off
                                    </button>
                                    <button
                                      type="button"
                                      className="btn-action"
                                      onClick={() => openReviewHistoryModal(risk)}
                                      title="View Governance Review History"
                                    >
                                      History
                                    </button>
                                    <button
                                      type="button"
                                      className={`btn-ai-analyze${expandedAiPanel === risk.id ? " btn-ai-active" : ""}`}
                                      onClick={() => handleAnalyzeRisk(risk.id)}
                                      disabled={!!aiLoading[risk.id]}
                                      title="Generate AI-assisted security intelligence"
                                      id={`ai-analyze-btn-${risk.id}`}
                                    >
                                      {aiLoading[risk.id]
                                        ? "Analyzing..."
                                        : expandedAiPanel === risk.id
                                          ? "▲ Hide AI"
                                          : "✦ AI Analysis"}
                                    </button>
                                  </div>
                                </td>
                              </tr>
                              {expandedAiPanel === risk.id && (
                                <tr className="ai-panel-row">
                                  <td colSpan="9" className="ai-panel-cell">
                                    <AIAnalysisPanel
                                      loading={!!aiLoading[risk.id]}
                                      error={aiError[risk.id] || null}
                                      analysis={aiAnalysis[risk.id] || null}
                                      onReanalyze={() => handleReanalyzeRisk(risk.id)}
                                    />
                                  </td>
                                </tr>
                              )}
                            </Fragment>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </section>
            )}

            {/* TAB 2: HEAT MAP */}
            {riskSubTab === "heatmap" && (
              <section className="panel">
                <div className="panel-header">
                  <div>
                    <h2>Enterprise Risk Heat Map (4×4 Matrix)</h2>
                    <p className="panel-desc">
                      {heatmapMatrixType === "inherent"
                        ? "Authoritative GRC matrix plotting Inherent Likelihood (1–4) against Impact (1–4). Inherent Risk Score = Likelihood × Impact."
                        : "Residual Risk matrix reflecting reduced likelihood achieved through deployed security controls."}
                    </p>
                  </div>
                  <div className="heatmap-toggle-wrap">
                    <button
                      type="button"
                      className={`heatmap-toggle-btn${heatmapMatrixType === "inherent" ? " active" : ""}`}
                      onClick={() => {
                        setHeatmapMatrixType("inherent");
                        setSelectedHeatmapCell(null);
                      }}
                    >
                      Inherent Matrix ({plottableInherentRisks.length})
                    </button>
                    <button
                      type="button"
                      className={`heatmap-toggle-btn${heatmapMatrixType === "residual" ? " active" : ""}`}
                      onClick={() => {
                        setHeatmapMatrixType("residual");
                        setSelectedHeatmapCell(null);
                      }}
                    >
                      Residual Matrix ({plottableResidualRisks.length})
                    </button>
                  </div>
                </div>

                <div className="heatmap-container" style={{ margin: "16px 0" }}>
                  <div className="heatmap-layout">
                    <div className="heatmap-y-axis">
                      <span className="heatmap-y-label">LIKELIHOOD</span>
                    </div>

                    <div className="heatmap-matrix-wrap">
                      <div className="heatmap-grid">
                        <div className="heatmap-header-cell" />
                        {impactLevels.map((imp) => (
                          <div key={imp.level} className="heatmap-header-cell">
                            {imp.label}
                          </div>
                        ))}

                        {likelihoodLevels.map((lh) => (
                          <Fragment key={lh.level}>
                            <div className="heatmap-row-header">{lh.label}</div>
                            {impactLevels.map((imp) => {
                              const cellRisks = getCellRisks(lh.level, imp.level);
                              const count = cellRisks.length;
                              const score = lh.level * imp.level;
                              const sevClass = getCellSeverityClass(score);
                              const isSelected = selectedHeatmapCell?.l === lh.level && selectedHeatmapCell?.i === imp.level;

                              return (
                                <div
                                  key={`${lh.level}-${imp.level}`}
                                  className={`heatmap-cell ${sevClass} ${count > 0 ? "active" : "empty"}${isSelected ? " selected" : ""}`}
                                  onClick={() =>
                                    setSelectedHeatmapCell(
                                      isSelected ? null : { l: lh.level, i: imp.level }
                                    )
                                  }
                                  role="button"
                                  tabIndex={0}
                                  aria-label={`Likelihood ${lh.level}, Impact ${imp.level}, Score ${score}, ${count} risks`}
                                >
                                  <span className="heatmap-cell-val">
                                    {count} {count === 1 ? "Risk" : "Risks"}
                                  </span>
                                  <span className="heatmap-cell-coord">
                                    L{lh.level} × I{imp.level}
                                  </span>
                                  <span className="heatmap-cell-score">
                                    Score {score}
                                  </span>
                                </div>
                              );
                            })}
                          </Fragment>
                        ))}
                      </div>

                      <div className="heatmap-x-label">IMPACT</div>
                    </div>
                  </div>

                  <div className="heatmap-legend">
                    <span className="heatmap-legend-item">
                      <span className="heatmap-legend-chip" style={{ background: "#22c55e" }} />
                      <strong>Low</strong> (1–3)
                    </span>
                    <span className="heatmap-legend-item">
                      <span className="heatmap-legend-chip" style={{ background: "#eab308" }} />
                      <strong>Medium</strong> (4–6)
                    </span>
                    <span className="heatmap-legend-item">
                      <span className="heatmap-legend-chip" style={{ background: "#f97316" }} />
                      <strong>High</strong> (7–11)
                    </span>
                    <span className="heatmap-legend-item">
                      <span className="heatmap-legend-chip" style={{ background: "#ef4444" }} />
                      <strong>Critical</strong> (12–16)
                    </span>
                  </div>

                  {heatmapExcludedCount > 0 && (
                    <div className="heatmap-excluded-note">
                      ℹ️ {heatmapExcludedCount} risk(s) could not be plotted on the {heatmapMatrixType} heat map because their coordinates are missing or outside the valid integer 1–4 range.
                    </div>
                  )}
                </div>

                {/* Selected Cell Inspector */}
                {selectedHeatmapCell ? (
                  <div className="heatmap-inspector">
                    <div className="heatmap-inspector-header">
                      <div className="heatmap-inspector-title">
                        Likelihood: {selectedHeatmapCell.l} ({likelihoodLevels.find(l => l.level === selectedHeatmapCell.l)?.label.split(" — ")[1] || selectedHeatmapCell.l}) • Impact: {selectedHeatmapCell.i} ({impactLevels.find(i => i.level === selectedHeatmapCell.i)?.label.split(" — ")[1] || selectedHeatmapCell.i}) • Score: {selectedHeatmapCell.l * selectedHeatmapCell.i} • Risks in this cell: {selectedCellRisks.length}
                      </div>
                      <button
                        type="button"
                        className="btn-secondary btn-sm"
                        onClick={() => setSelectedHeatmapCell(null)}
                      >
                        Clear Selection
                      </button>
                    </div>

                    {selectedCellRisks.length === 0 ? (
                      <div className="empty-cell" style={{ textAlign: "center", padding: "16px" }}>
                        No risks currently located at these coordinates.
                      </div>
                    ) : (
                      <div className="table-responsive">
                        <table className="data-table">
                          <thead>
                            <tr>
                              <th>Finding</th>
                              <th>Asset</th>
                              <th>Inherent</th>
                              <th>Residual</th>
                              <th>Treatment</th>
                              <th>Status & Review</th>
                              <th>Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {selectedCellRisks.map((risk) => {
                              const asset = assets.find((a) => a.id === risk.asset_id);
                              return (
                                <tr key={risk.id}>
                                  <td>
                                    <strong>#{risk.id}: {risk.title}</strong>
                                    <div className="sub-text">{risk.recommendation || risk.description}</div>
                                  </td>
                                  <td>
                                    <span className="ip-pill">{asset ? asset.ip_address : `Asset #${risk.asset_id}`}</span>
                                  </td>
                                  <td>
                                    <span className={`badge ${getRiskClass(risk.inherent_risk_level || risk.risk_level)}`}>
                                      {risk.inherent_risk_level || risk.risk_level || "Medium"} ({risk.inherent_risk_score || risk.risk_score})
                                    </span>
                                  </td>
                                  <td>
                                    <span className={`badge ${getRiskClass(risk.residual_risk_level)}`}>
                                      {risk.residual_risk_level ? `${risk.residual_risk_level}${risk.residual_risk_score != null ? ` (${risk.residual_risk_score})` : ""}` : "Not Available"}
                                    </span>
                                  </td>
                                  <td>
                                    <span className="badge badge-treatment">{risk.treatment || "Mitigate"}</span>
                                  </td>
                                  <td>
                                    <span className={`status-pill ${getStatusClass(risk.status)}`}>{risk.status || "Open"}</span>
                                    <div style={{ marginTop: "4px" }}>
                                      {getReviewStatusBadge(risk.review_status || "Pending Review")}
                                    </div>
                                  </td>
                                  <td>
                                    <div className="action-stack">
                                      <button
                                        type="button"
                                        className="btn-action"
                                        onClick={() => setViewingRisk(risk)}
                                      >
                                        Details
                                      </button>
                                      <button
                                        type="button"
                                        className="btn-action"
                                        onClick={() => openRiskModal(risk)}
                                      >
                                        Manage
                                      </button>
                                      <button
                                        type="button"
                                        className="btn-action"
                                        onClick={() => openSubmitReviewModal(risk)}
                                      >
                                        Sign-Off
                                      </button>
                                    </div>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="disclaimer-banner" style={{ marginTop: "16px" }}>
                    <span className="info-icon">ℹ️</span>
                    <span>
                      <strong>Interactive Matrix:</strong> Click on any populated cell in the 4×4 heat map above to inspect the specific enterprise risks plotted at those Likelihood × Impact coordinates.
                    </span>
                  </div>
                )}
              </section>
            )}

            {/* TAB 3: CONTROLS & TREATMENT */}
            {riskSubTab === "controls" && (
              <>
                {/* Treatment Strategy Breakdown */}
                <section className="panel" style={{ marginBottom: "20px" }}>
                  <div className="panel-header">
                    <div>
                      <h2>Enterprise Risk Treatment Strategies</h2>
                      <p className="panel-desc">
                        Formal response decisions assigned to enterprise risks under governance oversight.
                      </p>
                    </div>
                  </div>

                  <div className="treatment-grid">
                    <div className="treatment-card">
                      <div className="treatment-card-header">
                        <span className="treatment-card-title">Mitigate</span>
                        <span className="treatment-card-count">{mitigateCount}</span>
                      </div>
                      <div className="treatment-card-desc">
                        Deploy defensive controls to lower vulnerability exploitability and reduce likelihood score.
                      </div>
                      <div className="treatment-card-action">
                        <button
                          type="button"
                          className="btn-secondary btn-sm"
                          onClick={() => {
                            setRiskTreatmentFilter("Mitigate");
                            setRiskSubTab("register");
                          }}
                        >
                          View in Register ➔
                        </button>
                      </div>
                    </div>

                    <div className="treatment-card">
                      <div className="treatment-card-header">
                        <span className="treatment-card-title">Accept</span>
                        <span className="treatment-card-count">{acceptCount}</span>
                      </div>
                      <div className="treatment-card-desc">
                        Formally acknowledge risk within business risk appetite with documented executive sign-off.
                      </div>
                      <div className="treatment-card-action">
                        <button
                          type="button"
                          className="btn-secondary btn-sm"
                          onClick={() => {
                            setRiskTreatmentFilter("Accept");
                            setRiskSubTab("register");
                          }}
                        >
                          View in Register ➔
                        </button>
                      </div>
                    </div>

                    <div className="treatment-card">
                      <div className="treatment-card-header">
                        <span className="treatment-card-title">Transfer</span>
                        <span className="treatment-card-count">{transferCount}</span>
                      </div>
                      <div className="treatment-card-desc">
                        Shift financial and operational consequences via third-party contracts or cyber insurance.
                      </div>
                      <div className="treatment-card-action">
                        <button
                          type="button"
                          className="btn-secondary btn-sm"
                          onClick={() => {
                            setRiskTreatmentFilter("Transfer");
                            setRiskSubTab("register");
                          }}
                        >
                          View in Register ➔
                        </button>
                      </div>
                    </div>

                    <div className="treatment-card">
                      <div className="treatment-card-header">
                        <span className="treatment-card-title">Avoid</span>
                        <span className="treatment-card-count">{avoidCount}</span>
                      </div>
                      <div className="treatment-card-desc">
                        Eliminate exposure by decommissioning the asset, terminating the service, or disabling the feature.
                      </div>
                      <div className="treatment-card-action">
                        <button
                          type="button"
                          className="btn-secondary btn-sm"
                          onClick={() => {
                            setRiskTreatmentFilter("Avoid");
                            setRiskSubTab("register");
                          }}
                        >
                          View in Register ➔
                        </button>
                      </div>
                    </div>
                  </div>
                </section>

                {/* Security Controls Catalog */}
                <section className="panel">
                  <div className="panel-header">
                    <div>
                      <h2>Security Controls Catalog</h2>
                      <p className="panel-desc">
                        Available defensive safeguards. Implemented controls reduce risk likelihood based on their effectiveness rating.
                      </p>
                    </div>
                    <button
                      type="button"
                      className="btn-primary"
                      onClick={() => isReviewer && setShowAddControlModal(true)}
                      disabled={!isReviewer}
                      title={isReviewer ? "Add Control" : "GRC Reviewer or Administrator required to add controls"}
                    >
                      + Add Control
                    </button>
                  </div>

                  <div className="table-responsive">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Control Name</th>
                          <th>Framework</th>
                          <th>Category</th>
                          <th>Effectiveness</th>
                          <th>Status</th>
                          <th>Assigned Risks</th>
                          <th>Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {controls.length === 0 ? (
                          <tr>
                            <td colSpan="7" className="empty-cell">No controls in catalog.</td>
                          </tr>
                        ) : (
                          controls.map((control) => (
                            <tr key={control.id}>
                              <td>
                                <strong>{control.name}</strong>
                              </td>
                              <td>
                                <span className="badge badge-neutral">{control.framework || "NIST CSF"}</span>
                              </td>
                              <td>{control.category || "Preventive"}</td>
                              <td>
                                <span className={`badge ${control.effectiveness === "High" ? "badge-eff-high" : "badge-eff-med"}`}>
                                  {control.effectiveness} ({control.effectiveness === "High" ? "-2 Likelihood" : control.effectiveness === "Medium" ? "-1 Likelihood" : "0 Likelihood"})
                                </span>
                              </td>
                              <td>
                                <span className={`status-pill ${control.status === "Implemented" ? "status-resolved" : "status-review"}`}>
                                  {control.status}
                                </span>
                              </td>
                              <td>
                                <span className="count-bubble">{control.risk_count}</span>
                              </td>
                              <td className="desc-cell">{control.description || "No description provided."}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </section>
              </>
            )}
          </>
        );
      })()}

      {/* -------------------------------- */}
      {/* COMPLIANCE (PHASE 6)             */}
      {/* -------------------------------- */}
      {activePage === "compliance" && (() => {
        // 1. Metric aggregation helper — strictly tallies existing status counts from requirement data.
        // Does NOT calculate implementation coverage in React.
        const aggregateCounts = (reqList) => {
          const total = reqList.length;
          const implemented = reqList.filter(r => r.status === "Implemented").length;
          const partiallyImplemented = reqList.filter(r => r.status === "Partially Implemented").length;
          const notImplemented = reqList.filter(r => r.status === "Not Implemented").length;
          const notAssessed = reqList.filter(r => r.status === "Not Assessed" || !r.status).length;
          const notApplicable = reqList.filter(r => r.status === "Not Applicable").length;

          return {
            total,
            implemented,
            partiallyImplemented,
            notImplemented,
            notAssessed,
            notApplicable,
          };
        };

        // 2. Framework datasets & Authoritative Backend Summaries
        const nistFw = frameworks.find(f => f.name === "NIST CSF") || {
          name: "NIST CSF",
          version: "2.0",
          description: "NIST Cybersecurity Framework 2.0 (February 2024). Organized across 6 Core Functions: Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS), and Recover (RC). Evaluated as a reviewed prototype subset of supported requirements."
        };
        const isoFw = frameworks.find(f => f.name === "ISO/IEC 27001") || {
          name: "ISO/IEC 27001",
          version: "2022",
          description: "ISO/IEC 27001:2022 Information Security Management Systems - Annex A Controls. Structured across 4 themes: Organizational (A.5), People (A.6), Physical (A.7), and Technological (A.8). Evaluated as a reviewed prototype subset of supported requirements."
        };

        const nistReqs = requirements.filter(r => r.framework_name === "NIST CSF");
        const isoReqs = requirements.filter(r => r.framework_name === "ISO/IEC 27001");

        const nistSummary = complianceSummary.find(s => s.framework_name === "NIST CSF");
        const isoSummary = complianceSummary.find(s => s.framework_name === "ISO/IEC 27001");

        // Authoritative implementation_coverage values reported directly by backend API (/compliance/summary)
        const nistCoverage = nistSummary != null && typeof nistSummary.implementation_coverage === "number"
          ? nistSummary.implementation_coverage
          : null;
        const isoCoverage = isoSummary != null && typeof isoSummary.implementation_coverage === "number"
          ? isoSummary.implementation_coverage
          : null;

        const overallMetrics = aggregateCounts(requirements);
        const nistMetrics = aggregateCounts(nistReqs);
        const isoMetrics = aggregateCounts(isoReqs);

        // 3. NIST Functions definitions
        const NIST_FUNCTIONS = [
          { name: "Govern", code: "GV", desc: "Cybersecurity risk management strategy, expectations, and policy" },
          { name: "Identify", code: "ID", desc: "Current cybersecurity risk, enterprise assets, and supply chain" },
          { name: "Protect", code: "PR", desc: "Safeguards to prevent or contain the impact of cybersecurity events" },
          { name: "Detect", code: "DE", desc: "Find and analyze possible cybersecurity attacks and compromises" },
          { name: "Respond", code: "RS", desc: "Take action regarding a detected cybersecurity incident" },
          { name: "Recover", code: "RC", desc: "Restore assets and operations impacted by a cybersecurity incident" },
        ];

        // 4. ISO Domains definitions
        const ISO_DOMAINS = [
          { name: "Organizational", code: "A.5", desc: "Policies, roles, asset management, and organizational security" },
          { name: "People", code: "A.6", desc: "Screening, terms of employment, and security awareness education" },
          { name: "Physical", code: "A.7", desc: "Physical security perimeters, entry controls, and equipment protection" },
          { name: "Technological", code: "A.8", desc: "Endpoint security, network protection, authentication, and vulnerability management" },
        ];

        // 5. Active base requirements depending on sub-tab
        let baseReqs = requirements;
        if (complianceSubTab === "nist") {
          baseReqs = nistReqs;
        } else if (complianceSubTab === "iso") {
          baseReqs = isoReqs;
        }

        // Available functions/domains for filter dropdown in current view
        const availableDropdownFunctions = ["All", ...Array.from(new Set(baseReqs.map(r => r.function).filter(Boolean)))];

        // 6. Filtering logic
        const filteredReqs = baseReqs.filter(r => {
          // Framework filter (only active on overview)
          if (complianceSubTab === "overview" && complianceFrameworkFilter !== "All") {
            if (r.framework_name !== complianceFrameworkFilter) return false;
          }

          // Search query (case-insensitive over existing fields)
          if (complianceSearchQuery.trim()) {
            const q = complianceSearchQuery.trim().toLowerCase();
            const idMatch = (r.requirement_id || "").toLowerCase().includes(q);
            const titleMatch = (r.title || "").toLowerCase().includes(q);
            const descMatch = (r.description || "").toLowerCase().includes(q);
            const fwMatch = (r.framework_name || "").toLowerCase().includes(q);
            const fnMatch = (r.function || "").toLowerCase().includes(q);
            const catMatch = (r.category || "").toLowerCase().includes(q);
            const subcatMatch = (r.subcategory || "").toLowerCase().includes(q);
            const controlMatch = r.mapped_controls && r.mapped_controls.some(
              mc => (mc.name || "").toLowerCase().includes(q)
            );
            if (!idMatch && !titleMatch && !descMatch && !fwMatch && !fnMatch && !catMatch && !subcatMatch && !controlMatch) {
              return false;
            }
          }

          // Status filter
          if (complianceStatusFilter !== "All") {
            if (complianceStatusFilter === "Not Assessed") {
              if (r.status !== "Not Assessed" && r.status) return false;
            } else {
              if (r.status !== complianceStatusFilter) return false;
            }
          }

          // Function/Domain filter
          if (complianceFunctionFilter !== "All") {
            if ((r.function || "").toLowerCase() !== complianceFunctionFilter.toLowerCase()) return false;
          }

          // Mapping strength filter
          if (complianceStrengthFilter !== "All") {
            const controls = r.mapped_controls || [];
            if (complianceStrengthFilter === "Unmapped") {
              if (controls.length > 0) return false;
            } else if (complianceStrengthFilter === "Direct") {
              if (!controls.some(c => c.mapping_strength === "Direct")) return false;
            } else if (complianceStrengthFilter === "Supporting") {
              if (!controls.some(c => c.mapping_strength === "Supporting")) return false;
            }
          }

          return true;
        });

        // Check if any filters active
        const hasActiveFilters = Boolean(
          complianceSearchQuery.trim() ||
          complianceStatusFilter !== "All" ||
          complianceFunctionFilter !== "All" ||
          complianceStrengthFilter !== "All" ||
          (complianceSubTab === "overview" && complianceFrameworkFilter !== "All")
        );

        const resetFilters = () => {
          setComplianceSearchQuery("");
          setComplianceFrameworkFilter("All");
          setComplianceStatusFilter("All");
          setComplianceFunctionFilter("All");
          setComplianceStrengthFilter("All");
        };

        // Render helper for Proportional Segmented Status Distribution Bar
        const renderStatusDistribution = (metrics) => {
          const { total, implemented, partiallyImplemented, notImplemented, notAssessed, notApplicable } = metrics;
          if (!total || total === 0) {
            return (
              <div className="compliance-dist-empty">
                No requirement evaluation data available.
              </div>
            );
          }

          const implPct = ((implemented / total) * 100).toFixed(1);
          const partPct = ((partiallyImplemented / total) * 100).toFixed(1);
          const notImplPct = ((notImplemented / total) * 100).toFixed(1);
          const notAssPct = ((notAssessed / total) * 100).toFixed(1);
          const naPct = ((notApplicable / total) * 100).toFixed(1);

          return (
            <div className="compliance-dist-container">
              <div className="compliance-dist-bar">
                {implemented > 0 && (
                  <div
                    className="compliance-dist-seg comp-seg-implemented"
                    style={{ width: `${implPct}%` }}
                    title={`Implemented: ${implemented} (${implPct}%)`}
                  />
                )}
                {partiallyImplemented > 0 && (
                  <div
                    className="compliance-dist-seg comp-seg-partial"
                    style={{ width: `${partPct}%` }}
                    title={`Partially Implemented: ${partiallyImplemented} (${partPct}%)`}
                  />
                )}
                {notImplemented > 0 && (
                  <div
                    className="compliance-dist-seg comp-seg-not-impl"
                    style={{ width: `${notImplPct}%` }}
                    title={`Not Implemented: ${notImplemented} (${notImplPct}%)`}
                  />
                )}
                {notAssessed > 0 && (
                  <div
                    className="compliance-dist-seg comp-seg-not-assessed"
                    style={{ width: `${notAssPct}%` }}
                    title={`Not Assessed: ${notAssessed} (${notAssPct}%)`}
                  />
                )}
                {notApplicable > 0 && (
                  <div
                    className="compliance-dist-seg comp-seg-na"
                    style={{ width: `${naPct}%` }}
                    title={`Not Applicable: ${notApplicable} (${naPct}%)`}
                  />
                )}
              </div>
              <div className="compliance-dist-legend">
                <span className="compliance-legend-item">
                  <span className="compliance-legend-dot dot-impl" />
                  Implemented: <strong>{implemented}</strong> <span className="text-muted">({implPct}%)</span>
                </span>
                <span className="compliance-legend-item">
                  <span className="compliance-legend-dot dot-partial" />
                  Partially Implemented: <strong>{partiallyImplemented}</strong> <span className="text-muted">({partPct}%)</span>
                </span>
                <span className="compliance-legend-item">
                  <span className="compliance-legend-dot dot-not-impl" />
                  Not Implemented: <strong>{notImplemented}</strong> <span className="text-muted">({notImplPct}%)</span>
                </span>
                <span className="compliance-legend-item">
                  <span className="compliance-legend-dot dot-not-assessed" />
                  Not Assessed: <strong>{notAssessed}</strong> <span className="text-muted">({notAssPct}%)</span>
                </span>
                <span className="compliance-legend-item">
                  <span className="compliance-legend-dot dot-na" />
                  Not Applicable: <strong>{notApplicable}</strong> <span className="text-muted">({naPct}%)</span>
                </span>
              </div>
            </div>
          );
        };

        // Render helper for requirements table
        const renderRequirementsTable = (reqList, showFrameworkCol = false) => {
          return (
            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Requirement Code</th>
                    <th>Title & Description</th>
                    {showFrameworkCol && <th>Framework</th>}
                    <th>Function / Domain</th>
                    <th>Status</th>
                    <th>Mapped Controls</th>
                    <th>Auditor Notes</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {reqList.length === 0 ? (
                    <tr>
                      <td colSpan={showFrameworkCol ? 8 : 7} className="empty-cell">
                        No compliance requirements match the current filters.
                      </td>
                    </tr>
                  ) : (
                    reqList.map((req) => (
                      <tr key={req.id}>
                        <td>
                          <span className="req-code-badge">{req.requirement_id || "—"}</span>
                          {req.category && <div className="sub-text">{req.category}</div>}
                        </td>
                        <td style={{ minWidth: "240px", maxWidth: "340px" }}>
                          <strong className="compliance-table-title">{req.title}</strong>
                          <div className="sub-text desc-cell">{req.description}</div>
                        </td>
                        {showFrameworkCol && (
                          <td>
                            <span className="compliance-fw-tag">
                              {req.framework_name} v{req.framework_version}
                            </span>
                          </td>
                        )}
                        <td>
                          <span className="function-pill">{req.function}</span>
                        </td>
                        <td>
                          <span className={`badge ${getComplianceStatusClass(req.status)}`}>
                            {req.status || "Not Assessed"}
                          </span>
                        </td>
                        <td style={{ minWidth: "200px" }}>
                          {req.mapped_controls && req.mapped_controls.length > 0 ? (
                            <div className="controls-list">
                              {req.mapped_controls.map((mc) => (
                                <span key={mc.id || mc.name} className="control-chip">
                                  {mc.name}
                                  <span className={`strength-tag ${mc.mapping_strength === "Direct" ? "strength-direct" : "strength-sup"}`}>
                                    {mc.mapping_strength || "Supporting"}
                                  </span>
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-muted text-xs">Not Mapped</span>
                          )}
                        </td>
                        <td className="desc-cell" style={{ maxWidth: "200px" }}>
                          {req.notes ? (
                            <span title={req.notes}>{req.notes}</span>
                          ) : (
                            <span className="text-muted text-xs">No notes recorded</span>
                          )}
                        </td>
                        <td>
                          <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                            <button
                              className="btn-action"
                              onClick={() => setViewingRequirement(req)}
                              title="View Requirement Details"
                            >
                              Details
                            </button>
                            <button
                              className="btn-action"
                              onClick={() => openRequirementModal(req)}
                              title="Update Assessment Status"
                            >
                              Assess
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          );
        };

        return (
          <section className="panel compliance-panel">
            {/* Header with Title & Factual Disclaimer */}
            <div className="panel-header compliance-page-header">
              <div>
                <div className="section-tag">GOVERNANCE & REGULATORY POSTURE (PHASE 6)</div>
                <h2>Compliance Framework Management</h2>
                <p className="panel-desc">
                  Mapped technical safeguards, implementation tracking, and readiness evaluation across authoritative cybersecurity standards (reviewed prototype subset).
                </p>
              </div>

              {/* Segmented Sub-navigation Tabs */}
              <div className="compliance-sub-nav">
                <button
                  className={`compliance-sub-nav-btn ${complianceSubTab === "overview" ? "active" : ""}`}
                  onClick={() => {
                    setComplianceSubTab("overview");
                    setComplianceFunctionFilter("All");
                  }}
                >
                  <span>Overview</span>
                  <span className="compliance-sub-nav-badge">{requirements.length}</span>
                </button>
                <button
                  className={`compliance-sub-nav-btn ${complianceSubTab === "nist" ? "active" : ""}`}
                  onClick={() => {
                    setComplianceSubTab("nist");
                    setComplianceFunctionFilter("All");
                  }}
                >
                  <span>NIST CSF 2.0</span>
                  <span className="compliance-sub-nav-badge">{nistReqs.length}</span>
                </button>
                <button
                  className={`compliance-sub-nav-btn ${complianceSubTab === "iso" ? "active" : ""}`}
                  onClick={() => {
                    setComplianceSubTab("iso");
                    setComplianceFunctionFilter("All");
                  }}
                >
                  <span>ISO/IEC 27001:2022</span>
                  <span className="compliance-sub-nav-badge">{isoReqs.length}</span>
                </button>
              </div>
            </div>

            {/* Factual Disclaimer Banner */}
            <div className="disclaimer-banner">
              <span className="info-icon">ℹ️</span>
              <span>
                <strong>Factual Note:</strong> Implementation Coverage reflects mapped requirement implementation status in this platform. It is not a certification or independent compliance assessment.
              </span>
            </div>

            {/* ========================================================================= */}
            {/* SUB-VIEW 1: COMPLIANCE OVERVIEW                                           */}
            {/* ========================================================================= */}
            {complianceSubTab === "overview" && (
              <>
                {/* Executive KPI Summary Cards (6 Cards) */}
                <div className="compliance-kpi-grid">
                  <div className="compliance-kpi-card">
                    <div className="compliance-kpi-header">
                      <span className="compliance-kpi-label">Frameworks</span>
                      <span className="compliance-kpi-icon">📜</span>
                    </div>
                    <div className="compliance-kpi-val text-accent">
                      {frameworks.length || 2}
                    </div>
                    <div className="compliance-kpi-sub">
                      NIST CSF 2.0 & ISO/IEC 27001:2022
                    </div>
                  </div>

                  <div className="compliance-kpi-card">
                    <div className="compliance-kpi-header">
                      <span className="compliance-kpi-label">Requirements</span>
                      <span className="compliance-kpi-icon">📋</span>
                    </div>
                    <div className="compliance-kpi-val text-light">
                      {overallMetrics.total}
                    </div>
                    <div className="compliance-kpi-sub">
                      Reviewed prototype subset
                    </div>
                  </div>

                  <div className="compliance-kpi-card">
                    <div className="compliance-kpi-header">
                      <span className="compliance-kpi-label">Implemented</span>
                      <span className="compliance-kpi-icon">✅</span>
                    </div>
                    <div className="compliance-kpi-val text-green">
                      {overallMetrics.implemented}
                    </div>
                    <div className="compliance-kpi-sub">
                      {overallMetrics.total > 0 ? `${((overallMetrics.implemented / overallMetrics.total) * 100).toFixed(0)}% of total requirements` : "—"}
                    </div>
                  </div>

                  <div className="compliance-kpi-card">
                    <div className="compliance-kpi-header">
                      <span className="compliance-kpi-label">Partially Implemented</span>
                      <span className="compliance-kpi-icon">⚠️</span>
                    </div>
                    <div className="compliance-kpi-val text-yellow">
                      {overallMetrics.partiallyImplemented}
                    </div>
                    <div className="compliance-kpi-sub">
                      In-progress safeguard deployment
                    </div>
                  </div>

                  <div className="compliance-kpi-card">
                    <div className="compliance-kpi-header">
                      <span className="compliance-kpi-label">Not Implemented</span>
                      <span className="compliance-kpi-icon">❌</span>
                    </div>
                    <div className="compliance-kpi-val text-red">
                      {overallMetrics.notImplemented}
                    </div>
                    <div className="compliance-kpi-sub">
                      Identified compliance gaps
                    </div>
                  </div>

                  <div className="compliance-kpi-card">
                    <div className="compliance-kpi-header">
                      <span className="compliance-kpi-label">Not Assessed / N/A</span>
                      <span className="compliance-kpi-icon">⚖️</span>
                    </div>
                    <div className="compliance-kpi-val text-slate">
                      {overallMetrics.notAssessed + overallMetrics.notApplicable}
                    </div>
                    <div className="compliance-kpi-sub">
                      {overallMetrics.notAssessed} Not Assessed • {overallMetrics.notApplicable} N/A
                    </div>
                  </div>
                </div>

                {/* Framework Implementation Coverage Banner (Authoritative Backend Summaries) */}
                <div className="compliance-coverage-banner">
                  <div className="compliance-coverage-main">
                    <div className="compliance-coverage-meta">
                      <div className="compliance-coverage-tag">PROGRAM POSTURE</div>
                      <h3 className="compliance-coverage-title">Framework Implementation Coverage</h3>
                      <p className="compliance-coverage-desc">
                        Authoritative framework implementation coverage reported directly by the backend API (<code>/compliance/summary</code>).
                      </p>
                    </div>
                    <div className="compliance-coverage-score-box">
                      <div className="compliance-fw-coverage-pair">
                        <div className="compliance-fw-coverage-item">
                          <span className="compliance-fw-coverage-label">NIST CSF 2.0:</span>
                          <span className="compliance-fw-coverage-value text-accent">
                            {nistCoverage != null ? `${nistCoverage}%` : "Not Available"}
                          </span>
                        </div>
                        <div className="compliance-fw-coverage-item">
                          <span className="compliance-fw-coverage-label">ISO/IEC 27001:2022:</span>
                          <span className="compliance-fw-coverage-value text-accent">
                            {isoCoverage != null ? `${isoCoverage}%` : "Not Available"}
                          </span>
                        </div>
                      </div>
                      <div className="compliance-coverage-denom">
                        Direct API summary values from authoritative GRC engine
                      </div>
                    </div>
                  </div>

                  {/* Proportional Segmented Status Distribution Bar */}
                  {renderStatusDistribution(overallMetrics)}
                </div>

                {/* Framework Coverage Cards (2 Cards) */}
                <div className="compliance-framework-grid-two">
                  {/* NIST CSF Card */}
                  <div className="compliance-fw-card-full">
                    <div className="compliance-fw-top">
                      <div className="compliance-fw-badge-row">
                        <span className="compliance-fw-tag-primary">NIST CSF 2.0</span>
                        <span className="compliance-fw-version-pill">v{nistFw.version}</span>
                        <span className="compliance-subset-badge">Prototype Subset</span>
                      </div>
                      <div className="compliance-fw-score">
                        <span className="compliance-fw-score-val text-accent">
                          {nistCoverage != null ? `${nistCoverage}%` : "Not Available"}
                        </span>
                        <span className="compliance-fw-score-lbl">Implementation Coverage</span>
                      </div>
                    </div>
                    <h3 className="compliance-fw-heading">NIST Cybersecurity Framework</h3>
                    <p className="compliance-fw-desc">{nistFw.description}</p>

                    <div className="compliance-fw-mini-progress">
                      <div
                        className="compliance-fw-mini-fill"
                        style={{ width: `${Math.min(100, nistCoverage || 0)}%` }}
                      />
                    </div>

                    <div className="compliance-fw-stats-row">
                      <div className="compliance-fw-stat-col">
                        <span className="compliance-fw-stat-num text-light">{nistMetrics.total}</span>
                        <span className="compliance-fw-stat-lbl">Total</span>
                      </div>
                      <div className="compliance-fw-stat-col">
                        <span className="compliance-fw-stat-num text-green">{nistMetrics.implemented}</span>
                        <span className="compliance-fw-stat-lbl">Implemented</span>
                      </div>
                      <div className="compliance-fw-stat-col">
                        <span className="compliance-fw-stat-num text-yellow">{nistMetrics.partiallyImplemented}</span>
                        <span className="compliance-fw-stat-lbl">Partial</span>
                      </div>
                      <div className="compliance-fw-stat-col">
                        <span className="compliance-fw-stat-num text-red">{nistMetrics.notImplemented}</span>
                        <span className="compliance-fw-stat-lbl">Not Impl.</span>
                      </div>
                      <div className="compliance-fw-stat-col">
                        <span className="compliance-fw-stat-num text-slate">{nistMetrics.notAssessed}</span>
                        <span className="compliance-fw-stat-lbl">Not Assessed</span>
                      </div>
                      <div className="compliance-fw-stat-col">
                        <span className="compliance-fw-stat-num text-muted">{nistMetrics.notApplicable}</span>
                        <span className="compliance-fw-stat-lbl">N/A</span>
                      </div>
                    </div>

                    <div className="compliance-fw-actions">
                      <button
                        className="btn-secondary compliance-fw-btn"
                        onClick={() => {
                          setComplianceSubTab("nist");
                          setComplianceFunctionFilter("All");
                        }}
                      >
                        Open NIST CSF View →
                      </button>
                    </div>
                  </div>

                  {/* ISO/IEC 27001 Card */}
                  <div className="compliance-fw-card-full">
                    <div className="compliance-fw-top">
                      <div className="compliance-fw-badge-row">
                        <span className="compliance-fw-tag-primary">ISO/IEC 27001:2022</span>
                        <span className="compliance-fw-version-pill">v{isoFw.version}</span>
                        <span className="compliance-subset-badge">Prototype Subset</span>
                      </div>
                      <div className="compliance-fw-score">
                        <span className="compliance-fw-score-val text-accent">
                          {isoCoverage != null ? `${isoCoverage}%` : "Not Available"}
                        </span>
                        <span className="compliance-fw-score-lbl">Implementation Coverage</span>
                      </div>
                    </div>
                    <h3 className="compliance-fw-heading">Information Security Management</h3>
                    <p className="compliance-fw-desc">{isoFw.description}</p>

                    <div className="compliance-fw-mini-progress">
                      <div
                        className="compliance-fw-mini-fill"
                        style={{ width: `${Math.min(100, isoCoverage || 0)}%` }}
                      />
                    </div>

                    <div className="compliance-fw-stats-row">
                      <div className="compliance-fw-stat-col">
                        <span className="compliance-fw-stat-num text-light">{isoMetrics.total}</span>
                        <span className="compliance-fw-stat-lbl">Total</span>
                      </div>
                      <div className="compliance-fw-stat-col">
                        <span className="compliance-fw-stat-num text-green">{isoMetrics.implemented}</span>
                        <span className="compliance-fw-stat-lbl">Implemented</span>
                      </div>
                      <div className="compliance-fw-stat-col">
                        <span className="compliance-fw-stat-num text-yellow">{isoMetrics.partiallyImplemented}</span>
                        <span className="compliance-fw-stat-lbl">Partial</span>
                      </div>
                      <div className="compliance-fw-stat-col">
                        <span className="compliance-fw-stat-num text-red">{isoMetrics.notImplemented}</span>
                        <span className="compliance-fw-stat-lbl">Not Impl.</span>
                      </div>
                      <div className="compliance-fw-stat-col">
                        <span className="compliance-fw-stat-num text-slate">{isoMetrics.notAssessed}</span>
                        <span className="compliance-fw-stat-lbl">Not Assessed</span>
                      </div>
                      <div className="compliance-fw-stat-col">
                        <span className="compliance-fw-stat-num text-muted">{isoMetrics.notApplicable}</span>
                        <span className="compliance-fw-stat-lbl">N/A</span>
                      </div>
                    </div>

                    <div className="compliance-fw-actions">
                      <button
                        className="btn-secondary compliance-fw-btn"
                        onClick={() => {
                          setComplianceSubTab("iso");
                          setComplianceFunctionFilter("All");
                        }}
                      >
                        Open ISO/IEC 27001 View →
                      </button>
                    </div>
                  </div>
                </div>

                {/* Comprehensive Evaluated Requirement Inventory */}
                <div className="compliance-inventory-section">
                  <div className="compliance-inventory-header">
                    <div>
                      <h3 className="compliance-inventory-title">Evaluated Requirement Inventory</h3>
                      <p className="compliance-inventory-sub">
                        All mapped safeguard controls across evaluated standards. Filter by framework, status, function, or mapping strength.
                      </p>
                    </div>
                    <span className="compliance-inventory-count">
                      Showing <strong>{filteredReqs.length}</strong> of <strong>{requirements.length}</strong> requirements
                    </span>
                  </div>

                  {/* Filter and Search Bar */}
                  <div className="compliance-filter-bar">
                    <div className="compliance-search-box">
                      <span className="compliance-search-icon">🔍</span>
                      <input
                        type="text"
                        placeholder="Search by ID, title, description, function, or mapped control..."
                        value={complianceSearchQuery}
                        onChange={(e) => setComplianceSearchQuery(e.target.value)}
                        className="compliance-search-input"
                      />
                      {complianceSearchQuery && (
                        <button
                          className="compliance-search-clear"
                          onClick={() => setComplianceSearchQuery("")}
                        >
                          ×
                        </button>
                      )}
                    </div>

                    <div className="compliance-filters-row">
                      <div className="compliance-filter-item">
                        <label>Framework:</label>
                        <select
                          value={complianceFrameworkFilter}
                          onChange={(e) => setComplianceFrameworkFilter(e.target.value)}
                          className="select-filter"
                        >
                          <option value="All">All Frameworks ({requirements.length})</option>
                          <option value="NIST CSF">NIST CSF ({nistReqs.length})</option>
                          <option value="ISO/IEC 27001">ISO/IEC 27001 ({isoReqs.length})</option>
                        </select>
                      </div>

                      <div className="compliance-filter-item">
                        <label>Status:</label>
                        <select
                          value={complianceStatusFilter}
                          onChange={(e) => setComplianceStatusFilter(e.target.value)}
                          className="select-filter"
                        >
                          <option value="All">All Statuses</option>
                          <option value="Implemented">Implemented</option>
                          <option value="Partially Implemented">Partially Implemented</option>
                          <option value="Not Implemented">Not Implemented</option>
                          <option value="Not Assessed">Not Assessed</option>
                          <option value="Not Applicable">Not Applicable</option>
                        </select>
                      </div>

                      <div className="compliance-filter-item">
                        <label>Function / Domain:</label>
                        <select
                          value={complianceFunctionFilter}
                          onChange={(e) => setComplianceFunctionFilter(e.target.value)}
                          className="select-filter"
                        >
                          {availableDropdownFunctions.map((fn) => (
                            <option key={fn} value={fn}>{fn}</option>
                          ))}
                        </select>
                      </div>

                      <div className="compliance-filter-item">
                        <label>Mapping Strength:</label>
                        <select
                          value={complianceStrengthFilter}
                          onChange={(e) => setComplianceStrengthFilter(e.target.value)}
                          className="select-filter"
                        >
                          <option value="All">All Mappings</option>
                          <option value="Direct">Direct Mappings</option>
                          <option value="Supporting">Supporting Mappings</option>
                          <option value="Unmapped">Unmapped Controls</option>
                        </select>
                      </div>

                      {hasActiveFilters && (
                        <button
                          className="btn-link compliance-reset-btn"
                          onClick={resetFilters}
                        >
                          Reset Filters
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Requirements Table */}
                  {renderRequirementsTable(filteredReqs, true)}
                </div>
              </>
            )}

            {/* ========================================================================= */}
            {/* SUB-VIEW 2: NIST CSF 2.0 VIEW                                             */}
            {/* ========================================================================= */}
            {complianceSubTab === "nist" && (
              <>
                {/* NIST CSF Banner */}
                <div className="compliance-framework-banner">
                  <div className="compliance-fw-banner-left">
                    <div className="compliance-fw-badge-row">
                      <span className="compliance-fw-tag-primary">NIST CSF 2.0</span>
                      <span className="compliance-fw-version-pill">v{nistFw.version}</span>
                      <span className="compliance-subset-badge">Reviewed Prototype Subset</span>
                    </div>
                    <h3 className="compliance-fw-banner-title">NIST Cybersecurity Framework 2.0</h3>
                    <p className="compliance-fw-banner-desc">{nistFw.description}</p>
                  </div>
                  <div className="compliance-fw-banner-right">
                    <div className="compliance-fw-banner-stat">
                      <span className="compliance-fw-banner-num text-accent">
                        {nistCoverage != null ? `${nistCoverage}%` : "Not Available"}
                      </span>
                      <span className="compliance-fw-banner-lbl">Implementation Coverage</span>
                    </div>
                    <div className="compliance-fw-banner-stat">
                      <span className="compliance-fw-banner-num text-light">
                        {nistMetrics.implemented} / {nistMetrics.total}
                      </span>
                      <span className="compliance-fw-banner-lbl">Requirements Implemented</span>
                    </div>
                  </div>
                </div>

                {/* NIST Status Distribution */}
                {renderStatusDistribution(nistMetrics)}

                {/* 6 Core Functions Breakdown Cards Grid */}
                <div className="compliance-section-subhead">
                  <h4>NIST CSF 2.0 Core Functions ({NIST_FUNCTIONS.length})</h4>
                  <span className="text-muted text-xs">
                    Click any function to filter the requirement register below
                  </span>
                </div>

                <div className="compliance-functions-grid">
                  {NIST_FUNCTIONS.map((fn) => {
                    const fnReqs = nistReqs.filter(r => (r.function || "").toLowerCase() === fn.name.toLowerCase());
                    const fnMetrics = aggregateCounts(fnReqs);
                    const fnControlsCount = fnReqs.reduce((acc, r) => acc + (r.mapped_controls ? r.mapped_controls.length : 0), 0);
                    const isSelected = complianceFunctionFilter.toLowerCase() === fn.name.toLowerCase();

                    return (
                      <div
                        key={fn.name}
                        className={`compliance-function-card ${isSelected ? "active" : ""}`}
                        onClick={() => {
                          if (isSelected) {
                            setComplianceFunctionFilter("All");
                          } else {
                            setComplianceFunctionFilter(fn.name);
                          }
                        }}
                      >
                        <div className="compliance-fn-header">
                          <div>
                            <span className="compliance-fn-code">{fn.code}</span>
                            <span className="compliance-fn-name">{fn.name}</span>
                          </div>
                          <span className="compliance-fn-badge">
                            {fnReqs.length} {fnReqs.length === 1 ? "Req" : "Reqs"}
                          </span>
                        </div>
                        <p className="compliance-fn-desc">{fn.desc}</p>

                        <div className="compliance-fn-status-counts-row">
                          <span className="compliance-fn-count-pill text-green">
                            <strong>{fnMetrics.implemented}</strong> Impl
                          </span>
                          <span className="compliance-fn-count-pill text-yellow">
                            <strong>{fnMetrics.partiallyImplemented}</strong> Part
                          </span>
                          <span className="compliance-fn-count-pill text-red">
                            <strong>{fnMetrics.notImplemented}</strong> Not Impl
                          </span>
                          <span className="compliance-fn-count-pill text-slate">
                            <strong>{fnMetrics.notAssessed}</strong> Not Assessed
                          </span>
                        </div>

                        <div className="compliance-fn-footer">
                          <span className="text-muted text-xs">
                            {fnReqs.length} {fnReqs.length === 1 ? "evaluated requirement" : "evaluated requirements"}
                          </span>
                          <span className="compliance-fn-controls-count">
                            {fnControlsCount} mapped {fnControlsCount === 1 ? "control" : "controls"}
                          </span>
                        </div>

                        <div className="compliance-fn-filter-indicator">
                          {isSelected ? "✓ Active Filter (Click to clear)" : "Click to filter table"}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* NIST Filter and Table */}
                <div className="compliance-inventory-section">
                  <div className="compliance-inventory-header">
                    <div>
                      <h3 className="compliance-inventory-title">NIST CSF 2.0 Requirement Register</h3>
                      <p className="compliance-inventory-sub">
                        Showing evaluated requirements across the 6 Core Functions with mapped security controls.
                      </p>
                    </div>
                    <span className="compliance-inventory-count">
                      Showing <strong>{filteredReqs.length}</strong> of <strong>{nistReqs.length}</strong> requirements
                    </span>
                  </div>

                  {/* Filter and Search Bar */}
                  <div className="compliance-filter-bar">
                    <div className="compliance-search-box">
                      <span className="compliance-search-icon">🔍</span>
                      <input
                        type="text"
                        placeholder="Search NIST requirements, code, description, or mapped control..."
                        value={complianceSearchQuery}
                        onChange={(e) => setComplianceSearchQuery(e.target.value)}
                        className="compliance-search-input"
                      />
                      {complianceSearchQuery && (
                        <button
                          className="compliance-search-clear"
                          onClick={() => setComplianceSearchQuery("")}
                        >
                          ×
                        </button>
                      )}
                    </div>

                    <div className="compliance-filters-row">
                      <div className="compliance-filter-item">
                        <label>Function:</label>
                        <select
                          value={complianceFunctionFilter}
                          onChange={(e) => setComplianceFunctionFilter(e.target.value)}
                          className="select-filter"
                        >
                          <option value="All">All Functions ({nistReqs.length})</option>
                          {NIST_FUNCTIONS.map((fn) => (
                            <option key={fn.name} value={fn.name}>{fn.name} ({fn.code})</option>
                          ))}
                        </select>
                      </div>

                      <div className="compliance-filter-item">
                        <label>Status:</label>
                        <select
                          value={complianceStatusFilter}
                          onChange={(e) => setComplianceStatusFilter(e.target.value)}
                          className="select-filter"
                        >
                          <option value="All">All Statuses</option>
                          <option value="Implemented">Implemented</option>
                          <option value="Partially Implemented">Partially Implemented</option>
                          <option value="Not Implemented">Not Implemented</option>
                          <option value="Not Assessed">Not Assessed</option>
                          <option value="Not Applicable">Not Applicable</option>
                        </select>
                      </div>

                      <div className="compliance-filter-item">
                        <label>Mapping Strength:</label>
                        <select
                          value={complianceStrengthFilter}
                          onChange={(e) => setComplianceStrengthFilter(e.target.value)}
                          className="select-filter"
                        >
                          <option value="All">All Mappings</option>
                          <option value="Direct">Direct Mappings</option>
                          <option value="Supporting">Supporting Mappings</option>
                          <option value="Unmapped">Unmapped Controls</option>
                        </select>
                      </div>

                      {hasActiveFilters && (
                        <button
                          className="btn-link compliance-reset-btn"
                          onClick={resetFilters}
                        >
                          Reset Filters
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Requirements Table */}
                  {renderRequirementsTable(filteredReqs, false)}
                </div>
              </>
            )}

            {/* ========================================================================= */}
            {/* SUB-VIEW 3: ISO/IEC 27001:2022 VIEW                                       */}
            {/* ========================================================================= */}
            {complianceSubTab === "iso" && (
              <>
                {/* ISO/IEC 27001 Banner */}
                <div className="compliance-framework-banner">
                  <div className="compliance-fw-banner-left">
                    <div className="compliance-fw-badge-row">
                      <span className="compliance-fw-tag-primary">ISO/IEC 27001:2022</span>
                      <span className="compliance-fw-version-pill">v{isoFw.version}</span>
                      <span className="compliance-subset-badge">Reviewed Prototype Subset</span>
                    </div>
                    <h3 className="compliance-fw-banner-title">ISO/IEC 27001:2022 Annex A Controls</h3>
                    <p className="compliance-fw-banner-desc">{isoFw.description}</p>
                  </div>
                  <div className="compliance-fw-banner-right">
                    <div className="compliance-fw-banner-stat">
                      <span className="compliance-fw-banner-num text-accent">
                        {isoCoverage != null ? `${isoCoverage}%` : "Not Available"}
                      </span>
                      <span className="compliance-fw-banner-lbl">Implementation Coverage</span>
                    </div>
                    <div className="compliance-fw-banner-stat">
                      <span className="compliance-fw-banner-num text-light">
                        {isoMetrics.implemented} / {isoMetrics.total}
                      </span>
                      <span className="compliance-fw-banner-lbl">Requirements Implemented</span>
                    </div>
                  </div>
                </div>

                {/* ISO Status Distribution */}
                {renderStatusDistribution(isoMetrics)}

                {/* 4 Themes / Domains Breakdown Cards Grid */}
                <div className="compliance-section-subhead">
                  <h4>ISO/IEC 27001:2022 Annex A Themes ({ISO_DOMAINS.length})</h4>
                  <span className="text-muted text-xs">
                    Click any theme to filter the requirement register below
                  </span>
                </div>

                <div className="compliance-functions-grid iso-grid-four">
                  {ISO_DOMAINS.map((dom) => {
                    const domReqs = isoReqs.filter(r => (r.function || "").toLowerCase() === dom.name.toLowerCase());
                    const domMetrics = aggregateCounts(domReqs);
                    const domControlsCount = domReqs.reduce((acc, r) => acc + (r.mapped_controls ? r.mapped_controls.length : 0), 0);
                    const isSelected = complianceFunctionFilter.toLowerCase() === dom.name.toLowerCase();

                    return (
                      <div
                        key={dom.name}
                        className={`compliance-function-card ${isSelected ? "active" : ""}`}
                        onClick={() => {
                          if (isSelected) {
                            setComplianceFunctionFilter("All");
                          } else {
                            setComplianceFunctionFilter(dom.name);
                          }
                        }}
                      >
                        <div className="compliance-fn-header">
                          <div>
                            <span className="compliance-fn-code">{dom.code}</span>
                            <span className="compliance-fn-name">{dom.name}</span>
                          </div>
                          <span className="compliance-fn-badge">
                            {domReqs.length} {domReqs.length === 1 ? "Req" : "Reqs"}
                          </span>
                        </div>
                        <p className="compliance-fn-desc">{dom.desc}</p>

                        <div className="compliance-fn-status-counts-row">
                          <span className="compliance-fn-count-pill text-green">
                            <strong>{domMetrics.implemented}</strong> Impl
                          </span>
                          <span className="compliance-fn-count-pill text-yellow">
                            <strong>{domMetrics.partiallyImplemented}</strong> Part
                          </span>
                          <span className="compliance-fn-count-pill text-red">
                            <strong>{domMetrics.notImplemented}</strong> Not Impl
                          </span>
                          <span className="compliance-fn-count-pill text-slate">
                            <strong>{domMetrics.notAssessed}</strong> Not Assessed
                          </span>
                        </div>

                        <div className="compliance-fn-footer">
                          <span className="text-muted text-xs">
                            {domReqs.length} {domReqs.length === 1 ? "evaluated requirement" : "evaluated requirements"}
                          </span>
                          <span className="compliance-fn-controls-count">
                            {domControlsCount} mapped {domControlsCount === 1 ? "control" : "controls"}
                          </span>
                        </div>

                        <div className="compliance-fn-filter-indicator">
                          {isSelected ? "✓ Active Filter (Click to clear)" : "Click to filter table"}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* ISO Filter and Table */}
                <div className="compliance-inventory-section">
                  <div className="compliance-inventory-header">
                    <div>
                      <h3 className="compliance-inventory-title">ISO/IEC 27001:2022 Requirement Register</h3>
                      <p className="compliance-inventory-sub">
                        Showing evaluated Annex A requirements across the 4 thematic domains with mapped security controls.
                      </p>
                    </div>
                    <span className="compliance-inventory-count">
                      Showing <strong>{filteredReqs.length}</strong> of <strong>{isoReqs.length}</strong> requirements
                    </span>
                  </div>

                  {/* Filter and Search Bar */}
                  <div className="compliance-filter-bar">
                    <div className="compliance-search-box">
                      <span className="compliance-search-icon">🔍</span>
                      <input
                        type="text"
                        placeholder="Search ISO requirements, code, description, or mapped control..."
                        value={complianceSearchQuery}
                        onChange={(e) => setComplianceSearchQuery(e.target.value)}
                        className="compliance-search-input"
                      />
                      {complianceSearchQuery && (
                        <button
                          className="compliance-search-clear"
                          onClick={() => setComplianceSearchQuery("")}
                        >
                          ×
                        </button>
                      )}
                    </div>

                    <div className="compliance-filters-row">
                      <div className="compliance-filter-item">
                        <label>Domain / Theme:</label>
                        <select
                          value={complianceFunctionFilter}
                          onChange={(e) => setComplianceFunctionFilter(e.target.value)}
                          className="select-filter"
                        >
                          <option value="All">All Domains ({isoReqs.length})</option>
                          {ISO_DOMAINS.map((dom) => (
                            <option key={dom.name} value={dom.name}>{dom.name} ({dom.code})</option>
                          ))}
                        </select>
                      </div>

                      <div className="compliance-filter-item">
                        <label>Status:</label>
                        <select
                          value={complianceStatusFilter}
                          onChange={(e) => setComplianceStatusFilter(e.target.value)}
                          className="select-filter"
                        >
                          <option value="All">All Statuses</option>
                          <option value="Implemented">Implemented</option>
                          <option value="Partially Implemented">Partially Implemented</option>
                          <option value="Not Implemented">Not Implemented</option>
                          <option value="Not Assessed">Not Assessed</option>
                          <option value="Not Applicable">Not Applicable</option>
                        </select>
                      </div>

                      <div className="compliance-filter-item">
                        <label>Mapping Strength:</label>
                        <select
                          value={complianceStrengthFilter}
                          onChange={(e) => setComplianceStrengthFilter(e.target.value)}
                          className="select-filter"
                        >
                          <option value="All">All Mappings</option>
                          <option value="Direct">Direct Mappings</option>
                          <option value="Supporting">Supporting Mappings</option>
                          <option value="Unmapped">Unmapped Controls</option>
                        </select>
                      </div>

                      {hasActiveFilters && (
                        <button
                          className="btn-link compliance-reset-btn"
                          onClick={resetFilters}
                        >
                          Reset Filters
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Requirements Table */}
                  {renderRequirementsTable(filteredReqs, false)}
                </div>
              </>
            )}
          </section>
        );
      })()}

      {/* -------------------------------- */}
      {/* VULNERABILITY FINDINGS (Phase 4) */}
      {/* -------------------------------- */}
      {activePage === "vulnerabilities" && (() => {
        const totalVulns = vulnerabilities.length;
        const criticalVulns = vulnerabilities.filter(
          (v) => (v.severity || "").toLowerCase() === "critical"
        ).length;
        const highVulns = vulnerabilities.filter(
          (v) => (v.severity || "").toLowerCase() === "high"
        ).length;
        const mediumVulns = vulnerabilities.filter(
          (v) => (v.severity || "").toLowerCase() === "medium"
        ).length;
        const lowVulns = vulnerabilities.filter(
          (v) => (v.severity || "").toLowerCase() === "low"
        ).length;
        const unknownSeverityVulns = vulnerabilities.filter(
          (v) => !["critical", "high", "medium", "low"].includes((v.severity || "").toLowerCase())
        ).length;

        const uniqueAssetIds = new Set(
          vulnerabilities.map((v) => v.asset_id).filter((id) => id != null)
        );
        const affectedAssetsCount = uniqueAssetIds.size;

        const pct = (cnt) => (totalVulns > 0 ? ((cnt / totalVulns) * 100).toFixed(1) : "0.0");

        const filteredVulns = vulnerabilities.filter((v) => {
          // Search matching
          if (vulnSearchQuery.trim()) {
            const q = vulnSearchQuery.toLowerCase().trim();
            const title = (v.title || "").toLowerCase();
            const cve = (v.cve || "").toLowerCase();
            const desc = (v.description || "").toLowerCase();
            const service = (v.service || "").toLowerCase();
            const product = (v.product || "").toLowerCase();

            const asset = assets.find((a) => a.id === v.asset_id);
            const assetIp = (asset?.ip_address || "").toLowerCase();
            const assetHost = (asset?.hostname || "").toLowerCase();

            if (
              !title.includes(q) &&
              !cve.includes(q) &&
              !desc.includes(q) &&
              !service.includes(q) &&
              !product.includes(q) &&
              !assetIp.includes(q) &&
              !assetHost.includes(q)
            ) {
              return false;
            }
          }

          // Severity filter
          if (vulnSeverityFilter !== "All") {
            const sev = (v.severity || "").toLowerCase();
            if (vulnSeverityFilter.toLowerCase() === "unknown") {
              if (["critical", "high", "medium", "low"].includes(sev)) return false;
            } else {
              if (sev !== vulnSeverityFilter.toLowerCase()) return false;
            }
          }

          // Status filter
          if (vulnStatusFilter !== "All") {
            const st = (v.status || "Open").toLowerCase();
            if (st !== vulnStatusFilter.toLowerCase()) return false;
          }

          return true;
        });

        const hasActiveVulnFilters =
          vulnSearchQuery.trim() !== "" ||
          vulnSeverityFilter !== "All" ||
          vulnStatusFilter !== "All";

        const resetVulnFilters = () => {
          setVulnSearchQuery("");
          setVulnSeverityFilter("All");
          setVulnStatusFilter("All");
        };

        return (
          <>
            {/* 1. VULNERABILITY SUMMARY: Compact KPI Cards */}
            <section className="cards cards-six">
              <div className="card">
                <div className="card-label">Total Findings</div>
                <div className="card-val">{totalVulns}</div>
                <div className="card-sub">
                  {affectedAssetsCount} affected {affectedAssetsCount === 1 ? "host" : "hosts"}
                </div>
              </div>

              <div className="card">
                <div className="card-label">Critical</div>
                <div className="card-val highlight-critical">{criticalVulns}</div>
                <div className="card-sub">{pct(criticalVulns)}% of findings</div>
              </div>

              <div className="card">
                <div className="card-label">High</div>
                <div className="card-val highlight-orange">{highVulns}</div>
                <div className="card-sub">{pct(highVulns)}% of findings</div>
              </div>

              <div className="card">
                <div className="card-label">Medium</div>
                <div className="card-val highlight-amber">{mediumVulns}</div>
                <div className="card-sub">{pct(mediumVulns)}% of findings</div>
              </div>

              <div className="card">
                <div className="card-label">Low</div>
                <div className="card-val highlight-blue">{lowVulns}</div>
                <div className="card-sub">{pct(lowVulns)}% of findings</div>
              </div>

              <div className="card">
                <div className="card-label">Affected Assets</div>
                <div className="card-val highlight-green">{affectedAssetsCount}</div>
                <div className="card-sub">of {assets.length} monitored assets</div>
              </div>
            </section>

            {/* Unknown severity callout if any exist */}
            {unknownSeverityVulns > 0 && (
              <div className="asset-unclassified-banner">
                <div className="asset-unclassified-icon">⚠️</div>
                <div className="asset-unclassified-content">
                  <div className="asset-unclassified-title">
                    {unknownSeverityVulns} {unknownSeverityVulns === 1 ? "finding has" : "findings have"} unclassified severity
                  </div>
                  <div className="asset-unclassified-desc">
                    These vulnerability detections do not have an authoritative severity level assigned by scanner enrichment. Review the findings below to inspect raw detection details.
                  </div>
                </div>
                <div className="asset-unclassified-actions">
                  <button
                    type="button"
                    className="btn-action-view"
                    onClick={() => {
                      setVulnSeverityFilter("Unknown");
                      setVulnSearchQuery("");
                    }}
                  >
                    View Unclassified ({unknownSeverityVulns})
                  </button>
                </div>
              </div>
            )}

            {/* 2. SEVERITY EXPOSURE VISUALIZATION */}
            <div className="vuln-distribution-box">
              <div className="vuln-distribution-header">
                <div>
                  <span className="vuln-dist-title">🎯 Severity Exposure Distribution</span>
                  <span className="vuln-dist-sub">
                    {totalVulns > 0
                      ? `${criticalVulns + highVulns} critical & high exposure findings (${pct(criticalVulns + highVulns)}%)`
                      : "No findings recorded"}
                  </span>
                </div>
                <span className="vuln-dist-meta">{totalVulns} Total Correlated Findings</span>
              </div>

              {totalVulns === 0 ? (
                <div className="overview-empty">
                  <span className="overview-empty-icon">🔍</span>
                  No vulnerability findings recorded yet. Run a network scan to detect technical vulnerabilities.
                </div>
              ) : (
                <>
                  {/* Segmented proportional bar */}
                  <div
                    className="segmented-bar"
                    title={`Critical: ${criticalVulns}, High: ${highVulns}, Medium: ${mediumVulns}, Low: ${lowVulns}${unknownSeverityVulns > 0 ? `, Unknown: ${unknownSeverityVulns}` : ""}`}
                  >
                    {criticalVulns > 0 && (
                      <div className="segmented-segment critical" style={{ width: `${pct(criticalVulns)}%` }} />
                    )}
                    {highVulns > 0 && (
                      <div className="segmented-segment high" style={{ width: `${pct(highVulns)}%` }} />
                    )}
                    {mediumVulns > 0 && (
                      <div className="segmented-segment medium" style={{ width: `${pct(mediumVulns)}%` }} />
                    )}
                    {lowVulns > 0 && (
                      <div className="segmented-segment low" style={{ width: `${pct(lowVulns)}%` }} />
                    )}
                    {unknownSeverityVulns > 0 && (
                      <div className="segmented-segment unknown" style={{ width: `${pct(unknownSeverityVulns)}%` }} />
                    )}
                  </div>

                  {/* Legend row */}
                  <div className="vuln-legend-row">
                    <div className="vuln-legend-item">
                      <span className="breakdown-dot critical" />
                      <span className="vuln-legend-label">Critical:</span>
                      <strong>{criticalVulns}</strong>
                      <span className="text-muted">({pct(criticalVulns)}%)</span>
                    </div>
                    <div className="vuln-legend-item">
                      <span className="breakdown-dot high" />
                      <span className="vuln-legend-label">High:</span>
                      <strong>{highVulns}</strong>
                      <span className="text-muted">({pct(highVulns)}%)</span>
                    </div>
                    <div className="vuln-legend-item">
                      <span className="breakdown-dot medium" />
                      <span className="vuln-legend-label">Medium:</span>
                      <strong>{mediumVulns}</strong>
                      <span className="text-muted">({pct(mediumVulns)}%)</span>
                    </div>
                    <div className="vuln-legend-item">
                      <span className="breakdown-dot low" />
                      <span className="vuln-legend-label">Low:</span>
                      <strong>{lowVulns}</strong>
                      <span className="text-muted">({pct(lowVulns)}%)</span>
                    </div>
                    {unknownSeverityVulns > 0 && (
                      <div className="vuln-legend-item">
                        <span className="breakdown-dot unknown" />
                        <span className="vuln-legend-label">Unknown:</span>
                        <strong>{unknownSeverityVulns}</strong>
                        <span className="text-muted">({pct(unknownSeverityVulns)}%)</span>
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>

            {/* 3. VULNERABILITY INVENTORY TABLE */}
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Vulnerability Inventory & CVE Intelligence</h2>
                  <p className="panel-desc">
                    Technical security findings correlated with CVE/NVD intelligence, CVSS scoring, and affected infrastructure assets.
                  </p>
                </div>
                <div>
                  <button
                    type="button"
                    className="btn-secondary btn-sm"
                    onClick={() => fetchVulnerabilities()}
                    title="Refresh vulnerability findings from backend"
                  >
                    ↻ Refresh Findings
                  </button>
                </div>
              </div>

              {/* SEARCH & FILTERS TOOLBAR */}
              <div className="asset-toolbar">
                <div className="asset-search-box">
                  <span className="search-icon">🔍</span>
                  <input
                    type="text"
                    className="asset-search-input"
                    placeholder="Search by title, CVE, description, asset, service, product..."
                    value={vulnSearchQuery}
                    onChange={(e) => setVulnSearchQuery(e.target.value)}
                  />
                  {vulnSearchQuery && (
                    <button
                      type="button"
                      className="asset-search-clear"
                      onClick={() => setVulnSearchQuery("")}
                      title="Clear search"
                    >
                      ×
                    </button>
                  )}
                </div>

                <div className="asset-filter-group">
                  <div className="asset-filter-item">
                    <label htmlFor="vuln-sev-filter">Severity:</label>
                    <select
                      id="vuln-sev-filter"
                      className="asset-select"
                      value={vulnSeverityFilter}
                      onChange={(e) => setVulnSeverityFilter(e.target.value)}
                    >
                      <option value="All">All Severities</option>
                      <option value="Critical">Critical</option>
                      <option value="High">High</option>
                      <option value="Medium">Medium</option>
                      <option value="Low">Low</option>
                      {unknownSeverityVulns > 0 && <option value="Unknown">Unknown / Unclassified</option>}
                    </select>
                  </div>

                  <div className="asset-filter-item">
                    <label htmlFor="vuln-status-filter">Status:</label>
                    <select
                      id="vuln-status-filter"
                      className="asset-select"
                      value={vulnStatusFilter}
                      onChange={(e) => setVulnStatusFilter(e.target.value)}
                    >
                      <option value="All">All Statuses</option>
                      <option value="Open">Open</option>
                      <option value="Resolved">Resolved</option>
                    </select>
                  </div>

                  {hasActiveVulnFilters && (
                    <button
                      type="button"
                      className="btn-secondary btn-sm asset-reset-btn"
                      onClick={resetVulnFilters}
                      title="Clear all filters and search"
                    >
                      Reset Filters
                    </button>
                  )}
                </div>
              </div>

              {/* Status bar */}
              <div className="asset-table-meta">
                <span className="asset-count-info">
                  Showing <strong>{filteredVulns.length}</strong> of <strong>{vulnerabilities.length}</strong> findings
                  {hasActiveVulnFilters && " (filtered)"}
                </span>
              </div>

              {/* Table */}
              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Finding Title / ID</th>
                      <th>CVE Reference</th>
                      <th>Severity</th>
                      <th>CVSS Score</th>
                      <th>Affected Asset</th>
                      <th>Port / Service</th>
                      <th>Status</th>
                      <th>Discovered</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vulnerabilities.length === 0 ? (
                      <tr>
                        <td colSpan="9" className="empty-cell">
                          No vulnerability findings recorded yet. Run a network scan to detect technical vulnerabilities.
                        </td>
                      </tr>
                    ) : filteredVulns.length === 0 ? (
                      <tr>
                        <td colSpan="9" className="empty-cell">
                          No vulnerabilities match the active search and filter criteria.{" "}
                          <button
                            type="button"
                            className="btn-link"
                            onClick={resetVulnFilters}
                          >
                            Reset filters
                          </button>
                        </td>
                      </tr>
                    ) : (
                      filteredVulns.map((v) => {
                        const asset = assets.find((a) => a.id === v.asset_id);
                        return (
                          <tr key={v.id}>
                            <td>
                              <div className="font-semibold text-white">{v.title}</div>
                              <div className="sub-text">
                                ID #{v.id}
                                {v.product && ` • ${v.product}${v.version ? ` (${v.version})` : ""}`}
                              </div>
                            </td>
                            <td>
                              {v.cve ? (
                                <div className="cve-cell">
                                  <span className="cve-tag">{v.cve}</span>
                                  {v.cve_confidence && v.cve_confidence !== "None" && (
                                    <span className={`conf-badge conf-${(v.cve_confidence || "none").toLowerCase()}`}>
                                      {v.cve_confidence}
                                    </span>
                                  )}
                                </div>
                              ) : (
                                <span className="text-muted">Not Identified</span>
                              )}
                            </td>
                            <td>
                              <span className={`badge ${getRiskClass(v.severity)}`}>
                                {v.severity || "Unknown"}
                              </span>
                            </td>
                            <td>
                              {v.cvss_score != null ? (
                                <span className="cvss-tag font-mono">
                                  {v.cvss_score} ({v.cvss_version || "v3.1"})
                                </span>
                              ) : (
                                <span className="text-muted">N/A</span>
                              )}
                            </td>
                            <td>
                              {asset ? (
                                <div>
                                  <strong className="ip-text">{asset.ip_address}</strong>
                                  <div className="sub-text">
                                    {asset.hostname || asset.environment || `ID #${asset.id}`}
                                  </div>
                                </div>
                              ) : v.asset_id ? (
                                <span className="ip-pill">Asset #{v.asset_id}</span>
                              ) : (
                                <span className="text-muted">Not Assigned</span>
                              )}
                            </td>
                            <td>
                              <span className="font-mono text-xs">
                                {v.port != null ? v.port : "—"}
                              </span>
                              <span className="text-slate text-xs"> / {v.service || "unknown"}</span>
                            </td>
                            <td>
                              <span className={`status-pill ${getStatusClass(v.status)}`}>
                                {v.status || "Open"}
                              </span>
                            </td>
                            <td>
                              <span className="text-xs text-slate">
                                {formatDateTime(v.discovered_at)}
                              </span>
                            </td>
                            <td>
                              <button
                                type="button"
                                className="btn-action-view"
                                onClick={() => setViewingVuln(v)}
                                title="View Finding Details"
                              >
                                Details
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        );
      })()}

      {/* ------------------------------------------------ */}
      {/* PHASE 8: REVIEWS & SIGN-OFF WORKSPACE           */}
      {/* ------------------------------------------------ */}
      {activePage === "reviews" && (() => {
        // 1. KPI Calculations strictly from application state
        const attentionCount = risks.filter((r) => ["Pending Review", "Stale", "Changes Requested"].includes(r.review_status)).length;
        const pendingCount = risks.filter((r) => r.review_status === "Pending Review").length;
        const staleCount = risks.filter((r) => r.review_status === "Stale").length;
        const changesCount = risks.filter((r) => r.review_status === "Changes Requested").length;
        const approvedCount = risks.filter((r) => r.review_status === "Approved").length;
        const rejectedCount = risks.filter((r) => r.review_status === "Rejected").length;

        // Pending endpoint specific counts (Attention Queue)
        const pendingGovCount = govReviews.filter((e) => e.review_status === "Pending Review").length;
        const staleGovCount = govReviews.filter((e) => e.review_status === "Stale").length;
        const changesGovCount = govReviews.filter((e) => e.review_status === "Changes Requested").length;

        // Lookup map for govReviews items
        const govReviewMap = new Map(govReviews.map((item) => [item.risk.id, item]));

        // 2. Filter logic
        let displayedItems;
        if (reviewsSubTab === "queue") {
          displayedItems = govReviews.filter((item) => {
            const r = item.risk;
            const asset = assets.find((a) => a.id === r.asset_id);
            const status = item.review_status || r.review_status || "Pending Review";

            if (reviewsStatusFilter !== "All" && status !== reviewsStatusFilter) {
              return false;
            }

            if (reviewsLevelFilter !== "All") {
              const level = (r.residual_risk_level || r.inherent_risk_level || "").toLowerCase();
              if (level !== reviewsLevelFilter.toLowerCase()) return false;
            }

            if (reviewsTreatmentFilter !== "All") {
              const treatment = (r.treatment || "").toLowerCase();
              if (treatment !== reviewsTreatmentFilter.toLowerCase()) return false;
            }

            if (reviewsSearchQuery.trim()) {
              const q = reviewsSearchQuery.trim().toLowerCase();
              const titleMatch = (r.title || "").toLowerCase().includes(q);
              const idMatch = String(r.id).includes(q);
              const ipMatch = asset && (asset.ip_address || "").toLowerCase().includes(q);
              const hostMatch = asset && (asset.hostname || "").toLowerCase().includes(q);
              const treatMatch = (r.treatment || "").toLowerCase().includes(q);
              const statusMatch = status.toLowerCase().includes(q);
              if (!titleMatch && !idMatch && !ipMatch && !hostMatch && !treatMatch && !statusMatch) {
                return false;
              }
            }

            return true;
          });
        } else {
          displayedItems = risks.filter((r) => {
            const asset = assets.find((a) => a.id === r.asset_id);
            const status = r.review_status || "Pending Review";

            if (reviewsStatusFilter !== "All" && status !== reviewsStatusFilter) {
              return false;
            }

            if (reviewsLevelFilter !== "All") {
              const level = (r.residual_risk_level || r.inherent_risk_level || "").toLowerCase();
              if (level !== reviewsLevelFilter.toLowerCase()) return false;
            }

            if (reviewsTreatmentFilter !== "All") {
              const treatment = (r.treatment || "").toLowerCase();
              if (treatment !== reviewsTreatmentFilter.toLowerCase()) return false;
            }

            if (reviewsSearchQuery.trim()) {
              const q = reviewsSearchQuery.trim().toLowerCase();
              const titleMatch = (r.title || "").toLowerCase().includes(q);
              const idMatch = String(r.id).includes(q);
              const ipMatch = asset && (asset.ip_address || "").toLowerCase().includes(q);
              const hostMatch = asset && (asset.hostname || "").toLowerCase().includes(q);
              const treatMatch = (r.treatment || "").toLowerCase().includes(q);
              const statusMatch = status.toLowerCase().includes(q);
              const catMatch = (r.category || "").toLowerCase().includes(q);
              if (!titleMatch && !idMatch && !ipMatch && !hostMatch && !treatMatch && !statusMatch && !catMatch) {
                return false;
              }
            }

            return true;
          });
        }

        const isFiltered = reviewsSearchQuery.trim() !== "" || reviewsStatusFilter !== "All" || reviewsLevelFilter !== "All" || reviewsTreatmentFilter !== "All";
        const totalBaseCount = reviewsSubTab === "queue" ? govReviews.length : risks.length;

        const handleResetFilters = () => {
          setReviewsSearchQuery("");
          setReviewsStatusFilter("All");
          setReviewsLevelFilter("All");
          setReviewsTreatmentFilter("All");
        };

        return (
          <section className="panel reviews-panel">
            {/* Header */}
            <div className="reviews-page-header">
              <div className="reviews-header-left">
                <div className="reviews-badge-tag">GOVERNANCE & SIGN-OFF WORKFLOW</div>
                <h2>Reviews & Sign-off</h2>
                <p className="reviews-header-desc">
                  Human-in-the-loop risk sign-offs, dynamic staleness invalidation tracking, treatment approval workflows, and immutable review audit histories.
                </p>
              </div>
              <div className="reviews-header-actions">
                <button
                  className="btn-secondary btn-sm"
                  onClick={() => {
                    fetchGovReviews();
                    fetchRisks();
                  }}
                  title="Refresh governance reviews and risks"
                >
                  ↻ Refresh Reviews
                </button>
              </div>
            </div>

            {/* KPI Summary Grid (6 cards) */}
            <div className="reviews-kpi-grid">
              <div
                className={`reviews-kpi-card ${reviewsSubTab === "queue" && reviewsStatusFilter === "All" ? "kpi-card-active" : ""}`}
                onClick={() => {
                  setReviewsSubTab("queue");
                  setReviewsStatusFilter("All");
                }}
                title="Click to view Attention Queue"
              >
                <div className="reviews-kpi-header">
                  <span className="reviews-kpi-icon kpi-icon-amber">🛡️</span>
                  <span className="reviews-kpi-badge badge-attention">Attention Queue</span>
                </div>
                <div className="reviews-kpi-value highlight-amber">{attentionCount}</div>
                <div className="reviews-kpi-label">Pending, Stale, or Changes</div>
              </div>

              <div
                className={`reviews-kpi-card ${reviewsStatusFilter === "Pending Review" ? "kpi-card-active" : ""}`}
                onClick={() => {
                  setReviewsSubTab("queue");
                  setReviewsStatusFilter("Pending Review");
                }}
                title="Click to filter by Pending Review"
              >
                <div className="reviews-kpi-header">
                  <span className="reviews-kpi-icon kpi-icon-amber">⏳</span>
                  <span className="reviews-kpi-badge badge-pending">Pending Review</span>
                </div>
                <div className="reviews-kpi-value highlight-amber">{pendingCount}</div>
                <div className="reviews-kpi-label">Awaiting initial sign-off</div>
              </div>

              <div
                className={`reviews-kpi-card ${reviewsStatusFilter === "Stale" ? "kpi-card-active" : ""}`}
                onClick={() => {
                  setReviewsSubTab("queue");
                  setReviewsStatusFilter("Stale");
                }}
                title="Click to filter by Stale Baselines"
              >
                <div className="reviews-kpi-header">
                  <span className="reviews-kpi-icon kpi-icon-orange">⚠</span>
                  <span className="reviews-kpi-badge badge-stale-kpi">Stale Baselines</span>
                </div>
                <div className="reviews-kpi-value highlight-orange">{staleCount}</div>
                <div className="reviews-kpi-label">Invalidated by drift/changes</div>
              </div>

              <div
                className={`reviews-kpi-card ${reviewsStatusFilter === "Changes Requested" ? "kpi-card-active" : ""}`}
                onClick={() => {
                  setReviewsSubTab("queue");
                  setReviewsStatusFilter("Changes Requested");
                }}
                title="Click to filter by Changes Requested"
              >
                <div className="reviews-kpi-header">
                  <span className="reviews-kpi-icon kpi-icon-purple">💬</span>
                  <span className="reviews-kpi-badge badge-changes-kpi">Changes Requested</span>
                </div>
                <div className="reviews-kpi-value highlight-purple">{changesCount}</div>
                <div className="reviews-kpi-label">Treatment revision needed</div>
              </div>

              <div
                className={`reviews-kpi-card ${reviewsSubTab === "all" && reviewsStatusFilter === "Approved" ? "kpi-card-active" : ""}`}
                onClick={() => {
                  setReviewsSubTab("all");
                  setReviewsStatusFilter("Approved");
                }}
                title="Click to view Approved Sign-offs"
              >
                <div className="reviews-kpi-header">
                  <span className="reviews-kpi-icon kpi-icon-green">✅</span>
                  <span className="reviews-kpi-badge badge-approved-kpi">Approved</span>
                </div>
                <div className="reviews-kpi-value highlight-green">{approvedCount}</div>
                <div className="reviews-kpi-label">Active certified baselines</div>
              </div>

              <div
                className={`reviews-kpi-card ${reviewsSubTab === "all" && reviewsStatusFilter === "Rejected" ? "kpi-card-active" : ""}`}
                onClick={() => {
                  setReviewsSubTab("all");
                  setReviewsStatusFilter("Rejected");
                }}
                title="Click to view Rejected Reviews"
              >
                <div className="reviews-kpi-header">
                  <span className="reviews-kpi-icon kpi-icon-red">⛔</span>
                  <span className="reviews-kpi-badge badge-rejected-kpi">Rejected</span>
                </div>
                <div className="reviews-kpi-value highlight-critical">{rejectedCount}</div>
                <div className="reviews-kpi-label">Remediation unapproved</div>
              </div>
            </div>

            {/* Sub-View Navigation Tabs */}
            <div className="reviews-sub-nav">
              <button
                className={`reviews-tab-btn ${reviewsSubTab === "queue" ? "active" : ""}`}
                onClick={() => {
                  setReviewsSubTab("queue");
                  setReviewsStatusFilter("All");
                }}
              >
                <span className="reviews-tab-label">Attention Queue</span>
                <span className="reviews-tab-pill">{govReviews.length}</span>
              </button>
              <button
                className={`reviews-tab-btn ${reviewsSubTab === "all" ? "active" : ""}`}
                onClick={() => {
                  setReviewsSubTab("all");
                  setReviewsStatusFilter("All");
                }}
              >
                <span className="reviews-tab-label">All Enterprise Reviews</span>
                <span className="reviews-tab-pill">{risks.length}</span>
              </button>
            </div>

            {/* Filter and Search Controls Bar */}
            <div className="reviews-controls-bar">
              <div className="reviews-search-wrap">
                <span className="reviews-search-icon">🔍</span>
                <input
                  type="text"
                  className="reviews-search-input"
                  placeholder="Search by risk title, ID, IP address, treatment..."
                  value={reviewsSearchQuery}
                  onChange={(e) => setReviewsSearchQuery(e.target.value)}
                />
                {reviewsSearchQuery && (
                  <button
                    className="reviews-search-clear"
                    onClick={() => setReviewsSearchQuery("")}
                    title="Clear search query"
                  >
                    ×
                  </button>
                )}
              </div>

              <div className="filter-group">
                <label>Status:</label>
                <select
                  className="select-filter"
                  value={reviewsStatusFilter}
                  onChange={(e) => setReviewsStatusFilter(e.target.value)}
                >
                  {reviewsSubTab === "queue" ? (
                    <>
                      <option value="All">All Attention Items ({govReviews.length})</option>
                      <option value="Pending Review">Pending Review ({pendingGovCount})</option>
                      <option value="Stale">Stale Reviews ({staleGovCount})</option>
                      <option value="Changes Requested">Changes Requested ({changesGovCount})</option>
                    </>
                  ) : (
                    <>
                      <option value="All">All Review Statuses ({risks.length})</option>
                      <option value="Pending Review">Pending Review ({pendingCount})</option>
                      <option value="Approved">Approved ({approvedCount})</option>
                      <option value="Stale">Stale ({staleCount})</option>
                      <option value="Changes Requested">Changes Requested ({changesCount})</option>
                      <option value="Rejected">Rejected ({rejectedCount})</option>
                    </>
                  )}
                </select>
              </div>

              <div className="filter-group">
                <label>Risk Level:</label>
                <select
                  className="select-filter"
                  value={reviewsLevelFilter}
                  onChange={(e) => setReviewsLevelFilter(e.target.value)}
                >
                  <option value="All">All Risk Levels</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div className="filter-group">
                <label>Treatment:</label>
                <select
                  className="select-filter"
                  value={reviewsTreatmentFilter}
                  onChange={(e) => setReviewsTreatmentFilter(e.target.value)}
                >
                  <option value="All">All Treatments</option>
                  <option value="Mitigate">Mitigate</option>
                  <option value="Accept">Accept</option>
                  <option value="Transfer">Transfer</option>
                  <option value="Avoid">Avoid</option>
                </select>
              </div>

              {isFiltered && (
                <button
                  className="btn-secondary btn-sm"
                  onClick={handleResetFilters}
                  title="Clear all filters and search query"
                >
                  ✕ Reset Filters
                </button>
              )}

              <div className="reviews-count-summary">
                Showing {displayedItems.length} of {totalBaseCount} {reviewsSubTab === "queue" ? "attention items" : "risks"}
              </div>
            </div>

            {/* Table or States */}
            {govReviewsLoading && govReviews.length === 0 ? (
              <div className="monitoring-loading-box">
                <span className="ai-spinner" /> Loading governance review queue...
              </div>
            ) : govReviewsError ? (
              <div className="monitoring-error-box">
                <div>⚠ {govReviewsError}</div>
                <button className="btn-secondary btn-sm" onClick={fetchGovReviews}>Retry</button>
              </div>
            ) : displayedItems.length === 0 ? (
              <div className="gov-empty-box">
                <div className="empty-icon">{isFiltered ? "🔍" : (reviewsSubTab === "queue" ? "🛡️" : "📋")}</div>
                <div>
                  <strong>
                    {isFiltered
                      ? "No matching review items found"
                      : (reviewsSubTab === "queue" ? "Attention Queue Clear" : "No Enterprise Risks Found")}
                  </strong>
                </div>
                <div className="sub-text">
                  {isFiltered
                    ? "No items matched your current filter criteria or search keyword."
                    : (reviewsSubTab === "queue"
                        ? "All identified risks have an active human governance sign-off or no items require immediate attention."
                        : "No risks have been registered in the enterprise risk inventory.")}
                </div>
                {isFiltered && (
                  <button className="btn-secondary btn-sm" onClick={handleResetFilters}>
                    Reset Filters
                  </button>
                )}
              </div>
            ) : (
              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Risk Title & ID</th>
                      <th>Asset / Target</th>
                      <th>Inherent Risk</th>
                      <th>Residual Risk</th>
                      <th>Review Status</th>
                      <th>Treatment</th>
                      <th>Due Date</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayedItems.map((item) => {
                      const r = reviewsSubTab === "queue" ? item.risk : item;
                      const reviewStatus = reviewsSubTab === "queue" ? item.review_status : (r.review_status || "Pending Review");
                      const currentReview = reviewsSubTab === "queue" ? item.current_review : govReviewMap.get(r.id)?.current_review;
                      const asset = assets.find((a) => a.id === r.asset_id);

                      return (
                        <Fragment key={r.id}>
                          <tr>
                            <td style={{ minWidth: "220px" }}>
                              <div className="font-semibold text-white">{r.title}</div>
                              <div className="sub-text" style={{ display: "flex", gap: "6px", alignItems: "center", marginTop: "2px" }}>
                                <span>Risk #{r.id}</span>
                                {r.category && <span className="reviews-cat-pill">{r.category}</span>}
                              </div>
                            </td>
                            <td>
                              <span className="ip-pill">
                                {asset ? asset.ip_address : (r.asset_id ? `Asset #${r.asset_id}` : "—")}
                              </span>
                              {asset?.hostname && (
                                <div className="sub-text">{asset.hostname}</div>
                              )}
                            </td>
                            <td>
                              <span className={`badge ${getRiskClass(r.inherent_risk_level)}`}>
                                {r.inherent_risk_level || "Medium"} ({r.inherent_risk_score || r.risk_score})
                              </span>
                            </td>
                            <td>
                              <span className={`badge ${getRiskClass(r.residual_risk_level)}`}>
                                {r.residual_risk_level || "Medium"} ({r.residual_risk_score != null ? r.residual_risk_score : (r.risk_score || "—")})
                              </span>
                            </td>
                            <td>
                              {getReviewStatusBadge(reviewStatus)}
                            </td>
                            <td>
                              <span className="badge badge-treatment">
                                {r.treatment || "Mitigate"}
                              </span>
                            </td>
                            <td>
                              <span className="text-xs text-slate">
                                {r.due_date ? new Date(r.due_date).toLocaleDateString() : "—"}
                              </span>
                            </td>
                            <td>
                              <div className="action-buttons-group">
                                <button
                                  className="btn-action btn-action-primary"
                                  onClick={() => openSubmitReviewModal(r)}
                                  title="Submit Human Sign-Off Decision"
                                >
                                  Submit Sign-Off
                                </button>
                                <button
                                  className="btn-action"
                                  onClick={() => openReviewHistoryModal(r)}
                                  title="View Review History"
                                >
                                  View History
                                </button>
                              </div>
                            </td>
                          </tr>

                          {reviewStatus === "Stale" && (
                            <tr className="stale-callout-row">
                              <td colSpan="8" style={{ padding: "0 16px 12px 16px", background: "transparent" }}>
                                <div className="gov-stale-callout">
                                  <span className="stale-callout-icon">⚠</span>
                                  <div>
                                    <strong>Review Invalidation (Stale Baseline):</strong>
                                    {currentReview?.stale_reasons && currentReview.stale_reasons.length > 0 ? (
                                      <ul className="stale-reasons-list">
                                        {currentReview.stale_reasons.map((reason, idx) => (
                                          <li key={idx}>{reason}</li>
                                        ))}
                                      </ul>
                                    ) : (
                                      <div className="sub-text" style={{ color: "#fef08a", marginTop: "4px" }}>
                                        Technical baseline changes (drift, port status, or CVSS update) invalidated the previous sign-off.
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}

                          {reviewStatus === "Changes Requested" && (
                            <tr className="changes-callout-row">
                              <td colSpan="8" style={{ padding: "0 16px 12px 16px", background: "transparent" }}>
                                <div className="gov-changes-requested-callout">
                                  <span className="changes-callout-icon">💬</span>
                                  <div>
                                    <strong>Changes Requested:</strong>{" "}
                                    {currentReview?.comments || "Additional mitigating controls or treatment revisions requested by reviewer."}
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        );
      })()}

      {/* ------------------------------------------------ */}
      {/* PHASE 9: AUDIT TRAIL WORKSPACE                  */}
      {/* ------------------------------------------------ */}
      {activePage === "audit" && (() => {
        if (!isReviewer) {
          return (
            <div className="gov-panel" style={{ textAlign: "center", padding: "48px 24px" }}>
              <div style={{ fontSize: "40px", marginBottom: "16px" }}>🔒</div>
              <h3 style={{ color: "#ffffff", marginBottom: "8px" }}>Audit Trail Access Restricted</h3>
              <p style={{ color: "#94a3b8", maxWidth: "480px", margin: "0 auto" }}>
                Access to the immutable audit trail requires GRC Reviewer or Administrator privileges. Your current role is <strong>{user?.role}</strong>.
              </p>
            </div>
          );
        }
        // Client-side search on currently loaded page records (Clarification 2)
        const filteredLogs = auditLogs.filter((log) => {
          if (!auditSearchQuery.trim()) return true;
          const q = auditSearchQuery.trim().toLowerCase();
          const descMatch = (log.description || "").toLowerCase().includes(q);
          const actorMatch = (log.actor || "").toLowerCase().includes(q);
          const entityNameMatch = (log.entity_name || "").toLowerCase().includes(q);
          const entityIdMatch = log.entity_id != null && String(log.entity_id).includes(q);
          const ipMatch = (log.ip_address || "").toLowerCase().includes(q);
          const hashMatch = (log.integrity_hash || "").toLowerCase().includes(q);
          const actionMatch = (log.action || "").toLowerCase().includes(q);
          const sourceMatch = (log.source || "").toLowerCase().includes(q);
          return descMatch || actorMatch || entityNameMatch || entityIdMatch || ipMatch || hashMatch || actionMatch || sourceMatch;
        });

        const isFiltered = auditSearchQuery.trim() !== "" || auditSourceFilter !== "All" || auditActionFilter !== "All" || auditEntityFilter !== "All";

        const handleSourceChange = (e) => {
          const newSource = e.target.value;
          setAuditSourceFilter(newSource);
          setAuditOffset(0);
          fetchAuditLogs(0, newSource, auditActionFilter, auditEntityFilter, auditLimit);
        };

        const handleActionChange = (e) => {
          const newAction = e.target.value;
          setAuditActionFilter(newAction);
          setAuditOffset(0);
          fetchAuditLogs(0, auditSourceFilter, newAction, auditEntityFilter, auditLimit);
        };

        const handleEntityChange = (e) => {
          const newEntity = e.target.value;
          setAuditEntityFilter(newEntity);
          setAuditOffset(0);
          fetchAuditLogs(0, auditSourceFilter, auditActionFilter, newEntity, auditLimit);
        };

        const handleLimitChange = (e) => {
          const newLimit = Number(e.target.value);
          setAuditLimit(newLimit);
          setAuditOffset(0);
          fetchAuditLogs(0, auditSourceFilter, auditActionFilter, auditEntityFilter, newLimit);
        };

        const handleResetAllFilters = () => {
          setAuditSourceFilter("All");
          setAuditActionFilter("All");
          setAuditEntityFilter("All");
          setAuditSearchQuery("");
          setAuditOffset(0);
          fetchAuditLogs(0, "All", "All", "All", auditLimit);
        };

        // Calculate loaded page counts (Clarification 1: Clearly distinguish DB-wide total from page-level counts)
        const pageUserCount = auditLogs.filter((l) => l.source === "USER").length;
        const pageAutoCount = auditLogs.filter((l) => ["SCANNER", "SCHEDULER", "AI", "SYSTEM", "API"].includes(l.source)).length;
        const pageDiffCount = auditLogs.filter((l) => Boolean(l.old_values || l.new_values)).length;

        const totalPages = Math.max(1, Math.ceil(auditTotal / auditLimit));
        const currentPage = Math.floor(auditOffset / auditLimit) + 1;

        return (
          <section className="panel audit-panel">
            {/* Header */}
            <div className="audit-page-header">
              <div className="audit-header-left">
                <div className="audit-badge-tag">TAMPER-EVIDENT GOVERNANCE LOG</div>
                <h2>Audit Trail</h2>
                <p className="audit-header-desc">
                  Cryptographically verifiable, append-only chronological log of all governance reviews, security findings, automated scan executions, and risk treatment decisions.
                </p>
              </div>
              <div className="audit-header-actions">
                <div className="audit-append-pill" title="AuditLog is append-only through application API. No UPDATE or DELETE endpoints exist.">
                  <span className="status-indicator-dot dot-green" /> Append-Only Mode
                </div>
                <button
                  className="btn-secondary btn-sm"
                  onClick={() => fetchAuditLogs(auditOffset, auditSourceFilter, auditActionFilter, auditEntityFilter, auditLimit)}
                  title="Refresh audit log feed"
                >
                  ↻ Refresh Audit
                </button>
              </div>
            </div>

            {/* KPI Cards Grid (4 Cards - Clarification 1: Clearly distinguishing DB-wide from page-level) */}
            <div className="audit-kpi-grid">
              <div className="audit-kpi-card">
                <div className="audit-kpi-header">
                  <span className="audit-kpi-icon kpi-icon-blue">📜</span>
                  <span className="audit-kpi-badge badge-server-total">Server Total</span>
                </div>
                <div className="audit-kpi-value highlight-blue">{auditTotal}</div>
                <div className="audit-kpi-label">Events matching DB filters</div>
              </div>

              <div className="audit-kpi-card">
                <div className="audit-kpi-header">
                  <span className="audit-kpi-icon kpi-icon-green">👤</span>
                  <span className="audit-kpi-badge badge-page-user">Page Count</span>
                </div>
                <div className="audit-kpi-value highlight-green">{pageUserCount}</div>
                <div className="audit-kpi-label">Human operator events (Loaded Page)</div>
              </div>

              <div className="audit-kpi-card">
                <div className="audit-kpi-header">
                  <span className="audit-kpi-icon kpi-icon-amber">⚙️</span>
                  <span className="audit-kpi-badge badge-page-auto">Page Count</span>
                </div>
                <div className="audit-kpi-value highlight-amber">{pageAutoCount}</div>
                <div className="audit-kpi-label">Automated / System events (Loaded Page)</div>
              </div>

              <div className="audit-kpi-card">
                <div className="audit-kpi-header">
                  <span className="audit-kpi-icon kpi-icon-purple">🔄</span>
                  <span className="audit-kpi-badge badge-page-diff">Page Count</span>
                </div>
                <div className="audit-kpi-value highlight-purple">{pageDiffCount}</div>
                <div className="audit-kpi-label">State mutations with delta (Loaded Page)</div>
              </div>
            </div>

            {/* Filter and Search Controls Bar (Clarification 2) */}
            <div className="audit-controls-bar">
              <div className="audit-controls-top">
                <div className="audit-search-wrap">
                  <span className="audit-search-icon">🔍</span>
                  <input
                    type="text"
                    className="audit-search-input"
                    placeholder="Filter loaded page by description, actor, IP, hash..."
                    value={auditSearchQuery}
                    onChange={(e) => setAuditSearchQuery(e.target.value)}
                  />
                  {auditSearchQuery && (
                    <button
                      className="audit-search-clear"
                      onClick={() => setAuditSearchQuery("")}
                      title="Clear page search filter"
                    >
                      ×
                    </button>
                  )}
                </div>

                <div className="filter-group">
                  <label>Source:</label>
                  <select
                    className="select-filter"
                    value={auditSourceFilter}
                    onChange={handleSourceChange}
                  >
                    <option value="All">All Sources</option>
                    <option value="USER">USER</option>
                    <option value="SYSTEM">SYSTEM</option>
                    <option value="SCANNER">SCANNER</option>
                    <option value="SCHEDULER">SCHEDULER</option>
                    <option value="AI">AI</option>
                    <option value="API">API</option>
                  </select>
                </div>

                <div className="filter-group">
                  <label>Action:</label>
                  <select
                    className="select-filter"
                    value={auditActionFilter}
                    onChange={handleActionChange}
                  >
                    <option value="All">All Actions</option>
                    <option value="RISK_REVIEW_SUBMITTED">RISK_REVIEW_SUBMITTED</option>
                    <option value="RISK_REVIEW_STALE">RISK_REVIEW_STALE</option>
                    <option value="EXPORT">EXPORT</option>
                    <option value="EVIDENCE_CREATED">EVIDENCE_CREATED</option>
                    <option value="EVIDENCE_DELETED">EVIDENCE_DELETED</option>
                    <option value="SCAN_COMPLETED">SCAN_COMPLETED</option>
                    <option value="SCAN_TRIGGERED">SCAN_TRIGGERED</option>
                    <option value="CREATE">CREATE</option>
                    <option value="UPDATE">UPDATE</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                </div>

                <div className="filter-group">
                  <label>Entity Type:</label>
                  <select
                    className="select-filter"
                    value={auditEntityFilter}
                    onChange={handleEntityChange}
                  >
                    <option value="All">All Entity Types</option>
                    <option value="Risk">Risk</option>
                    <option value="Asset">Asset</option>
                    <option value="Control">Control</option>
                    <option value="ComplianceRequirement">ComplianceRequirement</option>
                    <option value="ScanJob">ScanJob</option>
                    <option value="EvidenceRecord">EvidenceRecord</option>
                  </select>
                </div>

                <div className="filter-group">
                  <label>Page Size:</label>
                  <select
                    className="select-filter"
                    value={auditLimit}
                    onChange={handleLimitChange}
                  >
                    <option value="25">25 per page</option>
                    <option value="50">50 per page</option>
                    <option value="100">100 per page</option>
                  </select>
                </div>

                {isFiltered && (
                  <button
                    className="btn-secondary btn-sm"
                    onClick={handleResetAllFilters}
                    title="Reset all filters and page search"
                  >
                    ✕ Reset Filters
                  </button>
                )}
              </div>

              <div className="audit-controls-bottom">
                <div className="audit-search-hint">
                  ℹ️ Text search filters visible records on currently loaded page ({filteredLogs.length} of {auditLogs.length} shown). Dropdowns execute server-wide database queries.
                </div>
                <div className="audit-count-summary">
                  Showing {auditLogs.length} of {auditTotal} database records (Page {currentPage} of {totalPages})
                </div>
              </div>
            </div>

            {/* Table or Loading/Error States */}
            {auditLoading && auditLogs.length === 0 ? (
              <div className="monitoring-loading-box">
                <span className="ai-spinner" /> Loading audit trail...
              </div>
            ) : auditError ? (
              <div className="monitoring-error-box">
                <div>⚠ {auditError}</div>
                <button
                  className="btn-secondary btn-sm"
                  onClick={() => fetchAuditLogs(auditOffset, auditSourceFilter, auditActionFilter, auditEntityFilter, auditLimit)}
                >
                  Retry
                </button>
              </div>
            ) : filteredLogs.length === 0 ? (
              <div className="gov-empty-box">
                <div className="empty-icon">{isFiltered ? "🔍" : "📜"}</div>
                <div>
                  <strong>
                    {isFiltered ? "No matching audit log entries" : "No audit log entries found"}
                  </strong>
                </div>
                <div className="sub-text">
                  {isFiltered
                    ? "No audit records matched your current search keyword or filter settings."
                    : "Events will be recorded here in an append-only, tamper-evident log as security and governance actions occur."}
                </div>
                {isFiltered && (
                  <button className="btn-secondary btn-sm" onClick={handleResetAllFilters}>
                    Reset Filters
                  </button>
                )}
              </div>
            ) : (
              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp & ID</th>
                      <th>Source & Action</th>
                      <th>Actor & IP</th>
                      <th>Target Entity</th>
                      <th>Description & Integrity</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLogs.map((log) => (
                      <tr key={log.id}>
                        <td style={{ whiteSpace: "nowrap" }}>
                          <div className="text-xs font-semibold">{formatDateTime(log.timestamp)}</div>
                          <div className="sub-text">Event #{log.id}</div>
                        </td>
                        <td>
                          <div style={{ display: "flex", flexDirection: "column", gap: "4px", alignItems: "flex-start" }}>
                            {getAuditSourceBadge(log.source)}
                            {getAuditActionBadge(log.action)}
                          </div>
                        </td>
                        <td>
                          <div className="font-semibold text-white">{log.actor}</div>
                          <div className="sub-text" style={{ marginTop: "2px" }}>
                            <span className="ip-pill">{log.ip_address || "127.0.0.1"}</span>
                          </div>
                        </td>
                        <td>
                          <strong>{log.entity_type || "—"}</strong>
                          <div className="sub-text">
                            {log.entity_name ? log.entity_name : (log.entity_id != null ? `ID #${log.entity_id}` : "")}
                          </div>
                        </td>
                        <td style={{ minWidth: "320px" }}>
                          <div>{log.description}</div>
                          {(log.old_values || log.new_values) && (
                            <details className="audit-diff-details">
                              <summary className="audit-diff-summary">
                                View State Changes / Diff
                              </summary>
                              <div className="audit-diff-content">
                                {log.old_values && (
                                  <div className="diff-col">
                                    <div className="diff-col-header">Previous State</div>
                                    <pre className="diff-json">
                                      {typeof log.old_values === "object"
                                        ? JSON.stringify(log.old_values, null, 2)
                                        : String(log.old_values)}
                                    </pre>
                                  </div>
                                )}
                                {log.new_values && (
                                  <div className="diff-col">
                                    <div className="diff-col-header">Updated State</div>
                                    <pre className="diff-json">
                                      {typeof log.new_values === "object"
                                        ? JSON.stringify(log.new_values, null, 2)
                                        : String(log.new_values)}
                                    </pre>
                                  </div>
                                )}
                              </div>
                            </details>
                          )}
                          {log.integrity_hash && (
                            <div className="audit-hash" title={`Deterministic SHA-256 Digest: ${log.integrity_hash}`}>
                              <span className="hash-label">SHA-256:</span>
                              <code>{log.integrity_hash.substring(0, 16)}...</code>
                            </div>
                          )}
                        </td>
                        <td style={{ whiteSpace: "nowrap" }}>
                          <button
                            className="btn-action btn-action-primary"
                            onClick={() => openAuditDetailModal(log)}
                            title="Inspect event metadata, full SHA-256 hash, and state delta"
                          >
                            Inspect Event
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {/* Audit Pagination */}
                {auditTotal > auditLimit && (
                  <div className="drift-pagination-bar">
                    <button
                      className="btn-secondary btn-sm"
                      disabled={auditOffset === 0}
                      onClick={() => {
                        const newOffset = Math.max(0, auditOffset - auditLimit);
                        setAuditOffset(newOffset);
                        fetchAuditLogs(newOffset, auditSourceFilter, auditActionFilter, auditEntityFilter, auditLimit);
                      }}
                    >
                      ← Previous Page
                    </button>
                    <span className="pagination-info">
                      Page {currentPage} of {totalPages}
                    </span>
                    <button
                      className="btn-secondary btn-sm"
                      disabled={auditOffset + auditLimit >= auditTotal}
                      onClick={() => {
                        const newOffset = auditOffset + auditLimit;
                        setAuditOffset(newOffset);
                        fetchAuditLogs(newOffset, auditSourceFilter, auditActionFilter, auditEntityFilter, auditLimit);
                      }}
                    >
                      Next Page →
                    </button>
                  </div>
                )}
              </div>
            )}
          </section>
        );
      })()}

      {/* ------------------------------------------------ */}
      {/* REPORTS PANEL                                   */}
      {/* ------------------------------------------------ */}
      {activePage === "reports" && (() => {
        const activeOperatorName = user?.display_name || user?.username || reviewForm.reviewer_name;
        const activeOperatorRole = user?.role || reviewForm.reviewer_role;

        const categories = [
          { key: "ALL", label: "All Suites" },
          { key: "EXECUTIVE", label: "Executive Posture" },
          { key: "TECHNICAL", label: "Attack Surface" },
          { key: "COMPLIANCE", label: "Regulatory Compliance" },
          { key: "RISK", label: "Risk Management" },
          { key: "AUDIT", label: "Audit & Evidence" },
        ];

        const filteredReports = REPORT_TYPES.filter((rep) => {
          const matchesCategory =
            reportCategoryFilter === "ALL" || rep.categoryKey === reportCategoryFilter;
          const q = reportSearchQuery.trim().toLowerCase();
          const matchesSearch =
            !q ||
            rep.title.toLowerCase().includes(q) ||
            rep.category.toLowerCase().includes(q) ||
            rep.desc.toLowerCase().includes(q) ||
            rep.targetAudience.toLowerCase().includes(q) ||
            rep.dataPoints.some((dp) => dp.toLowerCase().includes(q));
          return matchesCategory && matchesSearch;
        });

        const activeDownloadingTitle = downloadingReport
          ? REPORT_TYPES.find((r) => r.id === downloadingReport.type)?.title || downloadingReport.type
          : "";

        return (
          <section className="reports-workspace">
            {/* Header Section */}
            <div className="reports-header-card">
              <div className="reports-header-info">
                <div className="gov-tag">GOVERNANCE, RISK & COMPLIANCE REPORTING</div>
                <h2 className="reports-header-title">Reports & Regulatory Exports</h2>
                <p className="reports-header-desc">
                  Generate and download authoritative GRC report artifacts across machine-readable JSON, tabular CSV,
                  and formatted executive HTML formats. Export operations are automatically attributed to the operator
                  and recorded in the platform Audit Trail.
                </p>
              </div>
              <div className="reports-operator-badge-box">
                <div className="reports-operator-badge-label">EXPORT OPERATOR IDENTITY</div>
                <div className="reports-operator-badge-name">
                  <span className="operator-dot" />
                  <strong>{activeOperatorName}</strong>
                </div>
                <div className="reports-operator-badge-role">{activeOperatorRole}</div>
                <div className="reports-operator-badge-meta">Authenticated JWT Session • {activeOperatorRole}</div>
              </div>
            </div>

            {/* Capabilities & Information Ribbon */}
            <div className="reports-capabilities-ribbon">
              <div className="reports-capability-card">
                <div className="capability-icon">📊</div>
                <div className="capability-content">
                  <div className="capability-title">Report Suites</div>
                  <div className="capability-val">5 Formal Suites</div>
                  <div className="capability-desc">Executive, vulnerabilities, compliance, risk, and audit trail</div>
                </div>
              </div>
              <div className="reports-capability-card">
                <div className="capability-icon">📁</div>
                <div className="capability-content">
                  <div className="capability-title">Supported Formats</div>
                  <div className="capability-val">JSON • CSV • HTML</div>
                  <div className="capability-desc">Structured API data, spreadsheets, and styled executive docs</div>
                </div>
              </div>
              <div className="reports-capability-card">
                <div className="capability-icon">🛡</div>
                <div className="capability-content">
                  <div className="capability-title">Audit Trail Traceability</div>
                  <div className="capability-val">Append-Only Logging</div>
                  <div className="capability-desc">Exports are recorded in the Audit Trail by the backend</div>
                </div>
              </div>
              <div className="reports-capability-card">
                <div className="capability-icon">⚖</div>
                <div className="capability-content">
                  <div className="capability-title">Governance Boundary</div>
                  <div className="capability-val">Authoritative vs. Advisory</div>
                  <div className="capability-desc">Deterministic calculations partitioned from AI recommendations</div>
                </div>
              </div>
            </div>

            {/* In-Session Download Feedback & Errors */}
            {reportDownloadError && (
              <div className="reports-feedback-banner reports-error-banner">
                <span className="reports-feedback-icon">⚠</span>
                <div className="reports-feedback-body">
                  <strong>Export Error:</strong> {reportDownloadError}
                </div>
                <button
                  type="button"
                  className="btn-link reports-dismiss-btn"
                  onClick={() => setReportDownloadError(null)}
                >
                  Dismiss
                </button>
              </div>
            )}

            {lastExportedReport && !reportDownloadError && (
              <div className="reports-feedback-banner reports-success-banner">
                <span className="reports-feedback-icon">✓</span>
                <div className="reports-feedback-body">
                  <div className="reports-success-headline">
                    Download Completed: <code>{lastExportedReport.filename}</code>
                  </div>
                  <div className="reports-feedback-sub">
                    Export format: <strong>{lastExportedReport.format.toUpperCase()}</strong> • Generated at{" "}
                    {formatDateTime(lastExportedReport.timestamp)} • Recorded by backend in the Audit Trail with operator attribution.
                  </div>
                </div>
                <button
                  type="button"
                  className="btn-link reports-dismiss-btn"
                  onClick={() => setLastExportedReport(null)}
                >
                  Dismiss
                </button>
              </div>
            )}

            {downloadingReport && (
              <div className="reports-feedback-banner reports-progress-banner">
                <span className="reports-spinner" />
                <div className="reports-feedback-body">
                  <div className="reports-progress-headline">
                    Compiling <strong>{activeDownloadingTitle}</strong> in{" "}
                    <strong>{downloadingReport.format.toUpperCase()}</strong> format...
                  </div>
                  <div className="reports-feedback-sub">
                    Please wait while the backend prepares records and triggers your browser download.
                  </div>
                </div>
              </div>
            )}

            {/* Workspace Controls: Category Filter Pills & Search */}
            <div className="reports-controls-bar">
              <div className="reports-category-pills">
                {categories.map((cat) => {
                  const count =
                    cat.key === "ALL"
                      ? REPORT_TYPES.length
                      : REPORT_TYPES.filter((r) => r.categoryKey === cat.key).length;
                  return (
                    <button
                      key={cat.key}
                      type="button"
                      className={`reports-cat-pill ${reportCategoryFilter === cat.key ? "active" : ""}`}
                      onClick={() => setReportCategoryFilter(cat.key)}
                    >
                      {cat.label} <span className="cat-count">({count})</span>
                    </button>
                  );
                })}
              </div>

              <div className="reports-search-box">
                <span className="reports-search-icon">🔍</span>
                <input
                  type="text"
                  className="reports-search-input"
                  placeholder="Search suites by name, description, or data fields..."
                  value={reportSearchQuery}
                  onChange={(e) => setReportSearchQuery(e.target.value)}
                />
                {reportSearchQuery && (
                  <button
                    type="button"
                    className="reports-clear-search-btn"
                    onClick={() => setReportSearchQuery("")}
                    title="Clear search query"
                  >
                    ✕
                  </button>
                )}
              </div>
            </div>

            <div className="reports-results-meta">
              Showing <strong>{filteredReports.length}</strong> of {REPORT_TYPES.length} governance report suites
              {reportSearchQuery && (
                <span>
                  {" "}
                  matching &ldquo;<strong>{reportSearchQuery}</strong>&rdquo;
                </span>
              )}
              {reportCategoryFilter !== "ALL" && (
                <span>
                  {" "}
                  in <strong>{categories.find((c) => c.key === reportCategoryFilter)?.label}</strong>
                </span>
              )}
            </div>

            {/* Report Suites Grid */}
            <div className="reports-cards-grid">
              {filteredReports.map((rep) => {
                const isDownloadingThisReport = downloadingReport?.type === rep.id;
                return (
                  <div key={rep.id} className="reports-suite-card">
                    <div className="reports-suite-card-top">
                      <div className="reports-suite-top-row">
                        <span className={`reports-suite-badge badge-${rep.categoryKey.toLowerCase()}`}>
                          {rep.category}
                        </span>
                        <span className="reports-audience-tag">
                          {rep.targetAudience}
                        </span>
                      </div>
                      <h3 className="reports-suite-title">{rep.title}</h3>
                      <p className="reports-suite-desc">{rep.desc}</p>
                    </div>

                    <div className="reports-suite-dimensions">
                      <div className="reports-dim-label">Aggregated Data Dimensions:</div>
                      <div className="reports-dim-chips">
                        {rep.dataPoints.map((dp, idx) => (
                          <span key={idx} className="reports-dim-chip">
                            {dp}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="reports-suite-footer">
                      <div className="reports-export-row-header">
                        <span className="reports-export-label">Export Format:</span>
                        <span className="reports-export-hint">
                          {isDownloadingThisReport ? "Download in progress..." : "Select format to download"}
                        </span>
                      </div>
                      <div className="reports-format-btn-group">
                        {rep.formats.map((fmt) => {
                          const isCurrentFmtDownloading =
                            isDownloadingThisReport && downloadingReport.format === fmt;
                          return (
                            <button
                              key={fmt}
                              type="button"
                              className={`reports-btn-fmt fmt-${fmt} ${
                                isCurrentFmtDownloading ? "btn-generating" : ""
                              }`}
                              disabled={Boolean(downloadingReport)}
                              onClick={() => handleExportReport(rep.id, fmt)}
                              title={`Export ${rep.title} in ${fmt.toUpperCase()} format`}
                            >
                              {isCurrentFmtDownloading ? (
                                <>
                                  <span className="btn-spinner" />
                                  <span>Exporting...</span>
                                </>
                              ) : (
                                <>
                                  <span className="fmt-icon-badge">{fmt.toUpperCase()}</span>
                                  <span className="fmt-name">{fmt.toUpperCase()}</span>
                                </>
                              )}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                );
              })}

              {filteredReports.length === 0 && (
                <div className="reports-empty-state">
                  <div className="reports-empty-icon">📂</div>
                  <h3>No Report Suites Match Your Filter</h3>
                  <p>No governance report suites match the current search query or category filter.</p>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => {
                      setReportSearchQuery("");
                      setReportCategoryFilter("ALL");
                    }}
                  >
                    Reset Filters
                  </button>
                </div>
              )}
            </div>

            {/* Architecture & Audit Information Panel */}
            <div className="reports-info-panel">
              <div className="reports-info-card">
                <div className="reports-info-icon">🛡</div>
                <h4>Tamper-Evident Audit Logging</h4>
                <p>
                  Every report export action is recorded by the backend as an <code>EXPORT</code> event in the
                  append-only Audit Trail, capturing operator identity, timestamp, and requested format.
                </p>
              </div>
              <div className="reports-info-card">
                <div className="reports-info-icon">⚖</div>
                <h4>Authoritative vs. Advisory Separation</h4>
                <p>
                  Generated JSON and HTML reports cleanly partition deterministic risk scores and formal compliance
                  controls from automated AI advisory recommendations.
                </p>
              </div>
              <div className="reports-info-card">
                <div className="reports-info-icon">📋</div>
                <h4>Standard Compliance Disclaimer</h4>
                <p>
                  All exports include formal disclaimers identifying the assessment as point-in-time security intelligence
                  to support regulatory, internal audit, and executive oversight.
                </p>
              </div>
            </div>
          </section>
        );
      })()}

        </div>{/* end page-content */}
      </div>{/* end main-content */}

      {/* ================================ */}
      {/* MODALS (global, outside pages)  */}
      {/* ================================ */}

      {/* -------------------------------- */}
      {/* MODAL: ASSET DETAILS (Phase 3)   */}
      {/* -------------------------------- */}
      {viewingAsset && (
        <div className="modal-backdrop" onClick={() => setViewingAsset(null)}>
          <div className="modal-content modal-asset-detail" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label={`Asset Details — ${viewingAsset.ip_address}`}>
            <div className="modal-header">
              <div>
                <h3>Asset Details — {viewingAsset.ip_address}</h3>
                <div className="modal-subtitle">
                  Asset ID #{viewingAsset.id} • Status: <span className="text-white font-medium">{viewingAsset.status || "Active"}</span> • Last Seen: {formatDateTime(viewingAsset.last_seen)}
                </div>
              </div>
              <button type="button" className="modal-close" onClick={() => setViewingAsset(null)} aria-label="Close">×</button>
            </div>

            <div className="modal-body asset-detail-body">
              {isAssetUnclassified(viewingAsset) && (
                <div className="asset-detail-warning">
                  <span className="unclassified-pill">Unclassified Asset</span>
                  <span>This host requires classification. Business criticality and ownership remain unassigned until reviewed.</span>
                </div>
              )}

              {/* 2-Column Overview Cards */}
              <div className="asset-detail-grid">
                {/* Identity & Network */}
                <div className="asset-detail-card">
                  <div className="asset-detail-card-title">🖥️ Identity & Network</div>
                  <div className="kv-row">
                    <span className="kv-label">IP Address</span>
                    <span className="kv-val font-mono">{viewingAsset.ip_address}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-label">Hostname</span>
                    <span className="kv-val">{viewingAsset.hostname || <span className="text-muted">Not Available</span>}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-label">MAC Address</span>
                    <span className="kv-val font-mono">{viewingAsset.mac_address || <span className="text-muted">Not Available</span>}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-label">Operating System</span>
                    <span className="kv-val">{viewingAsset.operating_system || <span className="text-muted">OS not identified</span>}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-label">Status</span>
                    <span className="kv-val">{viewingAsset.status || "Active"}</span>
                  </div>
                </div>

                {/* GRC Classification & Context */}
                <div className="asset-detail-card">
                  <div className="asset-detail-card-title">⚖️ GRC Classification & Governance</div>
                  <div className="kv-row">
                    <span className="kv-label">Business Criticality</span>
                    <span className="kv-val">
                      {isAssetUnclassified(viewingAsset) ? (
                        <span className="badge badge-unclassified">Unclassified</span>
                      ) : (
                        <span className={`badge ${getRiskClass(viewingAsset.criticality)}`}>{viewingAsset.criticality}</span>
                      )}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-label">Environment</span>
                    <span className="kv-val">
                      <span className="badge badge-neutral">{viewingAsset.environment || "Not Specified"}</span>
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-label">Exposure</span>
                    <span className="kv-val">
                      <span className="badge badge-exposure">{viewingAsset.exposure || "Not Specified"}</span>
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-label">Assigned Owner</span>
                    <span className="kv-val">{viewingAsset.owner || <span className="text-muted">Not Assigned</span>}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-label">Business Function</span>
                    <span className="kv-val">{viewingAsset.business_function || <span className="text-muted">Not Specified</span>}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-label">Risk Rating</span>
                    <span className="kv-val">
                      <span className={`badge ${getRiskClass(viewingAsset.risk_level)}`}>
                        {viewingAsset.risk_level} ({viewingAsset.risk_score})
                      </span>
                    </span>
                  </div>
                </div>
              </div>

              {/* Open Ports */}
              <div className="asset-detail-section">
                <div className="asset-detail-section-header">
                  <h4>Open Ports & Detected Services</h4>
                  <span className="section-count">
                    {parsePortsList(viewingAsset.open_ports).length} Ports
                  </span>
                </div>
                {(() => {
                  const ports = parsePortsList(viewingAsset.open_ports);
                  if (ports.length === 0) {
                    return <div className="detail-empty-text">No open ports recorded for this asset.</div>;
                  }
                  return (
                    <div className="asset-ports-grid">
                      {ports.map((portStr, idx) => (
                        <span key={idx} className="asset-port-pill">
                          🔌 {portStr}
                        </span>
                      ))}
                    </div>
                  );
                })()}
              </div>

              {/* Correlated Vulnerabilities */}
              <div className="asset-detail-section">
                <div className="asset-detail-section-header">
                  <h4>Correlated Vulnerabilities</h4>
                  {(() => {
                    const vulns = vulnerabilities.filter((v) => v.asset_id === viewingAsset.id);
                    return <span className="section-count">{vulns.length} Findings</span>;
                  })()}
                </div>
                {(() => {
                  const vulns = vulnerabilities.filter((v) => v.asset_id === viewingAsset.id);
                  if (vulns.length === 0) {
                    return <div className="detail-empty-text">No technical vulnerabilities correlated with this host.</div>;
                  }
                  return (
                    <div className="asset-detail-table-wrap">
                      <table className="asset-subtable">
                        <thead>
                          <tr>
                            <th>Port / Service</th>
                            <th>Finding</th>
                            <th>Severity</th>
                            <th>CVE</th>
                            <th>CVSS</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {vulns.map((v) => (
                            <tr key={v.id}>
                              <td className="font-mono">{v.port}/{v.service || "unknown"}</td>
                              <td>{v.title}</td>
                              <td><span className={`badge ${getRiskClass(v.severity)}`}>{v.severity}</span></td>
                              <td>{v.cve || <span className="text-muted">Not identified</span>}</td>
                              <td>{v.cvss_score != null ? `${v.cvss_score} (${v.cvss_version || "v3.1"})` : "—"}</td>
                              <td><span className={`status-pill ${getStatusClass(v.status)}`}>{v.status}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  );
                })()}
              </div>

              {/* Enterprise GRC Risks */}
              <div className="asset-detail-section">
                <div className="asset-detail-section-header">
                  <h4>Enterprise GRC Risks</h4>
                  {(() => {
                    const assetRisks = risks.filter((r) => r.asset_id === viewingAsset.id);
                    return <span className="section-count">{assetRisks.length} Risks</span>;
                  })()}
                </div>
                {(() => {
                  const assetRisks = risks.filter((r) => r.asset_id === viewingAsset.id);
                  if (assetRisks.length === 0) {
                    return <div className="detail-empty-text">No GRC risks currently mapped to this asset.</div>;
                  }
                  return (
                    <div className="asset-detail-table-wrap">
                      <table className="asset-subtable">
                        <thead>
                          <tr>
                            <th>Risk Title</th>
                            <th>Inherent</th>
                            <th>Residual</th>
                            <th>Treatment</th>
                            <th>Status</th>
                            <th>Review</th>
                          </tr>
                        </thead>
                        <tbody>
                          {assetRisks.map((r) => (
                            <tr key={r.id}>
                              <td>{r.title}</td>
                              <td><span className={`badge ${getRiskClass(r.inherent_risk_level)}`}>{r.inherent_risk_level} ({r.inherent_risk_score})</span></td>
                              <td><span className={`badge ${getRiskClass(r.residual_risk_level)}`}>{r.residual_risk_level} ({r.residual_risk_score})</span></td>
                              <td><span className="badge badge-treatment">{r.treatment}</span></td>
                              <td><span className={`status-pill ${getStatusClass(r.status)}`}>{r.status}</span></td>
                              <td><span className="badge badge-neutral">{r.review_status || "Pending"}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  );
                })()}
              </div>
            </div>

            <div className="modal-footer">
              <button
                type="button"
                className="btn-secondary"
                onClick={() => setViewingAsset(null)}
              >
                Close
              </button>
              <button
                type="button"
                className="btn-primary"
                onClick={() => {
                  const a = viewingAsset;
                  setViewingAsset(null);
                  openAssetModal(a);
                }}
              >
                Edit Intelligence
              </button>
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------- */}
      {/* MODAL: VULNERABILITY DETAILS (Phase 4) */}
      {/* -------------------------------- */}
      {viewingVuln && (() => {
        const asset = assets.find((a) => a.id === viewingVuln.asset_id);
        const relatedRisks = risks.filter((r) => r.asset_id === viewingVuln.asset_id);

        return (
          <div className="modal-backdrop" onClick={() => setViewingVuln(null)}>
            <div className="modal-content modal-vuln-detail" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label={`Vulnerability Details — ${viewingVuln.title}`}>
              <div className="modal-header">
                <div>
                  <h3>Vulnerability Details — {viewingVuln.title}</h3>
                  <div className="modal-subtitle">
                    Finding ID #{viewingVuln.id} • {viewingVuln.cve || "No CVE identifier"} • Discovered: {formatDateTime(viewingVuln.discovered_at)}
                  </div>
                </div>
                <button type="button" className="modal-close" onClick={() => setViewingVuln(null)} aria-label="Close">×</button>
              </div>

              <div className="modal-body asset-detail-body">
                {/* 2-Column Overview Cards */}
                <div className="asset-detail-grid">
                  {/* Identification & CVE Metadata */}
                  <div className="asset-detail-card">
                    <div className="asset-detail-card-title">🔍 Finding Identification & CVE</div>
                    <div className="kv-row">
                      <span className="kv-label">Finding ID</span>
                      <span className="kv-val font-mono">#{viewingVuln.id}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">CVE Identifier</span>
                      <span className="kv-val">
                        {viewingVuln.cve ? <span className="cve-tag">{viewingVuln.cve}</span> : <span className="text-muted">Not Identified</span>}
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">CVE Confidence</span>
                      <span className="kv-val">
                        <span className={`conf-badge conf-${(viewingVuln.cve_confidence || "none").toLowerCase()}`}>
                          {viewingVuln.cve_confidence || "None"}
                        </span>
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Candidates Evaluated</span>
                      <span className="kv-val font-mono">{viewingVuln.cve_candidate_count != null ? viewingVuln.cve_candidate_count : 0}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Status</span>
                      <span className="kv-val">
                        <span className={`status-pill ${getStatusClass(viewingVuln.status)}`}>
                          {viewingVuln.status || "Open"}
                        </span>
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Discovered At</span>
                      <span className="kv-val text-xs">{formatDateTime(viewingVuln.discovered_at)}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Last Updated</span>
                      <span className="kv-val text-xs">{formatDateTime(viewingVuln.updated_at)}</span>
                    </div>
                  </div>

                  {/* Severity & Technical Context */}
                  <div className="asset-detail-card">
                    <div className="asset-detail-card-title">⚡ Severity & Technical Context</div>
                    <div className="kv-row">
                      <span className="kv-label">Severity</span>
                      <span className="kv-val">
                        <span className={`badge ${getRiskClass(viewingVuln.severity)}`}>
                          {viewingVuln.severity || "Unknown"}
                        </span>
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">CVSS Base Score</span>
                      <span className="kv-val font-mono">
                        {viewingVuln.cvss_score != null ? viewingVuln.cvss_score : <span className="text-muted">Not Available</span>}
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">CVSS Version</span>
                      <span className="kv-val">{viewingVuln.cvss_version || <span className="text-muted">Not Specified</span>}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Port</span>
                      <span className="kv-val font-mono">{viewingVuln.port != null ? viewingVuln.port : <span className="text-muted">Not Specified</span>}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Service</span>
                      <span className="kv-val">{viewingVuln.service || <span className="text-muted">Unknown</span>}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Product</span>
                      <span className="kv-val">{viewingVuln.product || <span className="text-muted">Unknown</span>}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Version</span>
                      <span className="kv-val font-mono">{viewingVuln.version || <span className="text-muted">Not Specified</span>}</span>
                    </div>
                  </div>
                </div>

                {/* Description */}
                <div className="asset-detail-section">
                  <div className="asset-detail-section-header">
                    <h4>Description & Finding Details</h4>
                  </div>
                  <p className="vuln-desc-text">
                    {viewingVuln.description || "No description provided for this vulnerability finding."}
                  </p>
                </div>

                {/* Affected Asset */}
                <div className="asset-detail-section">
                  <div className="asset-detail-section-header">
                    <h4>Affected Infrastructure Asset</h4>
                    {asset && <span className="section-count">ID #{asset.id}</span>}
                  </div>
                  {asset ? (
                    <div className="asset-detail-grid">
                      <div className="kv-row">
                        <span className="kv-label">IP Address</span>
                        <span className="kv-val font-mono font-bold text-white">{asset.ip_address}</span>
                      </div>
                      <div className="kv-row">
                        <span className="kv-label">Hostname</span>
                        <span className="kv-val">{asset.hostname || <span className="text-muted">Not Available</span>}</span>
                      </div>
                      <div className="kv-row">
                        <span className="kv-label">Environment</span>
                        <span className="kv-val">
                          <span className="badge badge-neutral">{asset.environment || "Not Specified"}</span>
                        </span>
                      </div>
                      <div className="kv-row">
                        <span className="kv-label">Exposure</span>
                        <span className="kv-val">
                          <span className="badge badge-exposure">{asset.exposure || "Not Specified"}</span>
                        </span>
                      </div>
                      <div className="kv-row">
                        <span className="kv-label">Criticality</span>
                        <span className="kv-val">
                          {isAssetUnclassified(asset) ? (
                            <span className="badge badge-unclassified">Unclassified</span>
                          ) : (
                            <span className={`badge ${getRiskClass(asset.criticality)}`}>{asset.criticality}</span>
                          )}
                        </span>
                      </div>
                      <div className="kv-row">
                        <span className="kv-label">Owner</span>
                        <span className="kv-val">{asset.owner || <span className="text-muted">Not Assigned</span>}</span>
                      </div>
                    </div>
                  ) : (
                    <div className="detail-empty-text">
                      {viewingVuln.asset_id
                        ? `Associated with Asset #${viewingVuln.asset_id} (host metadata not available).`
                        : "No asset association recorded for this finding."}
                    </div>
                  )}
                </div>

                {/* Risks Registered for This Asset */}
                <div className="asset-detail-section">
                  <div className="asset-detail-section-header">
                    <h4>Risks Registered for This Asset</h4>
                    <span className="section-count">{relatedRisks.length} Risks</span>
                  </div>
                  <p className="vuln-section-desc">
                    Existing GRC risks identified on this host. These are asset-level risks and not necessarily direct mappings to this specific vulnerability finding.
                  </p>
                  {relatedRisks.length === 0 ? (
                    <div className="detail-empty-text">
                      No GRC risks currently registered for this asset.
                    </div>
                  ) : (
                    <div className="asset-detail-table-wrap">
                      <table className="asset-subtable">
                        <thead>
                          <tr>
                            <th>Risk Title</th>
                            <th>Inherent</th>
                            <th>Residual</th>
                            <th>Treatment</th>
                            <th>Status</th>
                            <th>Governance</th>
                          </tr>
                        </thead>
                        <tbody>
                          {relatedRisks.map((r) => (
                            <tr key={r.id}>
                              <td>{r.title}</td>
                              <td><span className={`badge ${getRiskClass(r.inherent_risk_level)}`}>{r.inherent_risk_level} ({r.inherent_risk_score})</span></td>
                              <td><span className={`badge ${getRiskClass(r.residual_risk_level)}`}>{r.residual_risk_level} ({r.residual_risk_score})</span></td>
                              <td><span className="badge badge-treatment">{r.treatment}</span></td>
                              <td><span className={`status-pill ${getStatusClass(r.status)}`}>{r.status}</span></td>
                              <td><span className="badge badge-neutral">{r.review_status || "Pending"}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                {/* Remediation & Mitigation Information */}
                <div className="asset-detail-section">
                  <div className="asset-detail-section-header">
                    <h4>Remediation & Action Guidance</h4>
                  </div>
                  <div className="vuln-remediation-box">
                    <div className="remediation-notice">
                      ℹ️ Remediation guidance not available in current finding data.
                    </div>
                    <p className="remediation-hint">
                      {relatedRisks.length > 0
                        ? "To manage asset-level risk, review the registered risks and assigned controls for this host in the Risk Management register."
                        : "To manage asset-level risk, consider assessing risk impact in the Risk Management module or verifying port exposure in the Asset Inventory."}
                    </p>
                  </div>
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setViewingVuln(null)}
                >
                  Close
                </button>
                {asset && (
                  <button
                    type="button"
                    className="btn-primary"
                    onClick={() => {
                      setViewingVuln(null);
                      setActivePage("assets");
                      setViewingAsset(asset);
                    }}
                  >
                    View Asset in Inventory
                  </button>
                )}
              </div>
            </div>
          </div>
        );
      })()}

      {/* -------------------------------- */}
      {/* MODAL: VIEW RISK DETAILS         */}
      {/* -------------------------------- */}
      {viewingRisk && (() => {
        const liveRisk = risks.find((r) => r.id === viewingRisk.id) || viewingRisk;
        const asset = assets.find((a) => a.id === liveRisk.asset_id);
        const relatedVulns = vulnerabilities.filter((v) => v.asset_id === liveRisk.asset_id);

        return (
          <div className="modal-backdrop" onClick={() => setViewingRisk(null)}>
            <div className="modal-content modal-risk-detail" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label={`Risk Details — #${liveRisk.id}: ${liveRisk.title}`}>
              <div className="modal-header">
                <div>
                  <h3>Risk Details — #{liveRisk.id}: {liveRisk.title}</h3>
                  <div className="modal-subtitle">
                    Asset: {asset ? `${asset.ip_address} (${asset.hostname || "Host"})` : `Asset #${liveRisk.asset_id}`} • Lifecycle: {liveRisk.status || "Open"} • Governance: {liveRisk.review_status || "Pending Review"}
                  </div>
                </div>
                <button type="button" className="modal-close" onClick={() => setViewingRisk(null)} aria-label="Close">×</button>
              </div>

              <div className="modal-body asset-detail-body">
                {/* Top 2-Column Grid: Identification & Assessment */}
                <div className="asset-detail-grid">
                  {/* Risk Identification */}
                  <div className="asset-detail-card">
                    <div className="asset-detail-card-title">🔍 Risk Identification</div>
                    <div className="kv-row">
                      <span className="kv-label">Risk ID</span>
                      <span className="kv-val font-mono">#{liveRisk.id}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Title</span>
                      <span className="kv-val font-medium">{liveRisk.title}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Framework Mapping</span>
                      <span className="kv-val">
                        {liveRisk.compliance_framework ? (
                          <span className="framework-tag">
                            {liveRisk.compliance_framework} ({liveRisk.compliance_control || "Control"})
                          </span>
                        ) : (
                          <span className="text-muted">Not Specified</span>
                        )}
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Affected Asset</span>
                      <span className="kv-val">
                        {asset ? (
                          <span className="ip-pill">{asset.ip_address} {asset.hostname ? `(${asset.hostname})` : ""}</span>
                        ) : (
                          <span className="text-muted">Asset #{liveRisk.asset_id}</span>
                        )}
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Asset Criticality</span>
                      <span className="kv-val">
                        {asset ? (
                          <span className={`badge ${getRiskClass(asset.criticality)}`}>{asset.criticality || "Unclassified"}</span>
                        ) : (
                          <span className="text-muted">Not Available</span>
                        )}
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Asset Environment</span>
                      <span className="kv-val">{asset?.environment || "Not Available"}</span>
                    </div>
                  </div>

                  {/* Risk Assessment: Inherent vs. Residual */}
                  <div className="asset-detail-card">
                    <div className="asset-detail-card-title">⚖️ Risk Assessment (Inherent vs. Residual)</div>
                    <div className="kv-row">
                      <span className="kv-label">Inherent Risk Level</span>
                      <span className="kv-val">
                        <span className={`badge ${getRiskClass(liveRisk.inherent_risk_level || liveRisk.risk_level)}`}>
                          {liveRisk.inherent_risk_level || liveRisk.risk_level || "Medium"}
                        </span>
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Inherent Score</span>
                      <span className="kv-val font-mono">
                        {liveRisk.inherent_risk_score != null ? liveRisk.inherent_risk_score : liveRisk.risk_score} (Likelihood: {liveRisk.likelihood_score || 2} × Impact: {liveRisk.impact_score || 2})
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Residual Risk Level</span>
                      <span className="kv-val">
                        <span className={`badge ${getRiskClass(liveRisk.residual_risk_level)}`}>
                          {liveRisk.residual_risk_level || "Not Available"}
                        </span>
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Residual Score</span>
                      <span className="kv-val font-mono">
                        {liveRisk.residual_risk_score != null ? liveRisk.residual_risk_score : "Not Available"}
                        {liveRisk.residual_likelihood != null || liveRisk.residual_impact != null ? (
                          ` (Res Likelihood: ${liveRisk.residual_likelihood != null ? liveRisk.residual_likelihood : "Not Available"} × Res Impact: ${liveRisk.residual_impact != null ? liveRisk.residual_impact : "Not Available"})`
                        ) : ""}
                      </span>
                    </div>

                    {/* Inherent to Residual Trajectory Box */}
                    {liveRisk.inherent_risk_score != null && liveRisk.residual_risk_score != null ? (
                      <div className="risk-detail-trajectory-box">
                        <div className="risk-detail-trajectory-item">
                          <div className="risk-detail-trajectory-label">Inherent Posture</div>
                          <div className="risk-detail-trajectory-val" style={{ color: "#f87171" }}>
                            Score {liveRisk.inherent_risk_score}
                          </div>
                          <div className="text-xs text-slate">{liveRisk.inherent_risk_level || "Not Available"}</div>
                        </div>
                        <div style={{ fontSize: "20px", color: "#38bdf8", fontWeight: "bold" }}>➔</div>
                        <div className="risk-detail-trajectory-item">
                          <div className="risk-detail-trajectory-label">Residual Posture</div>
                          <div className="risk-detail-trajectory-val" style={{ color: "#4ade80" }}>
                            Score {liveRisk.residual_risk_score}
                          </div>
                          <div className="text-xs text-slate">{liveRisk.residual_risk_level || "Not Available"}</div>
                        </div>
                      </div>
                    ) : (
                      <div className="text-xs text-slate" style={{ marginTop: "10px", textAlign: "center", fontStyle: "italic" }}>
                        Residual risk trajectory not available (residual metrics not assessed).
                      </div>
                    )}
                  </div>
                </div>

                {/* Governance & Ownership */}
                <div className="asset-detail-card" style={{ marginTop: "16px" }}>
                  <div className="asset-detail-card-title">🏛️ Governance, Treatment & Lifecycle</div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "10px" }}>
                    <div className="kv-row">
                      <span className="kv-label">Risk Owner</span>
                      <span className="kv-val font-medium">{liveRisk.risk_owner || <span className="text-muted">Not Assigned</span>}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Treatment Strategy</span>
                      <span className="kv-val">
                        <span className="badge badge-treatment">{liveRisk.treatment || "Mitigate"}</span>
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Lifecycle Status</span>
                      <span className="kv-val">
                        <span className={`status-pill ${getStatusClass(liveRisk.status)}`}>{liveRisk.status || "Open"}</span>
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Governance Review</span>
                      <span className="kv-val">{getReviewStatusBadge(liveRisk.review_status || "Pending Review")}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Remediation Due Date</span>
                      <span className="kv-val text-xs">{liveRisk.due_date ? formatDateTime(liveRisk.due_date) : <span className="text-muted">Not Specified</span>}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Created At</span>
                      <span className="kv-val text-xs">{formatDateTime(liveRisk.created_at)}</span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-label">Last Updated</span>
                      <span className="kv-val text-xs">{formatDateTime(liveRisk.updated_at)}</span>
                    </div>
                  </div>
                </div>

                {/* Description & Recommendation */}
                {(liveRisk.description || liveRisk.recommendation) && (
                  <div className="asset-detail-card" style={{ marginTop: "16px" }}>
                    <div className="asset-detail-card-title">📝 Finding Description & Guidance</div>
                    {liveRisk.description && (
                      <div style={{ marginBottom: liveRisk.recommendation ? "12px" : 0 }}>
                        <div className="text-xs font-semibold text-slate" style={{ marginBottom: "4px" }}>DESCRIPTION:</div>
                        <p className="vuln-desc-text">{liveRisk.description}</p>
                      </div>
                    )}
                    {liveRisk.recommendation && (
                      <div>
                        <div className="text-xs font-semibold text-slate" style={{ marginBottom: "4px" }}>RECOMMENDED SAFEGUARD:</div>
                        <p className="vuln-desc-text">{liveRisk.recommendation}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Mitigating Controls Section */}
                <div className="asset-detail-card" style={{ marginTop: "16px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                    <div className="asset-detail-card-title" style={{ margin: 0 }}>
                      🛡️ Mitigating Security Controls ({liveRisk.controls ? liveRisk.controls.length : 0})
                    </div>
                    <div style={{ fontSize: "11px", color: "#64748b" }}>
                      Controls reduce likelihood rating based on effectiveness
                    </div>
                  </div>

                  {liveRisk.controls && liveRisk.controls.length > 0 ? (
                    <div className="table-responsive" style={{ margin: "8px 0" }}>
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Control Name</th>
                            <th>Framework</th>
                            <th>Category</th>
                            <th>Effectiveness</th>
                            <th>Status</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {liveRisk.controls.map((c) => (
                            <tr key={c.id}>
                              <td><strong>{c.name}</strong></td>
                              <td><span className="badge badge-neutral">{c.framework || "NIST CSF"}</span></td>
                              <td>{c.category || "Preventive"}</td>
                              <td>
                                <span className={`badge ${c.effectiveness === "High" ? "badge-eff-high" : "badge-eff-med"}`}>
                                  {c.effectiveness} ({c.effectiveness === "High" ? "-2 Likelihood" : c.effectiveness === "Medium" ? "-1 Likelihood" : "0 Likelihood"})
                                </span>
                              </td>
                              <td>
                                <span className={`status-pill ${c.status === "Implemented" ? "status-resolved" : "status-review"}`}>
                                  {c.status}
                                </span>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  className="btn-mini btn-cancel"
                                  onClick={() => handleDetachControl(liveRisk.id, c.id)}
                                  title="Detach control from this risk"
                                >
                                  Detach
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="text-xs text-muted" style={{ padding: "10px 0" }}>
                      No mitigating security controls currently assigned to this risk.
                    </div>
                  )}

                  {/* Inline Assign Control Box */}
                  <div style={{ marginTop: "8px", display: "flex", gap: "8px", alignItems: "center" }}>
                    <select
                      value={selectedControlId}
                      onChange={(e) => setSelectedControlId(e.target.value)}
                      className="select-filter"
                      style={{ maxWidth: "340px", fontSize: "12px" }}
                    >
                      <option value="">Select Control from Catalog to Assign...</option>
                      {controls
                        .filter((c) => !liveRisk.controls?.some((rc) => rc.id === c.id))
                        .map((c) => (
                          <option key={c.id} value={c.id}>
                            {c.name} ({c.effectiveness} Effectiveness)
                          </option>
                        ))}
                    </select>
                    <button
                      type="button"
                      className="btn-primary btn-sm"
                      onClick={() => handleAssignControl(liveRisk.id)}
                      disabled={!selectedControlId}
                    >
                      Assign Control
                    </button>
                  </div>
                </div>

                {/* Section: Technical Vulnerabilities on Affected Asset */}
                <div className="asset-detail-card" style={{ marginTop: "16px" }}>
                  <div className="asset-detail-card-title">
                    ⚡ Vulnerabilities Recorded for This Asset ({relatedVulns.length})
                  </div>
                  <div className="vuln-section-desc">
                    These findings were detected on the same asset ({asset ? asset.ip_address : `Asset #${liveRisk.asset_id}`}). They represent technical exposure for that host and do not establish a direct 1:1 causal link to this enterprise risk.
                  </div>

                  {relatedVulns.length === 0 ? (
                    <div className="empty-cell" style={{ padding: "16px", textAlign: "center" }}>
                      No technical vulnerability findings recorded for this asset.
                    </div>
                  ) : (
                    <div className="table-responsive">
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Finding</th>
                            <th>CVE</th>
                            <th>Severity</th>
                            <th>CVSS</th>
                            <th>Port / Service</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {relatedVulns.map((v) => (
                            <tr key={v.id}>
                              <td><strong>{v.title}</strong></td>
                              <td>{v.cve ? <span className="cve-tag">{v.cve}</span> : <span className="text-muted">—</span>}</td>
                              <td><span className={`badge ${getRiskClass(v.severity)}`}>{v.severity || "Unknown"}</span></td>
                              <td><span className="font-mono text-xs">{v.cvss_score != null ? v.cvss_score : "—"}</span></td>
                              <td><span className="port-pill font-mono">{v.port ? `${v.port}/${v.service || "tcp"}` : "Host-level"}</span></td>
                              <td><span className={`status-pill ${getStatusClass(v.status)}`}>{v.status || "Open"}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                {/* Section: AI Risk Intelligence */}
                <div className="asset-detail-card" style={{ marginTop: "16px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                    <div className="asset-detail-card-title" style={{ margin: 0 }}>
                      ✦ AI-Assisted Security Intelligence
                    </div>
                    <button
                      type="button"
                      className={`btn-ai-analyze${expandedAiPanel === liveRisk.id ? " btn-ai-active" : ""}`}
                      onClick={() => handleAnalyzeRisk(liveRisk.id)}
                      disabled={!!aiLoading[liveRisk.id]}
                    >
                      {aiLoading[liveRisk.id] ? "Analyzing..." : aiAnalysis[liveRisk.id] ? "↺ Re-analyze" : "✦ Run AI Analysis"}
                    </button>
                  </div>
                  <div className="vuln-section-desc">
                    AI analysis is advisory security intelligence and does not alter authoritative GRC risk scores.
                  </div>

                  <AIAnalysisPanel
                    loading={!!aiLoading[liveRisk.id]}
                    error={aiError[liveRisk.id] || null}
                    analysis={aiAnalysis[liveRisk.id] || null}
                    onReanalyze={() => handleReanalyzeRisk(liveRisk.id)}
                  />
                </div>
              </div>

              {/* Modal Footer Actions */}
              <div className="modal-footer" style={{ justifyContent: "space-between" }}>
                <div>
                  {asset && (
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => {
                        setActivePage("assets");
                        setAssetSearchQuery(asset.ip_address);
                        setViewingRisk(null);
                      }}
                    >
                      View Asset in Inventory ➔
                    </button>
                  )}
                </div>
                <div style={{ display: "flex", gap: "8px" }}>
                  <button
                    type="button"
                    className="btn-action"
                    onClick={() => {
                      openRiskModal(liveRisk);
                      setViewingRisk(null);
                    }}
                  >
                    Manage Treatment
                  </button>
                  <button
                    type="button"
                    className="btn-action"
                    onClick={() => {
                      openSubmitReviewModal(liveRisk);
                      setViewingRisk(null);
                    }}
                  >
                    Sign-Off
                  </button>
                  <button
                    type="button"
                    className="btn-action"
                    onClick={() => openReviewHistoryModal(liveRisk)}
                  >
                    Review History
                  </button>
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => setViewingRisk(null)}
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>
        );
      })()}

      {editingAsset && (
        <div className="modal-backdrop" onClick={() => setEditingAsset(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label={`Edit Asset Intelligence — ${editingAsset.ip_address}`}>
            <div className="modal-header">
              <h3>Edit Asset Intelligence — {editingAsset.ip_address}</h3>
              <button type="button" className="modal-close" onClick={() => setEditingAsset(null)} aria-label="Close">×</button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Business Criticality</label>
                <select
                  value={assetForm.criticality}
                  onChange={(e) => setAssetForm({ ...assetForm, criticality: e.target.value })}
                >
                  <option value="Low">Low (Impact = 1)</option>
                  <option value="Medium">Medium (Impact = 2)</option>
                  <option value="High">High (Impact = 3)</option>
                  <option value="Critical">Critical (Impact = 4)</option>
                </select>
                <span className="form-hint">Directly sets the Impact Score for all risks on this asset.</span>
              </div>

              <div className="form-group">
                <label>Environment</label>
                <select
                  value={assetForm.environment}
                  onChange={(e) => setAssetForm({ ...assetForm, environment: e.target.value })}
                >
                  <option value="Production">Production</option>
                  <option value="Development">Development</option>
                  <option value="Testing">Testing</option>
                </select>
              </div>

              <div className="form-group">
                <label>Network Exposure</label>
                <select
                  value={assetForm.exposure}
                  onChange={(e) => setAssetForm({ ...assetForm, exposure: e.target.value })}
                >
                  <option value="Internal">Internal (-1 Likelihood modifier)</option>
                  <option value="DMZ">DMZ (0 Likelihood modifier)</option>
                  <option value="External">External (+1 Likelihood modifier)</option>
                </select>
                <span className="form-hint">Affects the technical Likelihood score for findings on this host.</span>
              </div>

              <div className="form-group">
                <label>Asset Owner</label>
                <input
                  type="text"
                  placeholder="e.g. Infrastructure Team / John Doe"
                  value={assetForm.owner}
                  onChange={(e) => setAssetForm({ ...assetForm, owner: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>Business Function</label>
                <input
                  type="text"
                  placeholder="e.g. Core Database / Gateway"
                  value={assetForm.business_function}
                  onChange={(e) => setAssetForm({ ...assetForm, business_function: e.target.value })}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn-secondary" onClick={() => setEditingAsset(null)}>Cancel</button>
              <button type="button" className="btn-primary" onClick={saveAsset}>Save & Recalculate Risks</button>
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------- */}
      {/* MODAL: MANAGE RISK */}
      {/* -------------------------------- */}
      {editingRisk && (
        <div className="modal-backdrop" onClick={() => setEditingRisk(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label={`Manage Risk Treatment — #${editingRisk.id}`}>
            <div className="modal-header">
              <h3>Manage Risk Treatment — #{editingRisk.id}</h3>
              <button type="button" className="modal-close" onClick={() => setEditingRisk(null)} aria-label="Close">×</button>
            </div>
            <div className="modal-body">
              <div className="risk-summary-box">
                <strong>{editingRisk.title}</strong>
                <div>Inherent Score: {editingRisk.inherent_risk_score} • Residual Score: {editingRisk.residual_risk_score}</div>
              </div>

              <div className="form-group">
                <label>Risk Treatment Decision</label>
                <select
                  value={riskForm.treatment}
                  onChange={(e) => setRiskForm({ ...riskForm, treatment: e.target.value })}
                >
                  <option value="Mitigate">Mitigate (Deploy Controls)</option>
                  <option value="Accept">Accept (Document Business Acceptance)</option>
                  <option value="Transfer">Transfer (Insurance / Third-party)</option>
                  <option value="Avoid">Avoid (Decommission Service)</option>
                </select>
              </div>

              <div className="form-group">
                <label>Risk Owner</label>
                <input
                  type="text"
                  placeholder="e.g. SecOps Lead / Jane Smith"
                  value={riskForm.risk_owner}
                  onChange={(e) => setRiskForm({ ...riskForm, risk_owner: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>Remediation Due Date</label>
                <input
                  type="date"
                  value={riskForm.due_date}
                  onChange={(e) => setRiskForm({ ...riskForm, due_date: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>Lifecycle Status</label>
                <select
                  value={riskForm.status}
                  onChange={(e) => setRiskForm({ ...riskForm, status: e.target.value })}
                >
                  <option value="Open">Open</option>
                  <option value="Under Review">Under Review</option>
                  <option value="Accepted">Accepted</option>
                  <option value="Resolved">Resolved</option>
                </select>
              </div>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn-secondary" onClick={() => setEditingRisk(null)}>Cancel</button>
              <button type="button" className="btn-primary" onClick={saveRisk}>Save Changes</button>
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------- */}
      {/* MODAL: ADD CONTROL */}
      {/* -------------------------------- */}
      {showAddControlModal && (
        <div className="modal-backdrop" onClick={() => setShowAddControlModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Add Security Control to Catalog">
            <div className="modal-header">
              <h3>Add Security Control to Catalog</h3>
              <button type="button" className="modal-close" onClick={() => setShowAddControlModal(false)} aria-label="Close">×</button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Control Name *</label>
                <input
                  type="text"
                  placeholder="e.g. Web Application Firewall (WAF)"
                  value={controlForm.name}
                  onChange={(e) => setControlForm({ ...controlForm, name: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>Compliance Framework</label>
                <input
                  type="text"
                  placeholder="e.g. NIST CSF (PR.AC-4), ISO 27001"
                  value={controlForm.framework}
                  onChange={(e) => setControlForm({ ...controlForm, framework: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>Category</label>
                <select
                  value={controlForm.category}
                  onChange={(e) => setControlForm({ ...controlForm, category: e.target.value })}
                >
                  <option value="Preventive">Preventive</option>
                  <option value="Detective">Detective</option>
                  <option value="Corrective">Corrective</option>
                </select>
              </div>

              <div className="form-group">
                <label>Mitigation Effectiveness</label>
                <select
                  value={controlForm.effectiveness}
                  onChange={(e) => setControlForm({ ...controlForm, effectiveness: e.target.value })}
                >
                  <option value="High">High (-2 Likelihood reduction)</option>
                  <option value="Medium">Medium (-1 Likelihood reduction)</option>
                  <option value="Low">Low (0 Likelihood reduction)</option>
                </select>
              </div>

              <div className="form-group">
                <label>Implementation Status</label>
                <select
                  value={controlForm.status}
                  onChange={(e) => setControlForm({ ...controlForm, status: e.target.value })}
                >
                  <option value="Implemented">Implemented (Actively mitigating)</option>
                  <option value="Planned">Planned (No mitigation yet)</option>
                  <option value="Under Review">Under Review</option>
                </select>
              </div>

              <div className="form-group">
                <label>Description</label>
                <textarea
                  rows="3"
                  placeholder="Describe the safeguard mechanism and scope..."
                  value={controlForm.description}
                  onChange={(e) => setControlForm({ ...controlForm, description: e.target.value })}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn-secondary" onClick={() => setShowAddControlModal(false)}>Cancel</button>
              <button type="button" className="btn-primary" onClick={saveNewControl}>Add to Catalog</button>
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------- */}
      {/* MODAL: VIEW COMPLIANCE REQUIREMENT DETAILS (PHASE 6) */}
      {/* -------------------------------- */}
      {viewingRequirement && (() => {
        const req = requirements.find(r => r.id === viewingRequirement.id) || viewingRequirement;
        const mappedControls = req.mapped_controls || [];
        const correlatedRisks = risks.filter(
          risk => risk.controls && risk.controls.some(rc => mappedControls.some(mc => mc.id === rc.id))
        );

        return (
          <div className="modal-backdrop" onClick={() => setViewingRequirement(null)}>
            <div
              className="modal-content compliance-detail-modal"
              onClick={(e) => e.stopPropagation()}
              role="dialog"
              aria-modal="true"
              aria-label={`Requirement Details — ${req.requirement_id || req.title}`}
            >
              <div className="modal-header">
                <div className="compliance-modal-header-info">
                  <div className="compliance-modal-badges">
                    <span className="req-code-badge">{req.requirement_id || "ID Not Available"}</span>
                    <span className="compliance-fw-tag">{req.framework_name} v{req.framework_version}</span>
                    <span className="function-pill">{req.function}</span>
                  </div>
                  <h3>{req.title}</h3>
                </div>
                <button type="button" className="modal-close" onClick={() => setViewingRequirement(null)} aria-label="Close">×</button>
              </div>

              <div className="modal-body compliance-modal-body">
                {/* Section 1: Requirement Specification */}
                <div className="compliance-modal-section">
                  <h4 className="compliance-section-heading">Requirement Specification</h4>
                  <div className="compliance-meta-grid">
                    <div className="compliance-meta-item">
                      <span className="compliance-meta-label">Framework</span>
                      <span className="compliance-meta-val">{req.framework_name} v{req.framework_version}</span>
                    </div>
                    <div className="compliance-meta-item">
                      <span className="compliance-meta-label">Function / Domain</span>
                      <span className="compliance-meta-val">{req.function}</span>
                    </div>
                    <div className="compliance-meta-item">
                      <span className="compliance-meta-label">Category</span>
                      <span className="compliance-meta-val">{req.category || "Not Available"}</span>
                    </div>
                    <div className="compliance-meta-item">
                      <span className="compliance-meta-label">Subcategory</span>
                      <span className="compliance-meta-val">{req.subcategory || "Not Available"}</span>
                    </div>
                    <div className="compliance-meta-item">
                      <span className="compliance-meta-label">Last Evaluated</span>
                      <span className="compliance-meta-val">{formatDateTime(req.updated_at, "Not Available")}</span>
                    </div>
                    <div className="compliance-meta-item">
                      <span className="compliance-meta-label">Created</span>
                      <span className="compliance-meta-val">{formatDateTime(req.created_at, "Not Available")}</span>
                    </div>
                  </div>
                  <div className="compliance-desc-box">
                    <span className="compliance-desc-label">Requirement Statement:</span>
                    <p className="compliance-desc-text">{req.description}</p>
                  </div>
                </div>

                {/* Section 2: Implementation Posture */}
                <div className="compliance-modal-section">
                  <div className="compliance-section-header-row">
                    <h4 className="compliance-section-heading">Implementation Posture</h4>
                    <button
                      className="btn-action"
                      onClick={() => openRequirementModal(req)}
                    >
                      Update Assessment
                    </button>
                  </div>
                  <div className="compliance-posture-card">
                    <div className="compliance-posture-row">
                      <span className="compliance-meta-label">Current Status:</span>
                      <span className={`badge ${getComplianceStatusClass(req.status)}`}>
                        {req.status || "Not Assessed"}
                      </span>
                    </div>
                    <div className="compliance-posture-notes">
                      <span className="compliance-meta-label">Auditor Observations & Evidence Notes:</span>
                      <p className="compliance-notes-text">
                        {req.notes || "No notes recorded for this requirement."}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Section 3: Mapped Security Controls */}
                <div className="compliance-modal-section">
                  <h4 className="compliance-section-heading">
                    Mapped Security Controls ({mappedControls.length})
                  </h4>
                  {mappedControls.length === 0 ? (
                    <div className="compliance-empty-sub">
                      No security controls currently mapped to this requirement.
                    </div>
                  ) : (
                    <div className="compliance-controls-grid">
                      {mappedControls.map((mc) => (
                        <div key={mc.id || mc.name} className="compliance-control-item">
                          <div className="compliance-control-item-header">
                            <span className="compliance-control-name">{mc.name}</span>
                            <span className={`strength-tag ${mc.mapping_strength === "Direct" ? "strength-direct" : "strength-sup"}`}>
                              {mc.mapping_strength || "Supporting"}
                            </span>
                          </div>
                          <div className="compliance-control-meta">
                            <span>Category: <strong>{mc.category || "General"}</strong></span>
                            <span>Effectiveness: <strong>{mc.effectiveness || "Not Assessed"}</strong></span>
                            <span>Status: <strong>{mc.status || "Active"}</strong></span>
                          </div>
                          {mc.notes && (
                            <div className="compliance-control-notes">
                              {mc.notes}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Section 4: Associated Enterprise Risks via Mapped Security Controls */}
                <div className="compliance-modal-section">
                  <h4 className="compliance-section-heading">
                    Associated Enterprise Risks via Mapped Security Controls ({correlatedRisks.length})
                  </h4>
                  <div className="compliance-disclaimer-sub">
                    <strong>Control Reuse Notice:</strong> The enterprise risks listed below are associated with this compliance requirement strictly through shared mitigating security controls. This reflects security control reuse across the risk register and does not prove that this requirement directly causes, mitigates, or owns any specific risk finding.
                  </div>
                  {correlatedRisks.length === 0 ? (
                    <div className="compliance-empty-sub">
                      No enterprise risks currently associated with these mapped controls.
                    </div>
                  ) : (
                    <div className="table-responsive" style={{ maxHeight: "200px" }}>
                      <table className="data-table" style={{ fontSize: "12px" }}>
                        <thead>
                          <tr>
                            <th>Risk ID</th>
                            <th>Risk Title</th>
                            <th>Inherent Level</th>
                            <th>Residual Level</th>
                            <th>Treatment</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {correlatedRisks.map((cr) => (
                            <tr key={cr.id}>
                              <td><span className="code-pill">RISK-{cr.id}</span></td>
                              <td><strong>{cr.title}</strong></td>
                              <td><span className={`badge ${getRiskClass(cr.inherent_risk_level || cr.risk_level)}`}>{cr.inherent_risk_level || cr.risk_level}</span></td>
                              <td><span className={`badge ${cr.residual_risk_level ? getRiskClass(cr.residual_risk_level) : "badge-neutral"}`}>{cr.residual_risk_level || "Not Available"}</span></td>
                              <td>{cr.treatment || "Mitigate"}</td>
                              <td><span className={`status-pill ${cr.status === "Open" ? "status-open" : "status-resolved"}`}>{cr.status}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                {/* Factual Disclaimer Footer */}
                <div className="compliance-modal-disclaimer">
                  <span className="info-icon">ℹ️</span>
                  <span>
                    Implementation Coverage reflects mapped requirement implementation status in this platform. It is not a certification or independent compliance assessment.
                  </span>
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" className="btn-secondary" onClick={() => setViewingRequirement(null)}>Close</button>
                <button type="button" className="btn-primary" onClick={() => openRequirementModal(req)}>Assess Requirement</button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* -------------------------------- */}
      {/* MODAL: ASSESS COMPLIANCE REQUIREMENT (PHASE 3) */}
      {/* -------------------------------- */}
      {editingRequirement && (
        <div className="modal-backdrop" onClick={() => setEditingRequirement(null)}>
          <div
            className="modal-content"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-label={`Assess Requirement — ${editingRequirement.requirement_id}`}
          >
            <div className="modal-header">
              <h3>Assess Requirement — {editingRequirement.requirement_id}</h3>
              <button type="button" className="modal-close" onClick={() => setEditingRequirement(null)} aria-label="Close">×</button>
            </div>
            <div className="modal-body">
              <div className="risk-summary-box">
                <strong>{editingRequirement.title}</strong>
                <div>{editingRequirement.framework_name} v{editingRequirement.framework_version} • Function: {editingRequirement.function}</div>
                <div className="sub-text">{editingRequirement.description}</div>
              </div>

              <div className="form-group">
                <label>Compliance Status</label>
                <select
                  value={requirementForm.status}
                  onChange={(e) => setRequirementForm({ ...requirementForm, status: e.target.value })}
                >
                  <option value="Not Assessed">Not Assessed</option>
                  <option value="Partially Implemented">Partially Implemented</option>
                  <option value="Implemented">Implemented</option>
                  <option value="Not Implemented">Not Implemented</option>
                  <option value="Not Applicable">Not Applicable</option>
                </select>
                <span className="form-hint">
                  Assess independently of control mappings. Affects the Implementation Coverage metric.
                </span>
              </div>

              <div className="form-group">
                <label>Auditor Notes & Observations</label>
                <textarea
                  rows="4"
                  placeholder="Record assessment evidence, gaps, or justification for applicability..."
                  value={requirementForm.notes}
                  onChange={(e) => setRequirementForm({ ...requirementForm, notes: e.target.value })}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn-secondary" onClick={() => setEditingRequirement(null)}>Cancel</button>
              <button type="button" className="btn-primary" onClick={saveRequirementAssessment}>Save Assessment</button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------ */}
      {/* MODAL: ADD / EDIT MONITORING SCHEDULE (PHASE 5)  */}
      {/* ------------------------------------------------ */}
      {showScheduleModal && (
        <div className="modal-backdrop" onClick={() => setShowScheduleModal(false)}>
          <div
            className="modal-content"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-label={editingSchedule ? `Edit Schedule — #${editingSchedule.id}` : "Configure Automated Scan Schedule"}
          >
            <div className="modal-header">
              <h3>{editingSchedule ? `Edit Schedule — #${editingSchedule.id}` : "Configure Automated Scan Schedule"}</h3>
              <button type="button" className="modal-close" onClick={() => setShowScheduleModal(false)} aria-label="Close">×</button>
            </div>
            <form onSubmit={handleSaveSchedule}>
              <div className="modal-body">
                {scheduleActionError && (
                  <div className="modal-error-banner">⚠ {scheduleActionError}</div>
                )}
                <div className="form-group">
                  <label>Schedule Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Subnet Daily Sweep"
                    value={scheduleForm.name}
                    onChange={(e) => setScheduleForm({ ...scheduleForm, name: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label>Target Scope (Private RFC 1918, Max /24)</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. 192.168.127.0/24 or 10.0.1.0/24"
                    value={scheduleForm.target}
                    onChange={(e) => setScheduleForm({ ...scheduleForm, target: e.target.value })}
                  />
                  <span className="form-hint">
                    Only private networks allowed. Single IPv4 or /24-/32 subnets (maximum 256 hosts).
                  </span>
                </div>
                <div className="form-group">
                  <label>Scan Interval (Minutes)</label>
                  <input
                    type="number"
                    min="15"
                    step="1"
                    required
                    value={scheduleForm.interval_minutes}
                    onChange={(e) => setScheduleForm({ ...scheduleForm, interval_minutes: e.target.value })}
                  />
                  <span className="form-hint">
                    Minimum allowed interval is 15 minutes to avoid network and CPU congestion.
                  </span>
                </div>
              </div>
              <div className="modal-footer">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setShowScheduleModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-primary"
                  disabled={submittingSchedule}
                >
                  {submittingSchedule ? "Saving..." : (editingSchedule ? "Save Changes" : "Create Schedule")}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* -------------------------------- */}
      {/* MODAL: SUBMIT RISK REVIEW (PHASE 6C) */}
      {/* -------------------------------- */}
      {reviewingRisk && (
        <div className="modal-backdrop" onClick={() => setReviewingRisk(null)}>
          <div
            className="modal-content"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: "620px" }}
            role="dialog"
            aria-modal="true"
            aria-label={`Submit Governance Risk Review — #${reviewingRisk.id}`}
          >
            <div className="modal-header">
              <h3>Submit Governance Risk Review — #{reviewingRisk.id}</h3>
              <button type="button" className="modal-close" onClick={() => setReviewingRisk(null)} aria-label="Close">×</button>
            </div>
            <form onSubmit={handleReviewSubmit}>
              <div className="modal-body">
                {reviewSubmitError && (
                  <div className="modal-error-banner">⚠ {reviewSubmitError}</div>
                )}

                <div className="risk-summary-box">
                  <strong>{reviewingRisk.title}</strong>
                  <div>
                    Inherent: {reviewingRisk.inherent_risk_level || "Medium"} ({reviewingRisk.inherent_risk_score || reviewingRisk.risk_score}) • Residual: {reviewingRisk.residual_risk_level || "Not Available"} ({reviewingRisk.residual_risk_score != null ? reviewingRisk.residual_risk_score : "Not Available"})
                  </div>
                  <div className="sub-text">
                    Current Treatment: {reviewingRisk.treatment || "Mitigate"} • Lifecycle: {reviewingRisk.status || "Open"} • Review Status: {reviewingRisk.review_status || "Pending Review"}
                  </div>
                </div>

                {/* Reviewer Attribution */}
                <div style={{ marginTop: "14px" }}>
                  <div className="card-label" style={{ marginBottom: "4px" }}>Reviewer Attribution</div>
                  <div className="attribution-prototype-note">
                    🔒 Authoritative governance identity derived from your authenticated account session.
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label>Reviewer Name</label>
                      <input
                        type="text"
                        value={user?.display_name || user?.username || reviewForm.reviewer_name}
                        disabled
                        style={{ opacity: 0.7, cursor: "not-allowed" }}
                        title="Attributed to your authenticated account session"
                      />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label>Reviewer Role</label>
                      <input
                        type="text"
                        value={user?.role || reviewForm.reviewer_role}
                        disabled
                        style={{ opacity: 0.7, cursor: "not-allowed" }}
                        title="Attributed to your authenticated account session"
                      />
                    </div>
                  </div>
                </div>

                {/* Review Decision */}
                <div className="form-group" style={{ marginTop: "16px" }}>
                  <label>Review Decision *</label>
                  <select
                    value={reviewForm.decision}
                    onChange={(e) => setReviewForm({ ...reviewForm, decision: e.target.value })}
                  >
                    <option value="APPROVED">APPROVED — Formally accept/sign-off on current risk posture</option>
                    <option value="REJECTED">REJECTED — Risk treatment or findings rejected</option>
                    <option value="CHANGES_REQUESTED">CHANGES_REQUESTED — Additional controls or adjustments required</option>
                  </select>
                </div>

                {/* Explanatory note */}
                <div className="form-independent-note">
                  ⚠ Treatment selection records your agreed response strategy independently of the approval decision. The backend validates both fields separately.
                </div>

                {/* Agreed Treatment */}
                <div className="form-group">
                  <label>Agreed Treatment Strategy *</label>
                  <select
                    value={reviewForm.agreed_treatment}
                    onChange={(e) => setReviewForm({ ...reviewForm, agreed_treatment: e.target.value })}
                  >
                    <option value="Mitigate">Mitigate (Deploy Controls)</option>
                    <option value="Accept">Accept (Document Business Acceptance)</option>
                    <option value="Transfer">Transfer (Insurance / Third-party)</option>
                    <option value="Avoid">Avoid (Decommission Service)</option>
                  </select>
                </div>

                {/* Mandatory Justification Comments */}
                <div className="form-group">
                  <label>Auditor Justification & Comments * (min 5 chars)</label>
                  <textarea
                    rows="3"
                    required
                    placeholder="Document the formal justification for this governance decision..."
                    value={reviewForm.comments}
                    onChange={(e) => setReviewForm({ ...reviewForm, comments: e.target.value })}
                  />
                </div>

                {/* AI Advisory Acknowledgement */}
                <div className="form-group">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={reviewForm.ai_analysis_acknowledged}
                      onChange={(e) => setReviewForm({ ...reviewForm, ai_analysis_acknowledged: e.target.checked })}
                    />
                    <span>
                      I acknowledge reviewing the AI security intelligence and confirm that this sign-off represents an authoritative human governance decision.
                    </span>
                  </label>
                </div>
              </div>
              <div className="modal-footer">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setReviewingRisk(null)}
                  disabled={submittingReview}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-primary"
                  disabled={submittingReview}
                >
                  {submittingReview ? "Submitting Sign-Off..." : "Submit Risk Review"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* -------------------------------- */}
      {/* MODAL: VIEW REVIEW HISTORY (PHASE 6C) */}
      {/* -------------------------------- */}
      {historyRisk && (
        <div className="modal-backdrop" onClick={() => setHistoryRisk(null)}>
          <div
            className="modal-content"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: "680px" }}
            role="dialog"
            aria-modal="true"
            aria-label={`Review History — #${historyRisk.id}`}
          >
            <div className="modal-header">
              <div>
                <h3>Review History — #{historyRisk.id}</h3>
                <div className="sub-text">{historyRisk.title}</div>
              </div>
              <button type="button" className="modal-close" onClick={() => setHistoryRisk(null)} aria-label="Close">×</button>
            </div>
            <div className="modal-body history-modal-body">
              {historyLoading ? (
                <div className="monitoring-loading-box">
                  <span className="ai-spinner" /> Loading review history...
                </div>
              ) : historyError ? (
                <div className="monitoring-error-box">
                  <div>⚠ {historyError}</div>
                  <button className="btn-secondary btn-sm" onClick={() => openReviewHistoryModal(historyRisk)}>
                    Retry
                  </button>
                </div>
              ) : historyData ? (
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
                    <div>
                      <span className="text-slate text-xs">Current Governance Status: </span>
                      {getReviewStatusBadge(historyData.review_status)}
                    </div>
                    {historyData.is_stale && (
                      <span className="badge badge-stale">Stale Baseline</span>
                    )}
                  </div>

                  {historyData.is_stale && historyData.stale_reasons && historyData.stale_reasons.length > 0 && (
                    <div className="stale-alert-box">
                      <strong>⚠ Current Review Invalidated (Stale):</strong>
                      <ul className="stale-reasons-list">
                        {historyData.stale_reasons.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {!historyData.history || historyData.history.length === 0 ? (
                    <div className="empty-cell" style={{ textAlign: "center", padding: "24px" }}>
                      No prior governance reviews recorded for this risk.
                    </div>
                  ) : (
                    historyData.history.map((rev) => (
                      <div key={rev.id} className="history-card">
                        <div className="history-card-header">
                          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                            <span className={`badge ${rev.decision === "APPROVED" ? "badge-approved" : rev.decision === "REJECTED" ? "badge-rejected" : "badge-changes-requested"}`}>
                              {rev.decision}
                            </span>
                            <span className="badge badge-treatment">
                              {rev.agreed_treatment}
                            </span>
                            {rev.is_current ? (
                              <span className="badge badge-low">Active</span>
                            ) : (
                              <span className="badge badge-neutral">Superseded</span>
                            )}
                            {rev.is_stale && (
                              <span className="badge badge-stale">Stale</span>
                            )}
                          </div>
                          <span className="text-xs text-slate">{formatDateTime(rev.created_at)}</span>
                        </div>

                        <div className="text-xs" style={{ color: "#94a3b8", marginBottom: "6px" }}>
                          Reviewer: <strong>{rev.reviewer_name}</strong> ({rev.reviewer_role})
                        </div>

                        {rev.stale_reasons && rev.stale_reasons.length > 0 && (
                          <div className="gov-stale-callout" style={{ marginTop: "6px", marginBottom: "8px" }}>
                            <span className="stale-callout-icon">⚠</span>
                            <div>
                              <strong>Stale Reasons:</strong> {rev.stale_reasons.join("; ")}
                            </div>
                          </div>
                        )}

                        <div className="history-comments">
                          "{rev.comments}"
                        </div>

                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <span className="text-xs text-slate">
                            {rev.ai_analysis_acknowledged ? "✓ AI Advisory Acknowledged" : "—"}
                          </span>
                          {rev.snapshot && (
                            <span className="history-snapshot">
                              Snapshot: Inherent {rev.snapshot.inherent_level || "—"} ({rev.snapshot.inherent_score || "—"}) • Residual {rev.snapshot.residual_level || "—"} ({rev.snapshot.residual_score || "—"})
                              {rev.snapshot.cvss_score != null ? ` • CVSS ${rev.snapshot.cvss_score}` : ""}
                            </span>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              ) : null}
            </div>
            <div className="modal-footer">
              <button type="button" className="btn-secondary" onClick={() => setHistoryRisk(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
      {/* ------------------------------------------------ */}
      {/* MODAL: AUDIT EVENT INSPECTOR & DIFF (PHASE 9)    */}
      {/* ------------------------------------------------ */}
      {viewingAuditLog && (
        <div className="modal-backdrop" onClick={() => setViewingAuditLog(null)}>
          <div
            className="modal-content modal-audit-inspector"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-label={`Audit Event Inspector — Event #${viewingAuditLog.id}`}
          >
            <div className="modal-header">
              <div>
                <h3>Audit Event Inspector — Event #{viewingAuditLog.id}</h3>
                <div className="sub-text">
                  Recorded {formatDateTime(viewingAuditLog.timestamp)} • Source: {viewingAuditLog.source}
                </div>
              </div>
              <button type="button" className="modal-close" onClick={() => setViewingAuditLog(null)} aria-label="Close">×</button>
            </div>

            <div className="modal-body" style={{ maxHeight: "calc(85vh - 140px)", overflowY: "auto" }}>
              {auditDetailLoading ? (
                <div className="monitoring-loading-box" style={{ padding: "30px 10px" }}>
                  <span className="ai-spinner" /> Loading complete canonical event record...
                </div>
              ) : auditDetailError ? (
                <div className="monitoring-error-box">
                  <div>⚠ {auditDetailError}</div>
                  <button className="btn-secondary btn-sm" onClick={() => openAuditDetailModal(viewingAuditLog)}>
                    Retry
                  </button>
                </div>
              ) : (
                <>
                  {/* Event Attributes */}
                  <div className="audit-meta-grid">
                    <div className="audit-meta-item">
                      <span className="audit-meta-label">Actor Attribution</span>
                      <div className="audit-meta-val font-semibold">{viewingAuditLog.actor || "—"}</div>
                    </div>
                    <div className="audit-meta-item">
                      <span className="audit-meta-label">Client / Source IP</span>
                      <div className="audit-meta-val">
                        <span className="ip-pill">{viewingAuditLog.ip_address || "127.0.0.1"}</span>
                      </div>
                    </div>
                    <div className="audit-meta-item">
                      <span className="audit-meta-label">Execution Source</span>
                      <div className="audit-meta-val">{getAuditSourceBadge(viewingAuditLog.source)}</div>
                    </div>
                    <div className="audit-meta-item">
                      <span className="audit-meta-label">Action Classification</span>
                      <div className="audit-meta-val">{getAuditActionBadge(viewingAuditLog.action)}</div>
                    </div>
                    <div className="audit-meta-item">
                      <span className="audit-meta-label">Target Entity</span>
                      <div className="audit-meta-val">
                        <strong>{viewingAuditLog.entity_type || "—"}</strong>
                        {viewingAuditLog.entity_id != null && (
                          <span className="sub-text" style={{ marginLeft: "6px" }}>
                            (ID #{viewingAuditLog.entity_id})
                          </span>
                        )}
                        {viewingAuditLog.entity_name && (
                          <div className="sub-text">{viewingAuditLog.entity_name}</div>
                        )}
                      </div>
                    </div>
                    <div className="audit-meta-item">
                      <span className="audit-meta-label">UTC Timestamp</span>
                      <div className="audit-meta-val text-xs text-slate">
                        {viewingAuditLog.timestamp ? new Date(viewingAuditLog.timestamp).toUTCString() : "—"}
                      </div>
                    </div>
                  </div>

                  {/* Description */}
                  <div className="audit-desc-box">
                    <div className="desc-header">Event Description</div>
                    <div className="desc-text">{viewingAuditLog.description || "No descriptive summary provided."}</div>
                  </div>

                  {/* Tamper-Evident SHA-256 Hash */}
                  <div className="audit-hash-card">
                    <div className="audit-hash-header">
                      <span className="audit-hash-title">Tamper-Evident SHA-256 Digest</span>
                      {viewingAuditLog.integrity_hash && (
                        <button
                          type="button"
                          className="audit-hash-copy-btn"
                          onClick={() => copyIntegrityHash(viewingAuditLog.integrity_hash)}
                          title="Copy SHA-256 hash to clipboard"
                        >
                          {hashCopied ? "✓ Copied!" : "📋 Copy SHA-256"}
                        </button>
                      )}
                    </div>
                    <div className="audit-hash-code-full">
                      {viewingAuditLog.integrity_hash || "No integrity hash recorded for this entry."}
                    </div>
                    <p className="audit-hash-explainer">
                      Deterministic SHA-256 digest computed over canonical immutable event fields (timestamp, source, actor, action, entity, IP, and state values) upon record creation. Audit log is append-only via application API constraints.
                    </p>
                  </div>

                  {/* State Diff / Changes */}
                  <div className="audit-diff-section">
                    <div className="audit-diff-section-title">Recorded State Mutation (Delta)</div>
                    {viewingAuditLog.old_values || viewingAuditLog.new_values ? (
                      <div className="audit-diff-content">
                        {viewingAuditLog.old_values ? (
                          <div className="diff-col">
                            <div className="diff-col-header">Previous State (Pre-Change)</div>
                            <pre className="diff-json">
                              {typeof viewingAuditLog.old_values === "object"
                                ? JSON.stringify(viewingAuditLog.old_values, null, 2)
                                : String(viewingAuditLog.old_values)}
                            </pre>
                          </div>
                        ) : (
                          <div className="diff-col" style={{ opacity: 0.6 }}>
                            <div className="diff-col-header">Previous State</div>
                            <div className="sub-text" style={{ padding: "8px 0" }}>None (Entity creation event)</div>
                          </div>
                        )}
                        {viewingAuditLog.new_values ? (
                          <div className="diff-col">
                            <div className="diff-col-header">Updated State (Post-Change)</div>
                            <pre className="diff-json">
                              {typeof viewingAuditLog.new_values === "object"
                                ? JSON.stringify(viewingAuditLog.new_values, null, 2)
                                : String(viewingAuditLog.new_values)}
                            </pre>
                          </div>
                        ) : (
                          <div className="diff-col" style={{ opacity: 0.6 }}>
                            <div className="diff-col-header">Updated State</div>
                            <div className="sub-text" style={{ padding: "8px 0" }}>None (Entity deletion event)</div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="audit-no-diff-box">
                        No state mutation recorded for this event (informational or read-only event).
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>

            <div className="modal-footer">
              <button type="button" className="btn-secondary" onClick={() => setViewingAuditLog(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------ */}
      {/* GLOBAL AI COPILOT SLIDE-OVER DRAWER (PHASE 11)   */}
      {/* ------------------------------------------------ */}
      {showCopilotDrawer && (() => {
        const activeRisk =
          risks.find((r) => r.id === copilotSelectedRiskId) ||
          (risks.length > 0 ? risks[0] : null);

        const activeRiskId = activeRisk?.id;
        const currentAnalysis = activeRiskId ? aiAnalysis[activeRiskId] : null;
        const isLoading = activeRiskId ? Boolean(aiLoading[activeRiskId]) : false;
        const currentError = activeRiskId ? aiError[activeRiskId] : null;

        const confidencePct = currentAnalysis ? Math.round((currentAnalysis.confidence || 0) * 100) : 0;
        const confClass = confidencePct >= 75 ? "high" : confidencePct >= 50 ? "med" : "low";

        const priorityBadgeClass = (p) => {
          switch ((p || "").toLowerCase()) {
            case "critical": return "badge-critical";
            case "high": return "badge-high";
            case "medium": return "badge-medium";
            case "low": return "badge-low";
            default: return "badge-neutral";
          }
        };

        const activeOperatorName = reviewForm.reviewer_name.trim() || "Security Analyst";

        return (
          <div className="copilot-drawer-backdrop" onClick={() => setShowCopilotDrawer(false)}>
            <aside
              className="copilot-drawer"
              onClick={(e) => e.stopPropagation()}
              role="dialog"
              aria-modal="true"
              aria-label="AI Security and GRC Copilot"
            >
              {/* Drawer Header */}
              <div className="copilot-drawer-header">
                <div className="copilot-header-brand">
                  <div className="copilot-icon-badge">✦</div>
                  <div>
                    <h2 className="copilot-title">AI Security & GRC Copilot</h2>
                    <p className="copilot-sub">
                      On-demand risk intelligence, dual-audience explanations, and 3-tier remediation
                    </p>
                  </div>
                </div>
                <div className="copilot-header-actions">
                  <div className="copilot-header-meta">
                    <span className="copilot-advisory-pill">Advisory Only</span>
                    <span className="copilot-operator-tag" title="Operator attributed in analysis audit logs">
                      Operator: {activeOperatorName}
                    </span>
                  </div>
                  <button
                    type="button"
                    className="copilot-close-btn"
                    onClick={() => setShowCopilotDrawer(false)}
                    title="Close Copilot drawer (Escape)"
                    aria-label="Close"
                  >
                    ✕
                  </button>
                </div>
              </div>

              {/* Drawer Body */}
              <div className="copilot-drawer-body">
                {/* 1. Finding Selector Section */}
                <div className="copilot-section-card">
                  <div className="copilot-card-label">SELECTED RISK FINDING CONTEXT</div>
                  {risks.length === 0 ? (
                    <div className="copilot-empty-note">
                      No risks registered yet. Discover hosts or add risks in Risk Management to analyze with AI.
                    </div>
                  ) : (
                    <>
                      <select
                        className="copilot-risk-select"
                        value={activeRiskId || ""}
                        onChange={(e) => {
                          const id = Number(e.target.value);
                          setCopilotSelectedRiskId(id);
                        }}
                      >
                        {risks.map((r) => (
                          <option key={r.id} value={r.id}>
                            Risk #{r.id}: {r.title} ({r.asset ? r.asset.ip_address : "Unassigned"}) [{r.residual_risk_level || r.risk_level || "Medium"}]
                          </option>
                        ))}
                      </select>

                      {activeRisk && (
                        <div className="copilot-risk-meta-grid">
                          <div className="copilot-meta-item">
                            <span className="meta-k">Host Asset:</span>
                            <span className="meta-v font-mono">{activeRisk.asset?.ip_address || "Unassigned"}</span>
                          </div>
                          <div className="copilot-meta-item">
                            <span className="meta-k">Inherent Risk:</span>
                            <span className="meta-v">{activeRisk.inherent_risk_level || activeRisk.risk_level || "Medium"} ({activeRisk.inherent_risk_score || activeRisk.risk_score || "—"})</span>
                          </div>
                          <div className="copilot-meta-item">
                            <span className="meta-k">Residual Risk:</span>
                            <span className="meta-v">{activeRisk.residual_risk_level || "—"} ({activeRisk.residual_risk_score || "—"})</span>
                          </div>
                          <div className="copilot-meta-item">
                            <span className="meta-k">Treatment:</span>
                            <span className="meta-v">{activeRisk.treatment || "Mitigate"}</span>
                          </div>
                          <div className="copilot-meta-item">
                            <span className="meta-k">Status:</span>
                            <span className="meta-v">{activeRisk.status || "Open"}</span>
                          </div>
                          <div className="copilot-meta-item">
                            <span className="meta-k">Governance Review:</span>
                            <span className="meta-v">{activeRisk.review_status || "Pending Review"}</span>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>

                {/* 2. Analysis Actions & Focus Chips */}
                {activeRisk && (
                  <div className="copilot-actions-bar">
                    {!currentAnalysis && !isLoading ? (
                      <button
                        type="button"
                        className="btn-primary copilot-primary-btn"
                        onClick={() => handleAnalyzeRisk(activeRisk.id, true)}
                      >
                        ✦ Run AI Intelligence Analysis
                      </button>
                    ) : (
                      <div className="copilot-controls-row">
                        <div className="copilot-focus-chips">
                          <span className="copilot-chips-label">Focus View:</span>
                          <button
                            type="button"
                            className={`copilot-chip ${copilotActiveSection === "all" ? "active" : ""}`}
                            onClick={() => setCopilotActiveSection("all")}
                          >
                            All Insights
                          </button>
                          <button
                            type="button"
                            className={`copilot-chip ${copilotActiveSection === "remediation" ? "active" : ""}`}
                            onClick={() => setCopilotActiveSection("remediation")}
                          >
                            3-Tier Remediation
                          </button>
                          <button
                            type="button"
                            className={`copilot-chip ${copilotActiveSection === "controls" ? "active" : ""}`}
                            onClick={() => setCopilotActiveSection("controls")}
                          >
                            Catalog Controls
                          </button>
                          <button
                            type="button"
                            className={`copilot-chip ${copilotActiveSection === "impact" ? "active" : ""}`}
                            onClick={() => setCopilotActiveSection("impact")}
                          >
                            Root Cause & Impact
                          </button>
                        </div>
                        <button
                          type="button"
                          className="btn-secondary copilot-reanalyze-btn"
                          disabled={isLoading}
                          onClick={() => handleReanalyzeRisk(activeRisk.id)}
                          title="Trigger fresh AI analysis from backend"
                        >
                          ↺ Re-analyze
                        </button>
                      </div>
                    )}
                  </div>
                )}

                {/* 3. Status States: Loading, Error, Content, Empty */}
                {isLoading && (
                  <div className="copilot-state-card copilot-loading-card">
                    <span className="copilot-spinner" />
                    <div className="copilot-state-content">
                      <div className="copilot-state-title">
                        Synthesizing Security Intelligence...
                      </div>
                      <p className="copilot-state-desc">
                        Invoking the configured backend AI provider chain for Risk #{activeRiskId}. Evaluating normalized host context, CVE correlations, and catalog controls.
                      </p>
                    </div>
                  </div>
                )}

                {currentError && !isLoading && (
                  <div className="copilot-state-card copilot-error-card">
                    <span className="copilot-error-icon">⚠</span>
                    <div className="copilot-state-content">
                      <div className="copilot-state-title">Analysis Failed</div>
                      <p className="copilot-state-desc">{currentError}</p>
                      <button
                        type="button"
                        className="btn-secondary btn-sm"
                        onClick={() => handleAnalyzeRisk(activeRiskId, true)}
                        style={{ marginTop: "10px" }}
                      >
                        Retry Analysis
                      </button>
                    </div>
                  </div>
                )}

                {!isLoading && !currentError && !currentAnalysis && activeRisk && (
                  <div className="copilot-state-card copilot-empty-card">
                    <div className="copilot-empty-icon">✦</div>
                    <div className="copilot-state-title">No Prior Analysis for Risk #{activeRiskId}</div>
                    <p className="copilot-state-desc">
                      The backend evaluates this security finding against configured LLMs (Gemini / OpenAI / Groq) with deterministic local rule fallback, generating plain-language explanations, business consequences, and a 3-tier remediation plan.
                    </p>
                    <button
                      type="button"
                      className="btn-primary"
                      onClick={() => handleAnalyzeRisk(activeRiskId, true)}
                      style={{ marginTop: "12px" }}
                    >
                      ✦ Analyze Risk #{activeRiskId} Now
                    </button>
                  </div>
                )}

                {!isLoading && !currentError && currentAnalysis && (
                  <div className="copilot-result-container">
                    {/* Model, Priority & Confidence Header */}
                    <div className="copilot-result-header">
                      <div className="copilot-res-left">
                        <span className={`badge ${priorityBadgeClass(currentAnalysis.priority)}`}>
                          AI Priority: {currentAnalysis.priority}
                        </span>
                        <span className="copilot-model-pill" title="Actual provider/model reported in backend response">
                          Engine: {currentAnalysis.model_name}
                        </span>
                        {currentAnalysis.created_at && (
                          <span className="copilot-time-pill">
                            Generated: {formatDateTime(currentAnalysis.created_at)}
                          </span>
                        )}
                      </div>
                      <div className="copilot-res-right">
                        <span className="copilot-conf-label">Confidence:</span>
                        <div className="copilot-confidence-bar">
                          <div
                            className={`copilot-confidence-fill conf-${confClass}`}
                            style={{ width: `${confidencePct}%` }}
                          />
                        </div>
                        <span className={`copilot-conf-pct conf-${confClass}`}>{confidencePct}%</span>
                      </div>
                    </div>

                    {/* Human Review Warning if triggered */}
                    {currentAnalysis.human_review_required && (
                      <div className="copilot-review-warning">
                        <div className="warning-title">
                          ⚠ Human Review Recommended — Validate before making governance or operational decisions
                        </div>
                        {currentAnalysis.human_review_reasons && currentAnalysis.human_review_reasons.length > 0 && (
                          <ul className="warning-reasons">
                            {currentAnalysis.human_review_reasons.map((reason, idx) => (
                              <li key={idx}>{reason}</li>
                            ))}
                          </ul>
                        )}
                      </div>
                    )}

                    {/* Executive Summary */}
                    {(copilotActiveSection === "all" || copilotActiveSection === "impact") && currentAnalysis.simple_explanation && (
                      <div className="copilot-insight-box">
                        <div className="insight-title">Executive Security Intelligence Summary</div>
                        <p className="insight-body">{currentAnalysis.simple_explanation}</p>
                      </div>
                    )}

                    {/* Why It Matters & Technical Severity */}
                    {(copilotActiveSection === "all" || copilotActiveSection === "impact") && (
                      <div className="copilot-two-col">
                        {currentAnalysis.why_it_matters && (
                          <div className="copilot-mini-card">
                            <div className="mini-card-title">Why It Matters</div>
                            <div className="mini-card-text">{currentAnalysis.why_it_matters}</div>
                          </div>
                        )}
                        {currentAnalysis.severity_explanation && (
                          <div className="copilot-mini-card">
                            <div className="mini-card-title">Technical Severity Assessment</div>
                            <div className="mini-card-text">{currentAnalysis.severity_explanation}</div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Risk Factors & Potential Impact */}
                    {(copilotActiveSection === "all" || copilotActiveSection === "impact") && (
                      <>
                        {currentAnalysis.risk_factors && currentAnalysis.risk_factors.length > 0 && (
                          <div className="copilot-insight-box">
                            <div className="insight-title">Identified Risk Factors</div>
                            <div className="copilot-chips-wrap">
                              {currentAnalysis.risk_factors.map((rf, idx) => (
                                <span key={idx} className="copilot-factor-chip">{rf}</span>
                              ))}
                            </div>
                          </div>
                        )}

                        {currentAnalysis.potential_business_impact && currentAnalysis.potential_business_impact.length > 0 && (
                          <div className="copilot-insight-box">
                            <div className="insight-title">Potential Business Consequences</div>
                            <ul className="copilot-bullet-list">
                              {currentAnalysis.potential_business_impact.map((imp, idx) => (
                                <li key={idx}>{imp}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </>
                    )}

                    {/* 3-Tier Remediation Steps */}
                    {(copilotActiveSection === "all" || copilotActiveSection === "remediation") && currentAnalysis.remediation && (
                      <div className="copilot-remediation-section">
                        <div className="insight-title">3-Tier Structured Remediation Plan</div>
                        <div className="copilot-remediation-grid">
                          {currentAnalysis.remediation.immediate_mitigation && currentAnalysis.remediation.immediate_mitigation.length > 0 && (
                            <div className="copilot-tier-box tier-immediate">
                              <div className="tier-header">🔴 Tier 1: Immediate Mitigation</div>
                              <ul className="copilot-bullet-list">
                                {currentAnalysis.remediation.immediate_mitigation.map((m, idx) => (
                                  <li key={idx}>{m}</li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {currentAnalysis.remediation.permanent_remediation && currentAnalysis.remediation.permanent_remediation.length > 0 && (
                            <div className="copilot-tier-box tier-permanent">
                              <div className="tier-header">🔵 Tier 2: Permanent Remediation</div>
                              <ul className="copilot-bullet-list">
                                {currentAnalysis.remediation.permanent_remediation.map((p, idx) => (
                                  <li key={idx}>{p}</li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {currentAnalysis.remediation.validation && currentAnalysis.remediation.validation.length > 0 && (
                            <div className="copilot-tier-box tier-validation">
                              <div className="tier-header">✅ Tier 3: Validation & Verification</div>
                              <ul className="copilot-bullet-list">
                                {currentAnalysis.remediation.validation.map((v, idx) => (
                                  <li key={idx}>{v}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Recommended Platform Controls */}
                    {(copilotActiveSection === "all" || copilotActiveSection === "controls") && currentAnalysis.recommended_controls && currentAnalysis.recommended_controls.length > 0 && (
                      <div className="copilot-insight-box">
                        <div className="insight-title">Recommended Platform Safeguards (from Catalog)</div>
                        <div className="copilot-rec-controls-list">
                          {currentAnalysis.recommended_controls.map((ctrl, idx) => (
                            <div key={idx} className="copilot-rec-control-card">
                              <div className="ctrl-name">{ctrl.name}</div>
                              <div className="ctrl-reason">{ctrl.reason}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* General Recommendations */}
                    {(copilotActiveSection === "all" || copilotActiveSection === "controls") && currentAnalysis.recommendation && currentAnalysis.recommendation.length > 0 && (
                      <div className="copilot-insight-box">
                        <div className="insight-title">Actionable Recommendations</div>
                        <ul className="copilot-bullet-list">
                          {currentAnalysis.recommendation.map((rec, idx) => (
                            <li key={idx}>{rec}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* AI Advisory Disclaimer */}
                    <div className="copilot-advisory-disclaimer">
                      <span className="disclaimer-icon">ℹ️</span>
                      <div className="disclaimer-text">
                        <strong>AI Advisory Decision Support Only:</strong> This output is supplementary intelligence to assist human decision makers. It does not modify authoritative GRC risk scores. Official likelihood, impact, treatments, and statuses remain strictly governed by the rule-based risk engine.
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Drawer Footer */}
              <div className="copilot-drawer-footer">
                <div className="copilot-footer-status">
                  <span className="copilot-live-dot" />
                  <span>AI GRC Copilot Active</span>
                </div>
                <div className="copilot-footer-actions">
                  {activeRisk && (
                    <button
                      type="button"
                      className="btn-secondary btn-sm"
                      onClick={() => {
                        setShowCopilotDrawer(false);
                        setActivePage("risk-management");
                        setRiskSubTab("register");
                      }}
                    >
                      View in Risk Register ➔
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn-secondary btn-sm"
                    onClick={() => setShowCopilotDrawer(false)}
                  >
                    Close
                  </button>
                </div>
              </div>
            </aside>
          </div>
        );
      })()}
    </div>
  );
}

function AppShell() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <AuthLoadingScreen />;
  }

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  return <AuthenticatedDashboard />;
}

function App() {
  return (
    <AuthProvider>
      <AppShell />
    </AuthProvider>
  );
}

export default App;
