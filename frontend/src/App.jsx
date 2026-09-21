import { useEffect, useState } from "react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000";

function App() {
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [target, setTarget] = useState("192.168.127.1");

  const [assets, setAssets] = useState([]);
  const [risks, setRisks] = useState([]);
  const [controls, setControls] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);

  // Phase 3: Compliance State
  const [frameworks, setFrameworks] = useState([]);
  const [selectedFramework, setSelectedFramework] = useState("NIST CSF");
  const [complianceSummary, setComplianceSummary] = useState([]);
  const [requirements, setRequirements] = useState([]);
  const [statusFilter, setStatusFilter] = useState("All");
  const [functionFilter, setFunctionFilter] = useState("All");

  // Modals state
  const [editingAsset, setEditingAsset] = useState(null);
  const [editingRisk, setEditingRisk] = useState(null);
  const [showAddControlModal, setShowAddControlModal] = useState(false);
  const [assigningRiskId, setAssigningRiskId] = useState(null);
  const [editingRequirement, setEditingRequirement] = useState(null);

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
  // Data Fetching Functions
  // ----------------------------------------

  const fetchAssets = async () => {
    try {
      const response = await fetch(`${API_BASE}/assets`);
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
      const response = await fetch(`${API_BASE}/risks`);
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
      const response = await fetch(`${API_BASE}/controls`);
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
      const response = await fetch(`${API_BASE}/vulnerabilities`);
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
      const response = await fetch(`${API_BASE}/compliance/frameworks`);
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
      const response = await fetch(`${API_BASE}/compliance/summary`);
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
      const response = await fetch(`${API_BASE}/compliance/requirements`);
      if (response.ok) {
        const data = await response.json();
        setRequirements(data.requirements || []);
      }
    } catch (error) {
      console.error("Unable to fetch compliance requirements:", error);
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
      fetchComplianceRequirements()
    ]);
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refreshAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ----------------------------------------
  // Network Scanning
  // ----------------------------------------

  const runScan = async () => {
    setScanning(true);
    try {
      const response = await fetch(
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
      const response = await fetch(`${API_BASE}/assets/${editingAsset.id}`, {
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

      const response = await fetch(`${API_BASE}/risks/${editingRisk.id}`, {
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
      const response = await fetch(`${API_BASE}/risks/${riskId}/controls/${selectedControlId}`, {
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
      const response = await fetch(`${API_BASE}/risks/${riskId}/controls/${controlId}`, {
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
      const response = await fetch(`${API_BASE}/controls`, {
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
      const response = await fetch(`${API_BASE}/compliance/requirements/${editingRequirement.id}`, {
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
  // Helper classes & formatters
  // ----------------------------------------

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

  // Filter active requirements for the Compliance table
  const currentFwRequirements = requirements.filter(r => r.framework_name === selectedFramework);

  const availableFunctions = ["All", ...Array.from(new Set(currentFwRequirements.map(r => r.function).filter(Boolean)))];

  const filteredRequirements = currentFwRequirements.filter(r => {
    const matchesStatus = statusFilter === "All" || r.status === statusFilter;
    const matchesFunction = functionFilter === "All" || r.function === functionFilter;
    return matchesStatus && matchesFunction;
  });

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

  return (
    <div className="dashboard">
      {/* -------------------------------- */}
      {/* HEADER */}
      {/* -------------------------------- */}
      <header>
        <div>
          <div className="brand-badge">PHASE 3 ACTIVE • NIST CSF 2.0 & ISO/IEC 27001:2022</div>
          <h1>AI-GRC Platform</h1>
          <p>
            Automated Governance, Risk Management & Compliance with Inherent/Residual Risk Modeling and Authoritative Framework Mapping
          </p>
        </div>
        <div className="system-status">
          <span className="pulse-dot"></span> System Online
        </div>
      </header>

      {/* -------------------------------- */}
      {/* SUMMARY CARDS */}
      {/* -------------------------------- */}
      <section className="cards cards-five">
        <div className="card">
          <div className="card-label">Monitored Assets</div>
          <div className="card-val">{assets.length}</div>
          <div className="card-sub">Infrastructure inventory</div>
        </div>

        <div className="card">
          <div className="card-label">Registered Risks</div>
          <div className="card-val">{risks.length}</div>
          <div className="card-sub">
            {risks.filter(r => r.status === "Open").length} Open • {risks.filter(r => r.status === "Resolved").length} Resolved
          </div>
        </div>

        <div className="card">
          <div className="card-label">Security Controls</div>
          <div className="card-val highlight-blue">{controls.length}</div>
          <div className="card-sub">
            {controls.filter(c => c.status === "Implemented").length} Implemented Controls
          </div>
        </div>

        <div className="card">
          <div className="card-label">Implementation Coverage</div>
          <div className="card-val highlight-green">{activeSummary.implementation_coverage}%</div>
          <div className="card-sub">{selectedFramework} (Internal metric)</div>
        </div>

        <div className="card">
          <div className="card-label">Vulnerability Findings</div>
          <div className="card-val highlight-orange">{vulnerabilities.length}</div>
          <div className="card-sub">Identified technical findings</div>
        </div>
      </section>

      {/* -------------------------------- */}
      {/* NETWORK SCANNER */}
      {/* -------------------------------- */}
      <section className="panel">
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

      {/* -------------------------------- */}
      {/* ASSET INVENTORY & INTELLIGENCE */}
      {/* -------------------------------- */}
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Asset Inventory & Intelligence</h2>
            <p className="panel-desc">
              Manage business context: criticality, exposure, and environment dynamically inform Inherent Risk.
            </p>
          </div>
        </div>

        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Hostname / OS</th>
                <th>Criticality</th>
                <th>Environment</th>
                <th>Exposure</th>
                <th>Owner / Function</th>
                <th>Risk Score</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {assets.length === 0 ? (
                <tr>
                  <td colSpan="8" className="empty-cell">No assets discovered yet.</td>
                </tr>
              ) : (
                assets.map((asset) => (
                  <tr key={asset.id}>
                    <td>
                      <strong className="ip-text">{asset.ip_address}</strong>
                      <div className="sub-text">ID #{asset.id}</div>
                    </td>
                    <td>
                      <div>{asset.hostname || "Unknown Host"}</div>
                      <div className="sub-text">{asset.operating_system || "OS not identified"}</div>
                    </td>
                    <td>
                      <span className={`badge ${getRiskClass(asset.criticality)}`}>
                        {asset.criticality || "Medium"}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-neutral">
                        {asset.environment || "Production"}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-exposure">
                        {asset.exposure || "Internal"}
                      </span>
                    </td>
                    <td>
                      <div>{asset.owner || <span className="text-muted">Unassigned</span>}</div>
                      <div className="sub-text">{asset.business_function || "No function specified"}</div>
                    </td>
                    <td>
                      <span className={`badge ${getRiskClass(asset.risk_level)}`}>
                        {asset.risk_level} ({asset.risk_score})
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn-action"
                        onClick={() => openAssetModal(asset)}
                        title="Edit Asset Intelligence"
                      >
                        Edit Intelligence
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* -------------------------------- */}
      {/* RISK REGISTER */}
      {/* -------------------------------- */}
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>GRC Risk Register</h2>
            <p className="panel-desc">
              Comprehensive risk tracking from Inherent Risk (Likelihood × Impact) to Residual Risk mitigated by Security Controls.
            </p>
          </div>
        </div>

        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Risk Finding</th>
                <th>Asset</th>
                <th>Inherent Risk</th>
                <th>Mitigating Controls</th>
                <th>Residual Risk</th>
                <th>Treatment</th>
                <th>Owner & Due Date</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {risks.length === 0 ? (
                <tr>
                  <td colSpan="9" className="empty-cell">No risks registered yet.</td>
                </tr>
              ) : (
                risks.map((risk) => {
                  const asset = assets.find(a => a.id === risk.asset_id);
                  return (
                    <tr key={risk.id}>
                      <td style={{ minWidth: "200px" }}>
                        <strong>{risk.title}</strong>
                        <div className="sub-text">{risk.recommendation || risk.description}</div>
                        <div className="framework-tag">{risk.compliance_framework} ({risk.compliance_control})</div>
                      </td>
                      <td>
                        <span className="ip-pill">{asset ? asset.ip_address : `Asset #${risk.asset_id}`}</span>
                      </td>
                      <td>
                        <span className={`badge ${getRiskClass(risk.inherent_risk_level)}`}>
                          {risk.inherent_risk_level || "Medium"} ({risk.inherent_risk_score || risk.risk_score})
                        </span>
                        <div className="sub-calc">
                          L: {risk.likelihood_score || 2} × I: {risk.impact_score || 2}
                        </div>
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
                                .filter(c => !risk.controls?.some(rc => rc.id === c.id))
                                .map((c) => (
                                  <option key={c.id} value={c.id}>
                                    {c.name} ({c.effectiveness} Eff)
                                  </option>
                                ))}
                            </select>
                            <div className="assign-actions">
                              <button
                                className="btn-mini btn-save"
                                onClick={() => handleAssignControl(risk.id)}
                                disabled={!selectedControlId}
                              >
                                Save
                              </button>
                              <button
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
                        <span className={`badge ${getRiskClass(risk.residual_risk_level)}`}>
                          {risk.residual_risk_level || "Medium"} ({risk.residual_risk_score || risk.risk_score})
                        </span>
                        <div className="sub-calc">
                          Res L: {risk.residual_likelihood || 2} × I: {risk.residual_impact || 2}
                        </div>
                      </td>
                      <td>
                        <span className="badge badge-treatment">
                          {risk.treatment || "Mitigate"}
                        </span>
                      </td>
                      <td>
                        <div>{risk.risk_owner || <span className="text-muted">Unassigned</span>}</div>
                        <div className="sub-text">
                          {risk.due_date ? new Date(risk.due_date).toLocaleDateString() : "No due date"}
                        </div>
                      </td>
                      <td>
                        <span className={`status-pill ${getStatusClass(risk.status)}`}>
                          {risk.status || "Open"}
                        </span>
                      </td>
                      <td>
                        <button
                          className="btn-action"
                          onClick={() => openRiskModal(risk)}
                          title="Manage Risk Treatment & Ownership"
                        >
                          Manage
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

      {/* -------------------------------- */}
      {/* SECURITY CONTROLS CATALOG */}
      {/* -------------------------------- */}
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Security Controls Catalog</h2>
            <p className="panel-desc">
              Available defensive safeguards. Implemented controls reduce risk likelihood based on their effectiveness rating.
            </p>
          </div>
          <button
            className="btn-primary"
            onClick={() => setShowAddControlModal(true)}
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

      {/* -------------------------------- */}
      {/* PHASE 3: COMPLIANCE MAPPING */}
      {/* -------------------------------- */}
      <section className="panel">
        <div className="panel-header">
          <div>
            <div className="section-tag">GOVERNANCE & COMPLIANCE (PHASE 3)</div>
            <h2>Compliance Framework Mapping</h2>
            <p className="panel-desc">
              Official control mappings for NIST CSF 2.0 and ISO/IEC 27001:2022 (reviewed supported subset).
            </p>
          </div>

          <div className="framework-tabs">
            {frameworks.map(fw => (
              <button
                key={fw.id}
                className={`tab-btn ${selectedFramework === fw.name ? "active" : ""}`}
                onClick={() => {
                  setSelectedFramework(fw.name);
                  setFunctionFilter("All");
                  setStatusFilter("All");
                }}
              >
                {fw.name} v{fw.version}
              </button>
            ))}
          </div>
        </div>

        {/* Coverage & Status Bar */}
        <div className="compliance-summary-grid">
          <div className="comp-stat-card">
            <div className="comp-stat-label">Implementation Coverage</div>
            <div className="comp-stat-val text-accent">{activeSummary.implementation_coverage}%</div>
            <div className="progress-bar-bg">
              <div className="progress-bar-fill" style={{ width: `${Math.min(100, activeSummary.implementation_coverage)}%` }}></div>
            </div>
            <div className="comp-stat-sub">Internal GRC tracking metric</div>
          </div>

          <div className="comp-stat-mini">
            <div className="mini-num text-green">{activeSummary.implemented}</div>
            <div className="mini-lbl">Implemented</div>
          </div>

          <div className="comp-stat-mini">
            <div className="mini-num text-yellow">{activeSummary.partially_implemented}</div>
            <div className="mini-lbl">Partially Impl.</div>
          </div>

          <div className="comp-stat-mini">
            <div className="mini-num text-red">{activeSummary.not_implemented}</div>
            <div className="mini-lbl">Not Impl.</div>
          </div>

          <div className="comp-stat-mini">
            <div className="mini-num text-slate">{activeSummary.not_assessed}</div>
            <div className="mini-lbl">Not Assessed</div>
          </div>

          <div className="comp-stat-mini">
            <div className="mini-num text-muted">{activeSummary.not_applicable}</div>
            <div className="mini-lbl">Not Applicable</div>
          </div>
        </div>

        <div className="disclaimer-banner">
          <span className="info-icon">ℹ️</span>
          <span>
            <strong>Note:</strong> Implementation Coverage is an internal GRC tracking metric for the reviewed supported subset of requirements and does not constitute formal certification or compliance.
          </span>
        </div>

        {/* Filter Controls */}
        <div className="table-filter-bar">
          <div className="filter-group">
            <label>Filter by Status:</label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="select-filter"
            >
              <option value="All">All Statuses ({currentFwRequirements.length})</option>
              <option value="Not Assessed">Not Assessed</option>
              <option value="Partially Implemented">Partially Implemented</option>
              <option value="Implemented">Implemented</option>
              <option value="Not Implemented">Not Implemented</option>
              <option value="Not Applicable">Not Applicable</option>
            </select>
          </div>

          <div className="filter-group">
            <label>Filter by Function / Theme:</label>
            <select
              value={functionFilter}
              onChange={(e) => setFunctionFilter(e.target.value)}
              className="select-filter"
            >
              {availableFunctions.map(fn => (
                <option key={fn} value={fn}>{fn}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Compliance Table */}
        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Requirement Code</th>
                <th>Title & Function</th>
                <th>Mapped Security Controls</th>
                <th>Status</th>
                <th>Auditor Notes</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredRequirements.length === 0 ? (
                <tr>
                  <td colSpan="6" className="empty-cell">No requirements match the selected filters.</td>
                </tr>
              ) : (
                filteredRequirements.map(req => (
                  <tr key={req.id}>
                    <td>
                      <span className="req-code-badge">{req.requirement_id}</span>
                      <div className="sub-text">{req.category}</div>
                    </td>
                    <td style={{ minWidth: "260px" }}>
                      <strong>{req.title}</strong>
                      <div className="sub-text desc-cell">{req.description}</div>
                      <span className="function-pill">{req.function}</span>
                    </td>
                    <td style={{ minWidth: "220px" }}>
                      {req.mapped_controls && req.mapped_controls.length > 0 ? (
                        <div className="controls-list">
                          {req.mapped_controls.map(mc => (
                            <span key={mc.id} className="control-chip">
                              {mc.name}
                              <span className={`strength-tag ${mc.mapping_strength === "Direct" ? "strength-direct" : "strength-sup"}`}>
                                {mc.mapping_strength}
                              </span>
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-muted text-xs">No controls mapped</span>
                      )}
                    </td>
                    <td>
                      <span className={`badge ${getComplianceStatusClass(req.status)}`}>
                        {req.status || "Not Assessed"}
                      </span>
                    </td>
                    <td className="desc-cell">
                      {req.notes ? req.notes : <span className="text-muted">No notes recorded</span>}
                    </td>
                    <td>
                      <button
                        className="btn-action"
                        onClick={() => openRequirementModal(req)}
                        title="Update Assessment Status"
                      >
                        Assess
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* -------------------------------- */}
      {/* VULNERABILITY FINDINGS (PHASE 1) */}
      {/* -------------------------------- */}
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Vulnerability Findings</h2>
            <p className="panel-desc">
              Technical security findings with CVE/NVD correlation and CVSS scores.
            </p>
          </div>
        </div>

        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Port / Service</th>
                <th>Finding Title</th>
                <th>Severity</th>
                <th>CVE Reference</th>
                <th>CVSS Score</th>
                <th>CVE Confidence</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {vulnerabilities.length === 0 ? (
                <tr>
                  <td colSpan="7" className="empty-cell">No vulnerability findings yet.</td>
                </tr>
              ) : (
                vulnerabilities.map((v) => (
                  <tr key={v.id}>
                    <td>
                      <strong>{v.port}</strong> / {v.service || "unknown"}
                    </td>
                    <td>{v.title}</td>
                    <td>
                      <span className={`badge ${getRiskClass(v.severity)}`}>
                        {v.severity}
                      </span>
                    </td>
                    <td>{v.cve || <span className="text-muted">Not identified</span>}</td>
                    <td>
                      {v.cvss_score != null ? (
                        <span className="cvss-tag">{v.cvss_score} ({v.cvss_version || "v3.1"})</span>
                      ) : (
                        <span className="text-muted">N/A</span>
                      )}
                    </td>
                    <td>
                      <span className={`conf-badge conf-${v.cve_confidence || "none"}`}>
                        {v.cve_confidence || "None"}
                      </span>
                    </td>
                    <td>
                      <span className={`status-pill ${getStatusClass(v.status)}`}>
                        {v.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* -------------------------------- */}
      {/* MODAL: EDIT ASSET INTELLIGENCE */}
      {/* -------------------------------- */}
      {editingAsset && (
        <div className="modal-backdrop" onClick={() => setEditingAsset(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Edit Asset Intelligence — {editingAsset.ip_address}</h3>
              <button className="modal-close" onClick={() => setEditingAsset(null)}>×</button>
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
              <button className="btn-secondary" onClick={() => setEditingAsset(null)}>Cancel</button>
              <button className="btn-primary" onClick={saveAsset}>Save & Recalculate Risks</button>
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------- */}
      {/* MODAL: MANAGE RISK */}
      {/* -------------------------------- */}
      {editingRisk && (
        <div className="modal-backdrop" onClick={() => setEditingRisk(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Manage Risk Treatment — #{editingRisk.id}</h3>
              <button className="modal-close" onClick={() => setEditingRisk(null)}>×</button>
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
              <button className="btn-secondary" onClick={() => setEditingRisk(null)}>Cancel</button>
              <button className="btn-primary" onClick={saveRisk}>Save Changes</button>
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------- */}
      {/* MODAL: ADD CONTROL */}
      {/* -------------------------------- */}
      {showAddControlModal && (
        <div className="modal-backdrop" onClick={() => setShowAddControlModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Add Security Control to Catalog</h3>
              <button className="modal-close" onClick={() => setShowAddControlModal(false)}>×</button>
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
              <button className="btn-secondary" onClick={() => setShowAddControlModal(false)}>Cancel</button>
              <button className="btn-primary" onClick={saveNewControl}>Add to Catalog</button>
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------- */}
      {/* MODAL: ASSESS COMPLIANCE REQUIREMENT (PHASE 3) */}
      {/* -------------------------------- */}
      {editingRequirement && (
        <div className="modal-backdrop" onClick={() => setEditingRequirement(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Assess Requirement — {editingRequirement.requirement_id}</h3>
              <button className="modal-close" onClick={() => setEditingRequirement(null)}>×</button>
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
              <button className="btn-secondary" onClick={() => setEditingRequirement(null)}>Cancel</button>
              <button className="btn-primary" onClick={saveRequirementAssessment}>Save Assessment</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;