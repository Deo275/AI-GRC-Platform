import { useState } from "react";
import "./App.css";

function App() {
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);

  const runScan = async () => {
    setScanning(true);

    try {
      const response = await fetch("http://127.0.0.1:8000/scan", {
        method: "POST",
      });

      const data = await response.json();
      setResult(data);
    } catch {
      alert("Backend is not running. Please start FastAPI.");
    }

    setScanning(false);
  };

  return (
    <div className="dashboard">

      <header>
        <div>
          <h1>AI-GRC Platform</h1>
          <p>Cybersecurity Governance, Risk Management & Compliance</p>
        </div>

        <div className="status">
          ● System Online
        </div>
      </header>

      <section className="cards">

        <div className="card">
          <h3>Monitored Assets</h3>
          <strong>{result ? "1" : "0"}</strong>
        </div>

        <div className="card">
          <h3>Risk Score</h3>
          <strong className="risk">
            {result ? result.risk_score : "--"}
          </strong>
        </div>

        <div className="card">
          <h3>Risk Level</h3>
          <strong className="critical">
            {result ? result.risk_level : "--"}
          </strong>
        </div>

        <div className="card">
          <h3>Findings</h3>
          <strong>
            {result ? result.findings.length : "0"}
          </strong>
        </div>

      </section>

      <section className="scan-section">

        <h2>Network Monitoring</h2>

        <p>
          Scan the configured network asset and evaluate its security risk.
        </p>

        <button onClick={runScan} disabled={scanning}>
          {scanning ? "Scanning..." : "Run Network Scan"}
        </button>

      </section>

      {result && (
        <section className="results">

          <h2>Scan Results</h2>

          <div className="asset-info">
            <p><b>IP Address:</b> {result.ip_address}</p>

            <p><b>Risk Score:</b> {result.risk_score}</p>

            <p><b>Risk Level:</b> {result.risk_level}</p>

            <p><b>Open Ports:</b> {result.open_ports}</p>
          </div>

          <h3>Security Findings</h3>

          <ul>
            {result.findings.map((finding, index) => (
              <li key={index}>{finding}</li>
            ))}
          </ul>

        </section>
      )}

    </div>
  );
}

export default App;