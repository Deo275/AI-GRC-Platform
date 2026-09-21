import { useEffect, useState } from "react";
import "./App.css";

function App() {

  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [target, setTarget] = useState("192.168.127.1");

  const [assets, setAssets] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);

  // ----------------------------------------
  // Fetch Asset Inventory
  // ----------------------------------------

  const fetchAssets = async () => {

    try {

      const response = await fetch(
        "http://127.0.0.1:8000/assets"
      );

      const data = await response.json();

      setAssets(data.assets);

    } catch {

      console.error("Unable to fetch asset inventory.");

    }
  };

  const fetchVulnerabilities = async () => {
    try {
      const response = await fetch(
        "http://127.0.0.1:8000/vulnerabilities"
      );

      const data = await response.json();

      setVulnerabilities(data.vulnerabilities);
    } catch {
      console.error(
        "Unable to fetch vulnerability findings."
      );
    }
  };

  // Fetch assets when dashboard loads
  useEffect(() => {

    const loadAssets = async () => {

      try {

        const response = await fetch(
          "http://127.0.0.1:8000/assets"
        );

        const data = await response.json();

        setAssets(data.assets);

        try {
          const response = await fetch(
            "http://127.0.0.1:8000/vulnerabilities"
          );

          const data = await response.json();

          setVulnerabilities(data.vulnerabilities);
        } catch {
          console.error(
            "Unable to fetch vulnerability findings."
          );
        }

      } catch {

        console.error("Unable to fetch asset inventory.");

      }

    };

    loadAssets();

  }, []);


  // ----------------------------------------
  // Run Single Asset Scan
  // ----------------------------------------

  const runScan = async () => {

    setScanning(true);

    try {

      const response = await fetch(
        `http://127.0.0.1:8000/scan?target=${encodeURIComponent(target)}`,
        {
          method: "POST",
        }
      );

      const data = await response.json();

      setResult(data);

      // Refresh asset inventory
      fetchAssets();
      fetchVulnerabilities();

    } catch {

      alert("Backend is not running. Please start FastAPI.");

    }

    setScanning(false);
  };


  return (

    <div className="dashboard">

      {/* -------------------------------- */}
      {/* HEADER */}
      {/* -------------------------------- */}

      <header>

        <div>

          <h1>AI-GRC Platform</h1>

          <p>
            Cybersecurity Governance, Risk Management & Compliance
          </p>

        </div>

        <div className="status">
          ● System Online
        </div>

      </header>


      {/* -------------------------------- */}
      {/* SUMMARY CARDS */}
      {/* -------------------------------- */}

      <section className="cards">

        <div className="card">

          <h3>Monitored Assets</h3>

          <strong>
            {assets.length}
          </strong>

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
            {vulnerabilities.length}
          </strong>

        </div>

      </section>


      {/* -------------------------------- */}
      {/* NETWORK MONITORING */}
      {/* -------------------------------- */}

      <section className="scan-section">

        <h2>Network Monitoring</h2>

        <p>
          Enter a target IP address and evaluate its security risk.
        </p>


        <div className="scan-controls">

          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Enter target IP"
          />


          <button
            onClick={runScan}
            disabled={scanning}
          >

            {scanning
              ? "Scanning..."
              : "Run Network Scan"}

          </button>

        </div>

      </section>


      {/* -------------------------------- */}
      {/* ASSET INVENTORY */}
      {/* -------------------------------- */}

      <section className="results">

        <h2>Asset Inventory</h2>

        <p>
          Discovered assets monitored by the GRC platform.
        </p>


        <div className="asset-table-container">

          <table className="asset-table">

            <thead>

              <tr>

                <th>IP Address</th>
                <th>Hostname</th>
                <th>Operating System</th>
                <th>Open Ports</th>
                <th>Risk Score</th>
                <th>Risk Level</th>
                <th>Status</th>

              </tr>

            </thead>


            <tbody>

              {assets.length === 0 ? (

                <tr>

                  <td colSpan="7">
                    No assets discovered yet.
                  </td>

                </tr>

              ) : (

                assets.map((asset) => (

                  <tr key={asset.id}>

                    <td>
                      {asset.ip_address}
                    </td>

                    <td>
                      {asset.hostname || "Unknown"}
                    </td>

                    <td>
                      {asset.operating_system || "Unknown"}
                    </td>

                    <td>
                      {asset.open_ports || "None"}
                    </td>

                    <td>
                      {asset.risk_score}
                    </td>

                    <td>

                      <span
                        className={
                          asset.risk_level === "Critical"
                            ? "risk-critical"
                            : asset.risk_level === "High"
                            ? "risk-high"
                            : asset.risk_level === "Medium"
                            ? "risk-medium"
                            : "risk-low"
                        }
                      >
                        {asset.risk_level}
                      </span>

                    </td>

                    <td>
                      {asset.status}
                    </td>

                  </tr>

                ))

              )}

            </tbody>

          </table>

        </div>

      </section>


      {/* -------------------------------- */}
      {/* SCAN RESULTS */}
      {/* -------------------------------- */}

      <section className="results">
        <h2>Vulnerability Findings</h2>

        <p>
          Security exposures identified during network scanning.
        </p>

        <div className="asset-table-container">
          <table className="asset-table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Finding</th>
                <th>Severity</th>
                <th>CVE</th>
                <th>CVSS</th>
                <th>Status</th>
              </tr>
            </thead>

            <tbody>
              {vulnerabilities.length === 0 ? (
                <tr>
                  <td colSpan="7">
                    No vulnerability findings yet.
                  </td>
                </tr>
              ) : (
                vulnerabilities.map((vulnerability) => (
                  <tr key={vulnerability.id}>
                    <td>{vulnerability.port}</td>

                    <td>
                      {vulnerability.service}
                    </td>

                    <td>
                      {vulnerability.title}
                    </td>

                    <td>
                      <span
                        className={
                          vulnerability.severity === "High"
                            ? "risk-high"
                            : vulnerability.severity === "Medium"
                            ? "risk-medium"
                            : "risk-low"
                        }
                      >
                        {vulnerability.severity}
                      </span>
                    </td>

                    <td>
                      {vulnerability.cve || "Not identified"}
                    </td>

                    <td>
                      {vulnerability.cvss_score ?? "N/A"}
                    </td>

                    <td>
                      {vulnerability.status}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {result && (

        <section className="results">

          <h2>Scan Results</h2>


          <div className="asset-info">

            <p>
              <b>IP Address:</b> {result.ip_address}
            </p>

            <p>
              <b>Risk Score:</b> {result.risk_score}
            </p>

            <p>
              <b>Risk Level:</b> {result.risk_level}
            </p>

            <p>
              <b>Open Ports:</b> {result.open_ports}
            </p>

          </div>


          <h3>Security Findings</h3>


          <ul>

            {result.findings.map(
              (finding, index) => (

                <li key={index}>
                  {finding}
                </li>

              )
            )}

          </ul>

        </section>

      )}

    </div>
  );
}

export default App;