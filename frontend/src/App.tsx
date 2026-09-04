import { useEffect, useState } from "react";
import "./App.css";

type IOC = {
  id: number;
  type: string;
  value: string;
  severity: string;
  confidence: number;
  source: string;
  created_at: string;
};

type IntelligenceResponse = {
  ioc: {
    id: number;
    type: string;
    value: string;
    severity: string;
    confidence: number;
  };
  risk: {
    score: number;
    level: string;
  };
  campaigns: {
    campaign_id: number;
    campaign_name: string;
    threat_actor: string | null;
    techniques: {
      technique_id: string;
      name: string;
      tactic: string;
    }[];
  }[];
};

function App() {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [selectedIOC, setSelectedIOC] =
    useState<IntelligenceResponse | null>(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [investigating, setInvestigating] = useState(false);

  useEffect(() => {
  const loadIOCs = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(
        "http://127.0.0.1:8000/iocs"
      );

      if (!response.ok) {
        throw new Error("Failed to load threat intelligence");
      }

      const data = await response.json();
      setIocs(data);
    } catch (error) {
      console.error(error);
      setError(
        "Unable to connect to the threat intelligence API."
      );
    } finally {
      setLoading(false);
    }
  };

  loadIOCs();
}, []);

  const loadIntelligence = async (iocId: number) => {
  try {
    setInvestigating(true);
    setError(null);

    const response = await fetch(
      `http://127.0.0.1:8000/iocs/${iocId}/intelligence`
    );

    if (!response.ok) {
      throw new Error("Failed to load IOC intelligence");
    }

    const data = await response.json();
    setSelectedIOC(data);
  } catch (error) {
    console.error(error);
    setError("Unable to load correlated intelligence.");
  } finally {
    setInvestigating(false);
  }
};

  const highRiskCount = iocs.filter(
    (ioc) =>
      ioc.severity === "high" ||
      ioc.severity === "critical"
  ).length;

  return (
    <main className="app">
      <header className="header">
        <div>
          <p className="eyebrow">SECURITY OPERATIONS</p>
          <h1>Threat Intelligence Dashboard</h1>
          <p className="subtitle">
            Monitor indicators, campaigns and adversary activity.
          </p>
        </div>
      </header>

      <section className="stats">
        <article className="stat-card">
          <span>Total IOCs</span>
          <strong>{iocs.length}</strong>
        </article>

        <article className="stat-card">
          <span>High Risk</span>
          <strong>{highRiskCount}</strong>
        </article>

        <article className="stat-card">
          <span>Platform</span>
          <strong>Online</strong>
        </article>
      </section>

      {loading && (
  <div className="status-message">
    Loading threat intelligence...
  </div>
)}

{error && (
  <div className="status-message error-message">
    {error}
  </div>
)}
      
      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">INDICATORS</p>
            <h2>Indicators of Compromise</h2>
          </div>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Source</th>
                <th></th>
              </tr>
            </thead>

            <tbody>
              {iocs.map((ioc) => (
                <tr key={ioc.id}>
                  <td className="indicator">{ioc.value}</td>
                  <td>{ioc.type}</td>
                  <td>
                    <span
                      className={`severity severity-${ioc.severity}`}
                    >
                      {ioc.severity}
                    </span>
                  </td>
                  <td>{ioc.confidence}%</td>
                  <td>{ioc.source}</td>
                  <td>
                    <button
                      onClick={() => loadIntelligence(ioc.id)}
                      disabled={investigating}
                    >
                      {investigating ? "Investigating..." : "Investigate"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {selectedIOC && (
        <section className="panel intelligence">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">CORRELATED INTELLIGENCE</p>
              <h2>{selectedIOC.ioc.value}</h2>
            </div>

            <div className="risk-score">
              <span>Risk Score</span>
              <strong>{selectedIOC.risk.score}</strong>
              <small>{selectedIOC.risk.level}</small>
            </div>
          </div>

          {selectedIOC.campaigns.length === 0 ? (
            <p>No correlated campaigns found.</p>
          ) : (
            selectedIOC.campaigns.map((campaign) => (
              <article
                className="campaign-card"
                key={campaign.campaign_id}
              >
                <div>
                  <span>Campaign</span>
                  <strong>{campaign.campaign_name}</strong>
                </div>

                <div>
                  <span>Threat Actor</span>
                  <strong>
                    {campaign.threat_actor ?? "Unknown"}
                  </strong>
                </div>

                <div className="techniques">
                  <span>MITRE ATT&CK Techniques</span>

                  {campaign.techniques.map((technique) => (
                    <div
                      className="technique"
                      key={technique.technique_id}
                    >
                      <strong>{technique.technique_id}</strong>
                      <span>{technique.name}</span>
                      <small>{technique.tactic}</small>
                    </div>
                  ))}
                </div>
              </article>
            ))
          )}
        </section>
      )}
    </main>
  );
}

export default App;