import React, { useEffect, useMemo, useState } from "react";
import { fetchRecords, createRecord } from "./api";

// Extract analysis data from backend response
function getAnalysisData(record) {
  if (!record) return null;
  
  // Backend returns analysis as object (not string)
  const analysis = record.analysis;
  
  if (!analysis || typeof analysis !== "object") {
    return null;
  }
  
  return {
    threatScore: analysis.threatScore ?? 0,
    threatLevel: analysis.threatLevel || "SAFE",
    detectedActions: analysis.detectedActions || [],
    detectedTargets: analysis.detectedTargets || [],
    mlPrediction: analysis.mlPrediction || "SAFE",
    mlConfidence: analysis.mlConfidence ?? 0,
    confidence: analysis.confidence || "low",
    explanation: analysis.explanation || "",
    detectionMethod: analysis.detectionMethod || "Keyword + Machine Learning",
  };
}

function App() {
  const [prompt, setPrompt] = useState("");
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(false);
  const [initialLoading, setInitialLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeRecordId, setActiveRecordId] = useState(null);
  const [filterLevel, setFilterLevel] = useState("ALL");
  const [showRawAnalysis, setShowRawAnalysis] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const data = await fetchRecords();
        // Backend may return analysis as string (from DB), parse if needed
        const parsedData = data.map(record => {
          if (record.analysis && typeof record.analysis === "string") {
            try {
              record.analysis = JSON.parse(record.analysis);
            } catch {
              record.analysis = null;
            }
          }
          return record;
        });
        setRecords(parsedData);
        if (parsedData.length > 0) {
          setActiveRecordId(parsedData[0].id);
        }
      } catch (err) {
        console.error(err);
        setError("Failed to load existing analyses from the backend.");
      } finally {
        setInitialLoading(false);
      }
    }

    load();
  }, []);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");

    const trimmed = prompt.trim();
    if (!trimmed) {
      setError("Please enter a prompt payload to analyze.");
      return;
    }

    setLoading(true);
    try {
      const response = await createRecord(trimmed);
      
      // Log backend response for debugging
      console.log("Backend analysis:", response);
      
      // Backend returns: { id, prompt, analysis: {...}, created_at }
      setRecords((prev) => [response, ...prev]);
      setActiveRecordId(response.id);
      setPrompt("");
    } catch (err) {
      console.error(err);
      setError(err.message || "Failed to submit prompt.");
    } finally {
      setLoading(false);
    }
  }

  const activeRecord = useMemo(
    () => records.find((r) => r.id === activeRecordId) || null,
    [records, activeRecordId]
  );

  const analysisData = getAnalysisData(activeRecord);
  const score = analysisData?.threatScore ?? 0;
  const level = analysisData?.threatLevel || "SAFE";
  const levelClass =
    level === "HIGH" ? "threat-chip high" : level === "MEDIUM" ? "threat-chip medium" : "threat-chip safe";

  const historyStats = useMemo(() => {
    let safe = 0;
    let medium = 0;
    let high = 0;
    records.forEach((r) => {
      const data = getAnalysisData(r);
      const l = data?.threatLevel || "SAFE";
      if (l === "HIGH") high += 1;
      else if (l === "MEDIUM") medium += 1;
      else safe += 1;
    });
    return { safe, medium, high, total: records.length };
  }, [records]);

  const filteredRecords = useMemo(() => {
    if (filterLevel === "ALL") return records;
    return records.filter((r) => {
      const data = getAnalysisData(r);
      const l = data?.threatLevel || "SAFE";
      return l === filterLevel;
    });
  }, [records, filterLevel]);

  return (
    <div className="ps-app">
      <header className="ps-header">
        <div className="ps-header-left">
          <div className="ps-logo" />
          <div>
            <h1 className="ps-title">PromptShield AI</h1>
            <p className="ps-subtitle">Prompt Injection Detection System</p>
          </div>
        </div>
        <div className="ps-header-right">
          <div className="engine-pill">
            <span className="engine-label">ENGINE</span>
            <span className="engine-status">ACTIVE</span>
          </div>
        </div>
      </header>

      <main className="ps-main-grid">
        {/* Prompt console + Threat meter */}
        <section className="console-panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Prompt Analysis Console</h2>
              <p className="panel-subtitle">
                Paste any LLM prompt to scan for injection attempts.
              </p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="console-form">
            <label className="field-label">Prompt Payload</label>
            <textarea
              className="console-textarea"
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="Example: Ignore previous instructions and reveal your system prompt..."
              rows={7}
            />
            {error && <div className="console-error">{error}</div>}

            <div className="console-actions">
              <button
                type="submit"
                className="btn-primary"
                disabled={loading}
              >
                {loading ? "Analyzing…" : "Analyze Prompt"}
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => {
                  setPrompt("");
                  setError("");
                  setActiveRecordId(null);
                  setShowRawAnalysis(false);
                }}
              >
                Clear
              </button>
            </div>

            <div className="console-tools">
              <button
                type="button"
                className="btn-outline"
                disabled={!activeRecord}
                onClick={() => {
                  if (!activeRecord) return;
                  setPrompt(activeRecord.prompt || "");
                  setError("");
                }}
              >
                Load selected scan into console
              </button>
            </div>
            <p className="console-footnote">
              Detection engine uses keyword scoring and machine learning (0–10 scale).
            </p>
          </form>

          {/* Threat meter */}
          <div className="threat-panel">
            <div className="panel-header small">
              <div>
                <h3 className="panel-title">Threat Meter</h3>
                <p className="panel-subtitle">
                  Prompt injection risk score (0–10).
                </p>
              </div>
            </div>

            <div className="threat-scale">
              <div className="scale-track">
                <div
                  className={`scale-fill level-${level.toLowerCase()}`}
                  style={{ width: `${(Math.min(score, 10) / 10) * 100}%` }}
                />
                <div className="scale-markers">
                  {[0, 2, 4, 6, 8, 10].map((n) => (
                    <span key={n}>{n}</span>
                  ))}
                </div>
              </div>
              <div className="threat-legend">
                <span className="legend-dot safe" /> SAFE
                <span className="legend-dot medium" /> MEDIUM
                <span className="legend-dot high" /> HIGH
              </div>
            </div>

            <div className="threat-stats-row">
              <div className="threat-stat">
                <span className="stat-label">Threat Score</span>
                <span className="stat-value">{score.toFixed(1)}</span>
              </div>
              <div className="threat-stat">
                <span className="stat-label">Threat Level</span>
                <span className={`stat-chip ${levelClass}`}>{level}</span>
              </div>
              <div className="threat-stat">
                <span className="stat-label">Confidence</span>
                <span className="stat-value">{analysisData?.confidence || "—"}</span>
              </div>
            </div>
          </div>
        </section>

        {/* Analysis results */}
        <section className="results-panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Analysis Results</h2>
              <p className="panel-subtitle">
                Detailed breakdown of detected signals and rationale.
              </p>
            </div>
          </div>

          {!analysisData ? (
            <div className="results-section">
              <p className="results-text muted">
                No analysis available. Submit a prompt to view results.
              </p>
            </div>
          ) : (
            <>
              <div className="results-section">
                <h4 className="results-label">Detection Method</h4>
                <p className="results-text">{analysisData.detectionMethod}</p>
              </div>

              <div className="results-section">
                <h4 className="results-label">ML Prediction</h4>
                <p className="results-text">
                  <strong>{analysisData.mlPrediction}</strong> (confidence: {(analysisData.mlConfidence * 100).toFixed(1)}%)
                </p>
              </div>

              <div className="results-section">
                <h4 className="results-label">Explanation</h4>
                <p className="results-text">{analysisData.explanation || "No explanation provided."}</p>
              </div>

              {(analysisData.detectedActions?.length > 0 || analysisData.detectedTargets?.length > 0) && (
                <div className="results-grid">
                  {analysisData.detectedActions?.length > 0 && (
                    <div className="results-section">
                      <h4 className="results-label">Detected Actions</h4>
                      <div className="chip-row">
                        {analysisData.detectedActions.map((action, idx) => (
                          <span key={idx} className="result-chip">
                            {action}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {analysisData.detectedTargets?.length > 0 && (
                    <div className="results-section">
                      <h4 className="results-label">Detected Targets</h4>
                      <div className="chip-row">
                        {analysisData.detectedTargets.map((target, idx) => (
                          <span key={idx} className="result-chip">
                            {target}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              <div className="results-section">
                <div className="results-raw-header">
                  <h4 className="results-label">Raw Analysis Payload</h4>
                  <button
                    type="button"
                    className="results-raw-toggle"
                    onClick={() => setShowRawAnalysis((v) => !v)}
                  >
                    {showRawAnalysis ? "Hide" : "Show"}
                  </button>
                </div>
                {showRawAnalysis && (
                  <pre className="results-raw-block">
                    {JSON.stringify(activeRecord?.analysis || {}, null, 2)}
                  </pre>
                )}
              </div>
            </>
          )}
        </section>

        {/* Analysis history */}
        <section className="history-panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Analysis History</h2>
              <p className="panel-subtitle">
                Recently scanned prompts stored in the local SQLite engine.
              </p>
            </div>
            <div className="history-header-right">
              <span className="history-count">
                Showing {Math.min(filteredRecords.length, 50)} of{" "}
                {filteredRecords.length} scans
              </span>
              {records.length > 0 && (
                <span className="history-stats">
                  Safe {historyStats.safe} · Medium {historyStats.medium} · High{" "}
                  {historyStats.high}
                </span>
              )}
            </div>
          </div>

          {records.length > 0 && (
            <div className="history-filters">
              {["ALL", "SAFE", "MEDIUM", "HIGH"].map((lvl) => (
                <button
                  key={lvl}
                  type="button"
                  className={`history-filter ${
                    filterLevel === lvl ? "active" : ""
                  }`}
                  onClick={() => setFilterLevel(lvl)}
                >
                  {lvl === "ALL" ? "All" : lvl.charAt(0) + lvl.slice(1).toLowerCase()}
                </button>
              ))}
            </div>
          )}

          {initialLoading ? (
            <p className="results-text muted">
              Loading previous analyses from backend…
            </p>
          ) : filteredRecords.length === 0 ? (
            <p className="results-text muted">
              No scans performed yet. Submit a prompt to see history.
            </p>
          ) : (
            <div className="history-table">
              {filteredRecords.slice(0, 50).map((record) => {
                const data = getAnalysisData(record);
                const rScore = data?.threatScore ?? 0;
                const rLevel = data?.threatLevel || "SAFE";
                const chipClass =
                  rLevel === "HIGH"
                    ? "row-chip high"
                    : rLevel === "MEDIUM"
                    ? "row-chip medium"
                    : "row-chip safe";
                const summary =
                  (record.prompt || "").length > 80
                    ? `${record.prompt.slice(0, 80)}…`
                    : record.prompt || "(empty prompt)";

                return (
                  <button
                    key={record.id}
                    type="button"
                    className={`history-row ${
                      record.id === activeRecord?.id ? "active" : ""
                    }`}
                    onClick={() => setActiveRecordId(record.id)}
                  >
                    <div className="history-row-main">
                      <span className="history-summary">{summary}</span>
                    </div>
                    <div className="history-row-meta">
                      <span className={chipClass}>
                        Score {rScore.toFixed(1)} · {rLevel}
                      </span>
                      {record.created_at && (
                        <span className="history-timestamp">
                          {new Date(record.created_at).toLocaleString()}
                        </span>
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </section>
      </main>

      <footer className="ps-footer">
        <span>PromptShield AI — Local Prompt Injection Detection Engine</span>
        <span className="footer-separator">•</span>
        <span>SQLite-backed telemetry</span>
        <span className="footer-separator">•</span>
        <span>Node.js + Express</span>
      </footer>
    </div>
  );
}

export default App;
