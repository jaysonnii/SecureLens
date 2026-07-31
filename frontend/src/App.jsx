import { useEffect, useRef, useState } from "react";
import "./App.css";

const API_URL =
  import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000";

const MAX_FILE_SIZE = 5 * 1024 * 1024;
const ALLOWED_EXTENSIONS = ["txt", "log", "csv", "json"];

const API_STATUS_LABELS = {
  checking: "Checking API",
  online: "API Online",
  offline: "API Offline",
};

function getExtension(filename) {
  return filename.split(".").pop()?.toLowerCase() ?? "";
}

function formatFileSize(bytes) {
  if (bytes < 1024) {
    return `${bytes} bytes`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function App() {
  const fileInputRef = useRef(null);

  const [selectedFile, setSelectedFile] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [apiStatus, setApiStatus] = useState("checking");

  useEffect(() => {
    const controller = new AbortController();

    async function checkApiHealth() {
      try {
        const response = await fetch(`${API_URL}/health`, {
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error("API health check failed.");
        }

        const data = await response.json();

        setApiStatus(
          data.status === "healthy" ? "online" : "offline"
        );
      } catch (requestError) {
        if (requestError.name !== "AbortError") {
          setApiStatus("offline");
        }
      }
    }

    checkApiHealth();

    return () => controller.abort();
  }, []);

  function validateFile(file) {
    if (!file) {
      return "Please select a file.";
    }

    const extension = getExtension(file.name);

    if (!ALLOWED_EXTENSIONS.includes(extension)) {
      return "Only TXT, LOG, CSV, and JSON files are supported.";
    }

    if (file.size > MAX_FILE_SIZE) {
      return "The selected file is larger than 5 MB.";
    }

    if (file.size === 0) {
      return "The selected file is empty.";
    }

    return "";
  }

  function chooseFile(file) {
    const validationError = validateFile(file);

    setAnalysisResult(null);
    setError(validationError);

    if (validationError) {
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
  }

  function handleFileInput(event) {
    chooseFile(event.target.files?.[0]);
  }

  function handleDrop(event) {
    event.preventDefault();
    setIsDragging(false);

    chooseFile(event.dataTransfer.files?.[0]);
  }

  async function analyzeFile() {
    const validationError = validateFile(selectedFile);

    if (validationError) {
      setError(validationError);
      return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);

    setIsLoading(true);
    setError("");
    setAnalysisResult(null);

    try {
      const response = await fetch(`${API_URL}/upload`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "The log could not be analyzed."
        );
      }

      setAnalysisResult(data);
    } catch (requestError) {
      setError(
        requestError.message ||
          "SecureLens could not connect to the backend."
      );
    } finally {
      setIsLoading(false);
    }
  }

  function clearFile() {
    setSelectedFile(null);
    setAnalysisResult(null);
    setError("");

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  }

  const riskLevel =
    analysisResult?.analysis?.risk_level ?? "";
    
  const aiSummary = analysisResult?.ai_summary;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">S</div>

          <div>
            <h1>SecureLens</h1>
            <p>Security Log Intelligence</p>
          </div>
        </div>

        <div
          className={`api-status ${apiStatus}`}
          role="status"
          aria-live="polite"
        >
          <span
            className="status-dot"
            aria-hidden="true"
          />

          {API_STATUS_LABELS[apiStatus]}
        </div>
      </header>

      <main className="dashboard">
        <section className="hero">
          <span className="eyebrow">
            AI-ready security analysis
          </span>

          <h2>Turn security logs into clear findings.</h2>

          <p>
            Upload a log file to identify suspicious activity,
            calculate risk, map MITRE ATT&amp;CK techniques, and
            receive recommended investigation steps.
          </p>
        </section>

        <section className="panel upload-panel">
          <div className="panel-heading">
            <div>
              <p className="section-label">Log upload</p>
              <h3>Analyze a security log</h3>
            </div>

            <span className="file-rules">
              TXT, LOG, CSV or JSON · Maximum 5 MB
            </span>
          </div>

          <div
            className={`drop-zone ${
              isDragging ? "dragging" : ""
            }`}
            onDragEnter={() => setIsDragging(true)}
            onDragLeave={() => setIsDragging(false)}
            onDragOver={(event) => event.preventDefault()}
            onDrop={handleDrop}
          >
            <input
              ref={fileInputRef}
              id="log-file"
              type="file"
              accept=".txt,.log,.csv,.json"
              onChange={handleFileInput}
            />

            <div className="upload-icon">↑</div>

            <h4>Drop your log file here</h4>
            <p>or select a file from your computer</p>

            <button
              className="secondary-button"
              type="button"
              onClick={() =>
                fileInputRef.current?.click()
              }
            >
              Choose file
            </button>
          </div>

          {selectedFile && (
            <div className="selected-file">
              <div>
                <strong>{selectedFile.name}</strong>
                <span>
                  {formatFileSize(selectedFile.size)}
                </span>
              </div>

              <button type="button" onClick={clearFile}>
                Remove
              </button>
            </div>
          )}

          {error && (
            <div className="error-message">{error}</div>
          )}

          <button
            className="primary-button"
            type="button"
            disabled={!selectedFile || isLoading}
            onClick={analyzeFile}
          >
            {isLoading ? "Analyzing log..." : "Analyze log"}
          </button>
        </section>

        {analysisResult && (
          <section className="results">
            <div className="results-heading">
              <div>
                <p className="section-label">
                  Analysis complete
                </p>

                <h3>{analysisResult.filename}</h3>
              </div>

              <span
                className={`risk-badge ${riskLevel.toLowerCase()}`}
              >
                {riskLevel} risk
              </span>
            </div>

            <div className="summary-grid">
              <article className="summary-card score-card">
                <span>Risk score</span>

                <strong>
                  {analysisResult.analysis.risk_score}
                  <small>/100</small>
                </strong>
              </article>

              <article className="summary-card">
                <span>Risk level</span>

                <strong>
                  {analysisResult.analysis.risk_level}
                </strong>
              </article>

              <article className="summary-card">
                <span>Total findings</span>

                <strong>
                  {analysisResult.analysis.total_findings}
                </strong>
              </article>

              <article className="summary-card">
                <span>File size</span>

                <strong>
                  {formatFileSize(analysisResult.size_bytes)}
                </strong>
              </article>
            </div>

            {aiSummary && (
              <div className="panel ai-summary-panel">
                <div className="panel-heading">
                  <div>
                    <p className="section-label">
                      Analyst summary
                    </p>

                    <h3>Security overview</h3>
                  </div>

                  <span className="ai-provider">
                    {aiSummary.provider === "openai"
                      ? "AI generated"
                      : "Local analysis"}
                  </span>
                </div>

                <p className="ai-summary-text">
                  {aiSummary.summary}
                </p>

                {Array.isArray(aiSummary.priority_actions) &&
                  aiSummary.priority_actions.length > 0 && (
                    <div className="priority-actions">
                      <h4>Priority actions</h4>

                      <ol>
                        {aiSummary.priority_actions.map(
                          (action, index) => (
                            <li key={`${action}-${index}`}>
                              {action}
                            </li>
                          )
                        )}
                      </ol>
                    </div>
                  )}
              </div>
            )}
            
            <div className="panel findings-panel">
              <div className="panel-heading">
                <div>
                  <p className="section-label">
                    Detected activity
                  </p>

                  <h3>Security findings</h3>
                </div>
              </div>

              {analysisResult.analysis.findings.length ===
              0 ? (
                <div className="empty-state">
                  No suspicious indicators were detected.
                </div>
              ) : (
                <div className="findings-list">
                  {analysisResult.analysis.findings.map(
                    (finding, index) => (
                      <article
                        className="finding-card"
                        key={`${finding.type}-${index}`}
                      >
                        <div className="finding-header">
                          <div>
                            <span
                              className={`severity ${finding.severity.toLowerCase()}`}
                            >
                              {finding.severity}
                            </span>

                            <h4>{finding.type}</h4>
                          </div>

                          {finding.count !== undefined && (
                            <span className="finding-count">
                              {finding.count} detected
                            </span>
                          )}
                        </div>

                        {finding.mitre_attack && (
                          <div className="finding-row">
                            <span>MITRE ATT&amp;CK</span>

                            <strong>
                              {finding.mitre_attack}
                            </strong>
                          </div>
                        )}

                        {Array.isArray(finding.evidence) &&
                          finding.evidence.length > 0 && (
                            <div className="evidence">
                              <span>Evidence</span>

                              <ul className="evidence-list">
                                {finding.evidence.map((line, evidenceIndex) => (
                                  <li key={`${finding.type}-evidence-${evidenceIndex}`}>
                                    <code>{line}</code>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                        
                        <div className="recommendation">
                          <span>Recommended action</span>

                          <p>{finding.recommendation}</p>
                        </div>
                      </article>
                    )
                  )}
                </div>
              )}
            </div>

            <div className="panel preview-panel">
              <div className="panel-heading">
                <div>
                  <p className="section-label">
                    Uploaded content
                  </p>

                  <h3>Log preview</h3>
                </div>
              </div>

              <pre>{analysisResult.preview}</pre>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;