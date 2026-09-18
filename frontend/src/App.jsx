import { useEffect, useRef, useState } from "react";
import "./App.css";
import { joinFindings } from "./joinFindings";
import { buildTimeline } from "./timeline";

const API_URL =
  import.meta.env.VITE_API_URL ??
  (import.meta.env.PROD
    ? "/api"
    : "http://127.0.0.1:8000");

const MAX_FILE_SIZE_MB = Math.min(
  100,
  Math.max(
    1,
    Number(import.meta.env.VITE_MAX_FILE_SIZE_MB) || 5
  )
);
const MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024;
const ALLOWED_EXTENSIONS = ["txt", "log", "csv", "json"];

const API_STATUS_LABELS = {
  checking: "Checking API",
  online: "API Online",
  offline: "API Offline",
};

const SEVERITY_COLOR = {
  High: "#D4705F",
  Medium: "#C9A227",
  Low: "#8C8475",
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

function formatDuration(seconds) {
  if (seconds < 1) {
    return `${Math.round(seconds * 1000)} ms`;
  }

  return `${seconds.toFixed(2)} s`;
}

const ERRORS = {
  tooLarge: {
    title: `That file is over ${MAX_FILE_SIZE_MB} MB.`,
    body: `SecureLens caps uploads at ${MAX_FILE_SIZE_MB} MB so one request can't tie up the analyzer. Split the log or trim it to the window you care about.`,
    cta: "Choose another file",
  },
  encoding: {
    title: "That file isn't UTF-8 text.",
    body: "SecureLens reads text logs. If this came from Event Viewer, export it as CSV or XML first.",
    cta: "Choose another file",
  },
  budget: {
    title: "Analysis took too long.",
    body: "Correlation cost grows sharply with the number of login events. A smaller slice of the same log will finish.",
    cta: "Try a smaller file",
  },
  rateLimit: {
    title: "Too many uploads.",
    body: "Wait a moment and try again.",
    cta: "Back",
  },
  unsupportedType: {
    title: "Unsupported file type.",
    body: "SecureLens accepts TXT, LOG, CSV, and JSON files.",
    cta: "Choose another file",
  },
  empty: {
    title: "That file is empty.",
    body: "Choose a file that contains log data.",
    cta: "Choose another file",
  },
  network: {
    title: "Couldn't reach SecureLens.",
    body: "The backend didn't respond. Check the API status above and try again.",
    cta: "Try again",
  },
};

function genericError(detail) {
  return {
    title: "That upload didn't work.",
    body: detail || "The server rejected the file for an unspecified reason.",
    cta: "Choose another file",
  };
}

// Maps a POST /upload failure to one of the known error screens. Both
// the size cap and the analysis time budget return HTTP 413, so the two
// are told apart by the detail text the backend actually sends (see
// backend/app/routers/uploads.py and app/services/analyzer.py).
function classifyServerError(status, detail) {
  const lower = (detail || "").toLowerCase();

  if (status === 413 && lower.includes("time budget")) {
    return ERRORS.budget;
  }

  if (status === 413) {
    return ERRORS.tooLarge;
  }

  if (status === 429) {
    return detail ? { ...ERRORS.rateLimit, body: detail } : ERRORS.rateLimit;
  }

  if (status === 400 && lower.includes("utf-8")) {
    return ERRORS.encoding;
  }

  return genericError(detail);
}

function validateFile(file) {
  if (!file) {
    return genericError("Please select a file.");
  }

  const extension = getExtension(file.name);

  if (!ALLOWED_EXTENSIONS.includes(extension)) {
    return ERRORS.unsupportedType;
  }

  if (file.size > MAX_FILE_SIZE) {
    return ERRORS.tooLarge;
  }

  if (file.size === 0) {
    return ERRORS.empty;
  }

  return null;
}

function App() {
  const fileInputRef = useRef(null);

  const [view, setView] = useState("idle"); // idle | working | error | done
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
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

  async function analyze(file) {
    const validationError = validateFile(file);

    if (validationError) {
      setError(validationError);
      setView("error");
      return;
    }

    setView("working");

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch(`${API_URL}/upload`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json().catch(() => null);

      if (!response.ok) {
        setError(classifyServerError(response.status, data?.detail));
        setView("error");
        return;
      }

      setResult(data);
      setView("done");
    } catch {
      setError(ERRORS.network);
      setView("error");
    }
  }

  function reset() {
    setView("idle");
    setResult(null);
    setError(null);

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  }

  return (
    <div className="sl">
      <header className="sl-top">
        <span className="sl-brand">SecureLens</span>
        <span
          className={`sl-status ${apiStatus}`}
          role="status"
          aria-live="polite"
        >
          {API_STATUS_LABELS[apiStatus]}
        </span>
      </header>

      <main className="sl-main">
        {view === "idle" && (
          <Upload onFile={analyze} inputRef={fileInputRef} />
        )}
        {view === "working" && <Working />}
        {view === "error" && <Failure error={error} onRetry={reset} />}
        {view === "done" && <Results data={result} onReset={reset} />}
      </main>

      <footer className="sl-foot">
        <span>Nothing is stored. Files are analyzed in memory and discarded.</span>
        <a href="https://github.com/jaysonnii/SecureLens">Source</a>
      </footer>
    </div>
  );
}

/* ---------------------------------------------------------------- */

function Upload({ onFile, inputRef }) {
  const [over, setOver] = useState(false);

  return (
    <div className="sl-upload">
      <h1>Find out what happened in your log.</h1>
      <p className="sl-lede">
        Upload a security log. SecureLens scores it, maps what it finds to
        ATT&amp;CK, and shows the lines it based that on.
      </p>

      <div
        className={"sl-drop" + (over ? " is-over" : "")}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          onFile(e.dataTransfer.files[0]);
        }}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => e.key === "Enter" && inputRef.current?.click()}
        role="button"
        tabIndex={0}
      >
        <span className="sl-drop-main">Drop a log file here</span>
        <span className="sl-drop-sub">
          .log .txt .csv .json &nbsp;/&nbsp; up to {MAX_FILE_SIZE_MB} MB &nbsp;/&nbsp; UTF-8
        </span>
        <input
          ref={inputRef}
          id="log-file"
          type="file"
          accept=".log,.txt,.csv,.json"
          hidden
          onChange={(e) => onFile(e.target.files[0])}
        />
      </div>
    </div>
  );
}

function Working() {
  const [secs, setSecs] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setSecs((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="sl-working">
      <div className="sl-pulse" />
      <p className="sl-working-main">Analyzing</p>
      <p className="sl-meta">
        {secs < 10
          ? "Matching detection rules."
          : secs < 25
          ? "Correlating login sequences. Dense logs take longer."
          : "Still working. This stops at 40 seconds."}
      </p>
    </div>
  );
}

function Failure({ error, onRetry }) {
  return (
    <div className="sl-fail">
      <h2>{error.title}</h2>
      <p className="sl-lede">{error.body}</p>
      <button className="sl-btn" onClick={onRetry}>
        {error.cta}
      </button>
    </div>
  );
}

function Results({ data, onReset }) {
  const [open, setOpen] = useState(null);
  const [copyStatus, setCopyStatus] = useState("idle");

  const analysis = data.analysis;
  const { items, orphaned } = joinFindings(
    analysis.findings,
    analysis.score_breakdown
  );

  const total = analysis.score_before_cap;
  const capped = total > analysis.score_cap;
  const scale = Math.max(total, analysis.score_cap);

  async function copySha256() {
    try {
      await navigator.clipboard.writeText(data.sha256);
      setCopyStatus("copied");
    } catch {
      setCopyStatus("error");
    }
  }

  function downloadReport() {
    const safeFilename =
      data.filename
        .replace(/\.[^/.]+$/, "")
        .replace(/[^a-z0-9-_]+/gi, "-")
        .replace(/^-+|-+$/g, "") || "securelens-analysis";

    const reportData = { ...data };
    delete reportData.preview;

    const report = {
      exported_at: new Date().toISOString(),
      ...reportData,
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${safeFilename}-securelens-report.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  if (analysis.total_findings === 0) {
    return (
      <div className="sl-fail">
        <h2>Nothing matched.</h2>
        <p className="sl-lede">
          None of the current detection rules fired on {data.filename}.
          SecureLens covers failed logins, privilege use, PowerShell, and log
          clearing. It does not cover everything.
        </p>
        <button className="sl-btn" onClick={onReset}>
          Analyze another log
        </button>
      </div>
    );
  }

  return (
    <div className="sl-results">
      <div className="sl-file">
        <h1>{data.filename}</h1>
        <dl className="sl-facts">
          <div><dt>Records analyzed</dt><dd>{data.records_analyzed.toLocaleString()}</dd></div>
          <div><dt>Size</dt><dd>{formatFileSize(data.size_bytes)}</dd></div>
          {typeof data.analysis_duration_seconds === "number" && (
            <div>
              <dt>Analysis duration</dt>
              <dd>{formatDuration(data.analysis_duration_seconds)}</dd>
            </div>
          )}
          <div className="sl-fact-wide">
            <dt>SHA-256</dt>
            <dd title={data.sha256}>
              {data.sha256.slice(0, 32)}...
              <button className="sl-inline-btn" onClick={copySha256}>
                {copyStatus === "copied"
                  ? "Copied"
                  : copyStatus === "error"
                  ? "Copy failed"
                  : "Copy"}
              </button>
            </dd>
          </div>
        </dl>
      </div>

      <section className="sl-score">
        <div className="sl-score-row">
          <span className="sl-score-num">{Math.min(total, analysis.score_cap)}</span>
          <span
            className="sl-score-level"
            style={{ color: SEVERITY_COLOR[analysis.risk_level] }}
          >
            {analysis.risk_level}
          </span>
        </div>

        <div
          className="sl-bar"
          role="img"
          aria-label={`Risk ${Math.min(total, analysis.score_cap)} of ${analysis.score_cap}`}
        >
          {items.map((item) => (
            <button
              key={item.id}
              className={"sl-seg" + (open === item.id ? " is-open" : "")}
              style={{
                width: `${(item.points / scale) * 100}%`,
                background: SEVERITY_COLOR[item.severity],
              }}
              onClick={() => setOpen(open === item.id ? null : item.id)}
              title={`+${item.points} ${item.type}`}
            />
          ))}
          {orphaned.map((entry, i) => (
            <span
              key={`orphan-${i}`}
              className="sl-seg sl-seg-orphan"
              style={{ width: `${(entry.points / scale) * 100}%` }}
              title={`+${entry.points} ${entry.finding_type} (no matching finding data)`}
            />
          ))}
          {capped && (
            <span
              className="sl-cap"
              style={{ left: `${(analysis.score_cap / scale) * 100}%` }}
            >
              <span className="sl-cap-label">{analysis.score_cap}</span>
            </span>
          )}
        </div>

        {capped && (
          <p className="sl-meta">
            Findings total {total}. Capped at {analysis.score_cap}.
          </p>
        )}

        {orphaned.length > 0 && (
          <p className="sl-warning" role="alert">
            {orphaned.length} score contribution
            {orphaned.length === 1 ? "" : "s"} couldn't be matched to a
            finding: {orphaned.map((entry) => entry.finding_type).join(", ")}.
          </p>
        )}
      </section>

      <Timeline items={items} open={open} setOpen={setOpen} />

      <section className="sl-findings">
        {items.map((item) => {
          const isOpen = open === item.id;
          const shownCount = item.evidence.length;

          return (
            <article key={item.id} className="sl-finding">
              <button
                className="sl-finding-head"
                onClick={() => setOpen(isOpen ? null : item.id)}
                aria-expanded={isOpen}
              >
                <span
                  className="sl-pts"
                  style={{ color: SEVERITY_COLOR[item.severity] }}
                >
                  +{item.points}
                </span>
                <span className="sl-finding-title">
                  {item.type}
                  <span className="sl-sev">{item.severity}</span>
                </span>
                <span className="sl-tech">
                  {item.count !== undefined && <>{item.count}x</>}
                  {item.mitreAttack && <>&nbsp;{item.mitreAttack}</>}
                </span>
              </button>

              {isOpen && (
                <div className="sl-body">
                  <p className="sl-reason">{item.reason}</p>
                  <ul className="sl-evidence">
                    {item.evidence.map((entry) => (
                      <li key={entry.line_number}>
                        <span className="sl-ln">{entry.line_number}</span>
                        {entry.text}
                      </li>
                    ))}
                  </ul>
                  {item.count !== undefined && (
                    <p className="sl-more">
                      {item.count} match{item.count === 1 ? "" : "es"},{" "}
                      {shownCount} shown.
                    </p>
                  )}
                  <p className="sl-action">{item.recommendation}</p>
                </div>
              )}
            </article>
          );
        })}
      </section>

      {data.ai_summary && (
        <section className="sl-summary">
          <p>{data.ai_summary.summary}</p>
          <p className="sl-meta">
            Written by SecureLens from the findings above. Review before acting.
          </p>
          {data.ai_summary.priority_actions?.length > 0 && (
            <div className="sl-priority">
              <p className="sl-meta">Priority actions</p>
              <ol>
                {data.ai_summary.priority_actions.map((action, i) => (
                  <li key={i}>{action}</li>
                ))}
              </ol>
            </div>
          )}
        </section>
      )}

      <div className="sl-actions">
        <button className="sl-btn" onClick={downloadReport}>
          Download report
        </button>
        <button className="sl-btn" onClick={onReset}>
          Analyze another log
        </button>
      </div>
    </div>
  );
}

function Timeline({ items, open, setOpen }) {
  const timeline = buildTimeline(items);

  // Fewer than two placed points can't show a window - rendering one
  // tick (or none) would either be meaningless or misleading, so the
  // timeline doesn't render at all rather than imply a scale it doesn't
  // have.
  if (timeline.placedCount < 2) {
    return null;
  }

  return (
    <section className="sl-timeline">
      <h2 className="sl-timeline-title">Timeline</h2>
      <p className="sl-meta">
        {timeline.placedCount} of {timeline.totalCount} events placed in
        time.
        {timeline.hasAssumedTimezone && (
          <>
            {" "}
            Some timestamps didn&apos;t specify a timezone; UTC was assumed
            for those.
          </>
        )}
      </p>

      <div
        className="sl-timeline-track"
        role="img"
        aria-label={`Timeline of ${timeline.placedCount} events`}
      >
        {timeline.events.map((event, i) => (
          <button
            key={`${event.findingId}-${i}`}
            className={
              "sl-tick" + (open === event.findingId ? " is-open" : "")
            }
            style={{
              left: `${event.percent}%`,
              background: SEVERITY_COLOR[event.severity],
            }}
            onClick={() =>
              setOpen(open === event.findingId ? null : event.findingId)
            }
            title={`Line ${event.lineNumber} — ${event.timestamp.utc}${
              event.timestamp.timezone_assumed ? " (UTC assumed)" : ""
            }`}
          />
        ))}
      </div>
    </section>
  );
}

export default App;
