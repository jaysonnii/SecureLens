import {
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import App from "./App";
import { joinFindings } from "./joinFindings";


function jsonResponse(data, ok = true, status = ok ? 200 : 400) {
  return {
    ok,
    status,
    json: vi.fn().mockResolvedValue(data),
  };
}


const analysisResponse = {
  analyzed_at: "2026-08-01T19:00:00Z",
  filename: "security.log",
  content_type: "text/plain",
  size_bytes: 128,
  sha256: "a".repeat(64),
  input_format: "text",
  records_analyzed: 4,
  preview: "Event ID: 4104 PowerShell.exe -EncodedCommand AAAA",
  analysis: {
    risk_score: 80,
    score_before_cap: 80,
    score_cap: 100,
    risk_level: "High",
    total_findings: 2,
    score_breakdown: [
      {
        finding_type: "Suspicious PowerShell Activity",
        points: 40,
        reason: "Encoded PowerShell activity was detected.",
      },
      {
        finding_type: "Failed Login Attempts",
        points: 40,
        reason: "4 failed login attempt(s) at 10 points each, capped at 40.",
      },
    ],
    findings: [
      {
        type: "Suspicious PowerShell Activity",
        severity: "High",
        count: 1,
        mitre_attack: "T1059.001 - PowerShell",
        evidence: [
          {
            line_number: 12,
            text: "Event ID: 4104 PowerShell.exe -EncodedCommand AAAA",
          },
        ],
        recommendation: "Review the PowerShell command.",
      },
      {
        type: "Failed Login Attempts",
        severity: "Medium",
        count: 4,
        evidence: [
          { line_number: 3, text: "4625  j.reyes  203.0.113.44" },
          { line_number: 7, text: "4625  j.reyes  203.0.113.44 (retry)" },
        ],
        recommendation: "Review the source IP and account.",
      },
    ],
  },
  ai_summary: {
    status: "disabled",
    provider: "local",
    model: null,
    summary: "SecureLens detected suspicious activity.",
    priority_actions: [
      "Review the PowerShell command.",
      "Review the source IP and account.",
    ],
  },
};


function setupClipboardAndDownload() {
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: vi.fn(),
  });

  Object.defineProperty(URL, "createObjectURL", {
    configurable: true,
    value: vi.fn(() => "blob:securelens-report"),
  });

  Object.defineProperty(URL, "revokeObjectURL", {
    configurable: true,
    value: vi.fn(),
  });

  Object.defineProperty(HTMLAnchorElement.prototype, "click", {
    configurable: true,
    value: vi.fn(),
  });
}


describe("joinFindings", () => {
  it("joins score_breakdown to findings by finding_type", () => {
    const { items, orphaned } = joinFindings(
      analysisResponse.analysis.findings,
      analysisResponse.analysis.score_breakdown
    );

    expect(items).toHaveLength(2);
    expect(orphaned).toHaveLength(0);

    const psh = items.find((item) => item.type === "Suspicious PowerShell Activity");
    expect(psh.points).toBe(40);
    expect(psh.severity).toBe("High");
    expect(psh.mitreAttack).toBe("T1059.001 - PowerShell");
  });

  it("surfaces a score_breakdown entry with no matching finding instead of dropping it", () => {
    const findings = [
      {
        type: "Failed Login Attempts",
        severity: "Medium",
        count: 4,
        evidence: [],
        recommendation: "Review the source IP.",
      },
    ];

    const scoreBreakdown = [
      {
        finding_type: "Failed Login Attempts",
        points: 40,
        reason: "4 failed login attempt(s).",
      },
      {
        finding_type: "Ghost Finding",
        points: 30,
        reason: "Something the findings list doesn't know about.",
      },
    ];

    const { items, orphaned } = joinFindings(findings, scoreBreakdown);

    expect(items).toHaveLength(1);
    expect(orphaned).toHaveLength(1);
    expect(orphaned[0].finding_type).toBe("Ghost Finding");
  });

  it("handles empty input", () => {
    expect(joinFindings([], [])).toEqual({ items: [], orphaned: [] });
    expect(joinFindings(undefined, undefined)).toEqual({
      items: [],
      orphaned: [],
    });
  });
});


describe("SecureLens App", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    setupClipboardAndDownload();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("shows when the backend API is online", async () => {
    fetch.mockResolvedValueOnce(jsonResponse({ status: "healthy" }));

    render(<App />);

    expect(await screen.findByText("API Online")).toBeInTheDocument();

    expect(
      screen.getByText("up to 5 MB", { exact: false })
    ).toBeInTheDocument();

    expect(fetch).toHaveBeenCalledWith(
      "http://127.0.0.1:8000/health",
      expect.objectContaining({ signal: expect.any(AbortSignal) })
    );
  });

  it("shows when the backend API is offline", async () => {
    fetch.mockRejectedValueOnce(new Error("network down"));

    render(<App />);

    expect(await screen.findByText("API Offline")).toBeInTheDocument();
  });

  it("rejects an unsupported file before uploading", async () => {
    fetch.mockResolvedValueOnce(jsonResponse({ status: "healthy" }));

    render(<App />);
    await screen.findByText("API Online");

    const input = document.querySelector('input[type="file"]');
    const badFile = new File(["example"], "malware.exe", {
      type: "application/octet-stream",
    });

    fireEvent.change(input, { target: { files: [badFile] } });

    expect(
      await screen.findByText("Unsupported file type.")
    ).toBeInTheDocument();

    // Only the health check ran - no request for the rejected file.
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("rejects an oversized file before uploading", async () => {
    fetch.mockResolvedValueOnce(jsonResponse({ status: "healthy" }));

    render(<App />);
    await screen.findByText("API Online");

    const input = document.querySelector('input[type="file"]');
    const bigFile = new File(["x"], "huge.log", { type: "text/plain" });
    Object.defineProperty(bigFile, "size", { value: 6 * 1024 * 1024 });

    fireEvent.change(input, { target: { files: [bigFile] } });

    expect(
      await screen.findByText("That file is over 5 MB.")
    ).toBeInTheDocument();
  });

  it(
    "uploads a valid log, shows results with shared selection, and resets",
    async () => {
      const user = userEvent.setup();

      fetch
        .mockResolvedValueOnce(jsonResponse({ status: "healthy" }))
        .mockResolvedValueOnce(jsonResponse(analysisResponse));

      render(<App />);
      await screen.findByText("API Online");

      const input = document.querySelector('input[type="file"]');
      const logFile = new File(["Event ID: 4104 PowerShell"], "security.log", {
        type: "text/plain",
      });

      fireEvent.change(input, { target: { files: [logFile] } });

      expect(await screen.findByText("security.log")).toBeInTheDocument();
      expect(
        screen.getByRole("img", { name: "Risk 80 of 100" })
      ).toBeInTheDocument();
      expect(screen.getByText("80")).toBeInTheDocument();

      expect(fetch).toHaveBeenNthCalledWith(
        2,
        "http://127.0.0.1:8000/upload",
        expect.objectContaining({
          method: "POST",
          body: expect.any(FormData),
        })
      );

      // Clicking a finding header opens its evidence. (The score-bar
      // segment for the same finding shares its accessible name via its
      // title attribute, so scope this query to the findings list.)
      const findingsSection = screen.getByText("Suspicious PowerShell Activity").closest(".sl-findings");
      const findingHeader = within(findingsSection).getByRole("button", {
        name: /Suspicious PowerShell Activity/,
      });
      await user.click(findingHeader);

      expect(
        within(findingsSection).getByText("Review the PowerShell command.")
      ).toBeInTheDocument();
      expect(screen.getByText("1 match, 1 shown.")).toBeInTheDocument();
      expect(within(findingsSection).getByText("12")).toBeInTheDocument();

      // Clicking the same finding's score-bar segment closes it -
      // bar segments and finding headers drive the same selection state.
      const barSegment = screen.getByTitle("+40 Suspicious PowerShell Activity");
      await user.click(barSegment);

      expect(
        within(findingsSection).queryByText("Review the PowerShell command.")
      ).not.toBeInTheDocument();

      // Clicking it again re-opens the same finding from the bar.
      await user.click(barSegment);
      expect(
        within(findingsSection).getByText("Review the PowerShell command.")
      ).toBeInTheDocument();

      // A different finding's header opens that finding and (implicitly,
      // since selection is single-valued) closes the previous one.
      await user.click(
        within(findingsSection).getByRole("button", {
          name: /Failed Login Attempts/,
        })
      );
      expect(
        within(findingsSection).getByText("Review the source IP and account.")
      ).toBeInTheDocument();
      expect(
        within(findingsSection).queryByText("Review the PowerShell command.")
      ).not.toBeInTheDocument();

      // AI summary and priority actions render.
      expect(
        screen.getByText("SecureLens detected suspicious activity.")
      ).toBeInTheDocument();
      expect(
        screen.getByText("Review the source IP and account.", { selector: "li" })
      ).toBeInTheDocument();

      // SHA-256 copy.
      await user.click(screen.getByRole("button", { name: "Copy" }));
      expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();

      // Download report.
      await user.click(screen.getByRole("button", { name: "Download report" }));
      expect(URL.createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
      expect(HTMLAnchorElement.prototype.click).toHaveBeenCalled();
      expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:securelens-report");

      // Reset back to idle.
      await user.click(screen.getByRole("button", { name: "Analyze another log" }));
      expect(screen.queryByText("security.log")).not.toBeInTheDocument();
      expect(screen.getByText("Drop a log file here")).toBeInTheDocument();
    }
  );

  it("shows a working screen while the upload request is in flight", async () => {
    fetch.mockResolvedValueOnce(jsonResponse({ status: "healthy" }));

    let resolveUpload;
    fetch.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveUpload = resolve;
        })
    );

    render(<App />);
    await screen.findByText("API Online");

    const input = document.querySelector('input[type="file"]');
    fireEvent.change(input, {
      target: { files: [new File(["x"], "security.log", { type: "text/plain" })] },
    });

    expect(await screen.findByText("Analyzing")).toBeInTheDocument();

    resolveUpload(jsonResponse(analysisResponse));

    expect(await screen.findByText("security.log")).toBeInTheDocument();
  });

  it("renders a finding with no count field (e.g. Login After Multiple Failures) without an 'undefinedx' label", async () => {
    fetch
      .mockResolvedValueOnce(jsonResponse({ status: "healthy" }))
      .mockResolvedValueOnce(
        jsonResponse({
          ...analysisResponse,
          analysis: {
            ...analysisResponse.analysis,
            total_findings: 1,
            score_breakdown: [
              {
                finding_type: "Login After Multiple Failures",
                points: 30,
                reason: "A successful login occurred after at least three failed attempts.",
              },
            ],
            findings: [
              {
                type: "Login After Multiple Failures",
                severity: "High",
                mitre_attack: "T1110 - Brute Force",
                evidence: [{ line_number: 5, text: "login evidence line" }],
                recommendation: "Review account activity.",
              },
            ],
          },
        })
      );

    render(<App />);
    await screen.findByText("API Online");

    const input = document.querySelector('input[type="file"]');
    fireEvent.change(input, {
      target: { files: [new File(["x"], "security.log", { type: "text/plain" })] },
    });

    await screen.findByText("Login After Multiple Failures");

    expect(screen.queryByText(/undefined/i)).not.toBeInTheDocument();
    expect(screen.getByText("T1110 - Brute Force")).toBeInTheDocument();
  });

  it("shows the empty state when nothing matched", async () => {
    fetch
      .mockResolvedValueOnce(jsonResponse({ status: "healthy" }))
      .mockResolvedValueOnce(
        jsonResponse({
          ...analysisResponse,
          analysis: {
            ...analysisResponse.analysis,
            total_findings: 0,
            findings: [],
            score_breakdown: [],
          },
        })
      );

    render(<App />);
    await screen.findByText("API Online");

    const input = document.querySelector('input[type="file"]');
    fireEvent.change(input, {
      target: { files: [new File(["clean"], "clean.log", { type: "text/plain" })] },
    });

    expect(await screen.findByText("Nothing matched.")).toBeInTheDocument();
  });

  describe("server error mapping", () => {
    beforeEach(async () => {
      fetch.mockResolvedValueOnce(jsonResponse({ status: "healthy" }));
      render(<App />);
      await screen.findByText("API Online");
    });

    async function upload() {
      const input = document.querySelector('input[type="file"]');
      fireEvent.change(input, {
        target: { files: [new File(["x"], "security.log", { type: "text/plain" })] },
      });
    }

    it("maps a 413 size-limit response to the size error screen", async () => {
      fetch.mockResolvedValueOnce(
        jsonResponse(
          { detail: "File is too large. Maximum allowed size is 5 MB." },
          false,
          413
        )
      );

      await upload();

      expect(
        await screen.findByText("That file is over 5 MB.")
      ).toBeInTheDocument();
    });

    it("maps a 413 time-budget response to the budget error screen", async () => {
      fetch.mockResolvedValueOnce(
        jsonResponse(
          {
            detail:
              "This log is too large or too detection-dense to analyze within the time budget. Upload a smaller or less repetitive log.",
          },
          false,
          413
        )
      );

      await upload();

      expect(
        await screen.findByText("Analysis took too long.")
      ).toBeInTheDocument();
    });

    it("maps a 400 encoding response to the encoding error screen", async () => {
      fetch.mockResolvedValueOnce(
        jsonResponse(
          { detail: "The file could not be read as UTF-8 text." },
          false,
          400
        )
      );

      await upload();

      expect(
        await screen.findByText("That file isn't UTF-8 text.")
      ).toBeInTheDocument();
    });

    it("maps a 429 rate-limit response to the rate-limit error screen", async () => {
      fetch.mockResolvedValueOnce(
        jsonResponse(
          { detail: "Rate limit exceeded. Try again in 42 seconds." },
          false,
          429
        )
      );

      await upload();

      expect(await screen.findByText("Too many uploads.")).toBeInTheDocument();
      expect(
        screen.getByText("Rate limit exceeded. Try again in 42 seconds.")
      ).toBeInTheDocument();
    });

    it("maps an unrecognized 400 response to a generic error screen", async () => {
      fetch.mockResolvedValueOnce(
        jsonResponse(
          { detail: "Unsupported file type. Upload a TXT, LOG, CSV, or JSON file." },
          false,
          400
        )
      );

      await upload();

      expect(
        await screen.findByText("That upload didn't work.")
      ).toBeInTheDocument();
      expect(
        screen.getByText("Unsupported file type. Upload a TXT, LOG, CSV, or JSON file.")
      ).toBeInTheDocument();
    });

    it("shows a network error when the request fails outright", async () => {
      fetch.mockRejectedValueOnce(new Error("fetch failed"));

      await upload();

      expect(
        await screen.findByText("Couldn't reach SecureLens.")
      ).toBeInTheDocument();
    });

    it("returns to the upload screen from an error screen", async () => {
      fetch.mockResolvedValueOnce(
        jsonResponse({ detail: "Rate limit exceeded." }, false, 429)
      );

      await upload();

      expect(await screen.findByText("Too many uploads.")).toBeInTheDocument();

      await userEvent.setup().click(screen.getByRole("button", { name: "Back" }));

      expect(screen.getByText("Drop a log file here")).toBeInTheDocument();
    });
  });
});
