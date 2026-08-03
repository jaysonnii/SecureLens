import {
  fireEvent,
  render,
  screen,
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


function jsonResponse(data, ok = true) {
  return {
    ok,
    json: vi.fn().mockResolvedValue(data),
  };
}


const analysisResponse = {
  analyzed_at: "2026-08-01T19:00:00Z",
  filename: "security.log",
  content_type: "text/plain",
  size_bytes: 128,
  input_format: "text",
  records_analyzed: 4,
  preview: (
    "Event ID: 4104 PowerShell.exe "
    + "-EncodedCommand AAAA"
  ),
  analysis: {
    risk_score: 80,
    score_before_cap: 80,
    score_cap: 100,
    risk_level: "High",
    total_findings: 1,
    score_breakdown: [
      {
        finding_type: (
          "Suspicious PowerShell Activity"
        ),
        points: 40,
        reason: (
          "Encoded PowerShell activity was detected."
        ),
      },
    ],
    findings: [
      {
        type: "Suspicious PowerShell Activity",
        severity: "High",
        count: 1,
        mitre_attack: "T1059.001 - PowerShell",
        evidence: [
          (
            "Event ID: 4104 PowerShell.exe "
            + "-EncodedCommand AAAA"
          ),
        ],
        recommendation: (
          "Review the PowerShell command."
        ),
      },
    ],
  },
  ai_summary: {
    status: "disabled",
    provider: "local",
    model: null,
    summary: (
      "SecureLens detected suspicious activity."
    ),
    priority_actions: [
      "Review the PowerShell command.",
    ],
  },
};


describe("SecureLens App", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());

    Object.defineProperty(
      HTMLElement.prototype,
      "scrollIntoView",
      {
        configurable: true,
        value: vi.fn(),
      }
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("shows when the backend API is online", async () => {
    fetch.mockResolvedValueOnce(
      jsonResponse({
        status: "healthy",
      })
    );

    render(<App />);

    expect(
      await screen.findByText("API Online")
    ).toBeInTheDocument();

    expect(
      screen.getByText(
        "TXT, LOG, CSV or JSON · Maximum 25 MB"
      )
    ).toBeInTheDocument();

    expect(fetch).toHaveBeenCalledWith(
      "http://127.0.0.1:8000/health",
      expect.objectContaining({
        signal: expect.any(AbortSignal),
      })
    );
  });

  it("rejects unsupported files before upload", async () => {
    fetch.mockResolvedValueOnce(
      jsonResponse({
        status: "healthy",
      })
    );

    render(<App />);

    await screen.findByText("API Online");

    const input = document.querySelector(
      'input[type="file"]'
    );

    const unsupportedFile = new File(
      ["example"],
      "malware.exe",
      {
        type: "application/octet-stream",
      }
    );

    fireEvent.change(input, {
      target: {
        files: [unsupportedFile],
      },
    });

    expect(
      screen.getByText(
        "Only TXT, LOG, CSV, and JSON files "
        + "are supported."
      )
    ).toBeInTheDocument();

    expect(
      screen.getByRole("button", {
        name: "Analyze log",
      })
    ).toBeDisabled();

    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it(
    "uploads a valid log, displays results, "
      + "and starts a new analysis",
    async () => {
      const user = userEvent.setup();

      fetch
        .mockResolvedValueOnce(
          jsonResponse({
            status: "healthy",
          })
        )
        .mockResolvedValueOnce(
          jsonResponse(analysisResponse)
        );

      render(<App />);

      await screen.findByText("API Online");

      const input = document.querySelector(
        'input[type="file"]'
      );

      const logFile = new File(
        ["Event ID: 4104 PowerShell"],
        "security.log",
        {
          type: "text/plain",
        }
      );

      await user.upload(input, logFile);

      expect(
        screen.getByText("security.log")
      ).toBeInTheDocument();

      const analyzeButton = screen.getByRole(
        "button",
        {
          name: "Analyze log",
        }
      );

      expect(analyzeButton).toBeEnabled();

      await user.click(analyzeButton);

      expect(
        await screen.findByText(
          "Analysis complete"
        )
      ).toBeInTheDocument();

      expect(
        screen.getByText("High risk")
      ).toBeInTheDocument();

      expect(
        screen.getByText("Why this score?")
      ).toBeInTheDocument();

      expect(
        screen.getByText("Records analyzed")
      ).toBeInTheDocument();

      expect(
        screen.getByText("4")
      ).toBeInTheDocument();

      expect(
        screen.getByText(
          "SecureLens detected suspicious activity."
        )
      ).toBeInTheDocument();

      expect(
        screen.getByText(
          "T1059.001 - PowerShell"
        )
      ).toBeInTheDocument();

      expect(fetch).toHaveBeenNthCalledWith(
        2,
        "http://127.0.0.1:8000/upload",
        expect.objectContaining({
          method: "POST",
          body: expect.any(FormData),
        })
      );

      await user.click(
        screen.getByRole("button", {
          name: "Analyze another file",
        })
      );

      expect(
        screen.queryByText("Analysis complete")
      ).not.toBeInTheDocument();

      expect(
        screen.getByRole("button", {
          name: "Analyze log",
        })
      ).toBeDisabled();

      expect(
        HTMLElement.prototype.scrollIntoView
      ).toHaveBeenCalled();
    }
  );
});
