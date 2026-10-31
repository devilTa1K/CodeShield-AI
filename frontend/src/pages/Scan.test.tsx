import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ProjectScanResponse, ScanFinding } from "../scanTypes";
import { finding, json } from "../test/fixtures";
import Scan from "./Scan";

beforeEach(() => vi.unstubAllGlobals());
afterEach(() => vi.unstubAllGlobals());

function scanFinding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return { ...finding({ ai_explained: false, explanation: null, why_it_matters: null, suggested_code: null }), file: "app.py", ...overrides };
}

function scanResult(overrides: Partial<ProjectScanResponse> = {}): ProjectScanResponse {
  const findings = overrides.findings ?? [
    scanFinding({ id: "P1", severity: "critical", title: "Subprocess with shell=True (B602)", file: "app.py" }),
    scanFinding({ id: "P2", severity: "high", title: "requests 2.19.0: GHSA-x", file: "requirements.txt", tool: "OSV.dev", category: "Vulnerable dependency" }),
    scanFinding({ id: "P3", severity: "low", title: "Use of eval", file: "web/app.js" }),
  ];
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return {
    scan_id: "scan123",
    source: null,
    status: "complete",
    files_scanned: 4,
    files_skipped: 1,
    excluded_tests: 0,
    skipped: [{ path: "big.py", reason: "too large (400 KB)" }],
    languages: { python: 1, javascript: 1 },
    total_findings: findings.length,
    counts,
    score: 39,
    grade: "F",
    findings,
    truncated: false,
    files: [],
    dependencies: { status: "ok", message: null, checked: 5, vulnerable: 1, unpinned: 2, items: [] },
    scanners: [],
    disclaimer: "Automated assistance, not a guarantee.",
    duration_ms: 3200,
    ...overrides,
  };
}

const zip = (name = "project.zip", size = 2048) => {
  const f = new File(["PK"], name, { type: "application/zip" });
  Object.defineProperty(f, "size", { value: size });
  return f;
};

describe("Scan: project upload", () => {
  it("starts with Scan disabled until a ZIP is chosen", () => {
    render(<Scan />);
    expect(screen.getByRole("button", { name: "Scan project" })).toBeDisabled();
    expect(screen.getByText(/Drop a project ZIP here/)).toBeInTheDocument();
  });

  it("uploads the raw ZIP and shows the summary and findings grouped by file", async () => {
    const user = userEvent.setup();
    const fetchMock = vi.fn(async () => json(scanResult()));
    vi.stubGlobal("fetch", fetchMock);
    render(<Scan />);

    const file = zip();
    await user.upload(screen.getByLabelText(/Drop a project ZIP/), file);
    expect(screen.getByText(/ready to scan/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Scan project" }));

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toMatch(/\/api\/scan$/);
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/zip");
    expect(init.body).toBe(file);

    const summary = await screen.findByRole("region", { name: "Scan summary" });
    expect(within(summary).getByText("39")).toBeInTheDocument();
    expect(within(summary).getByLabelText("Grade F")).toBeInTheDocument();
    expect(within(summary).getByText("Vulnerable packages")).toBeInTheDocument();
    expect(screen.getByText("app.py")).toBeInTheDocument();
    expect(screen.getByText("requirements.txt")).toBeInTheDocument();
    expect(screen.getByText("Showing 3 of 3")).toBeInTheDocument();
    expect(screen.getByText(/1 file\(s\) skipped/)).toBeInTheDocument();
    expect(screen.getByText(/2 dependency declaration\(s\) use version ranges/)).toBeInTheDocument();
  });

  it("filters findings by severity", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("fetch", vi.fn(async () => json(scanResult())));
    render(<Scan />);
    await user.upload(screen.getByLabelText(/Drop a project ZIP/), zip());
    await user.click(screen.getByRole("button", { name: "Scan project" }));
    await screen.findByText("Showing 3 of 3");

    await user.click(screen.getByRole("button", { name: "Critical" }));
    expect(screen.getByText("Showing 1 of 3")).toBeInTheDocument();
    expect(screen.queryByText("requirements.txt")).not.toBeInTheDocument();
  });

  it("warns when the dependency check is unavailable but still shows findings", async () => {
    const user = userEvent.setup();
    const result = scanResult({ dependencies: { status: "unavailable", message: "OSV.dev could not be reached.", checked: 3, vulnerable: 0, unpinned: 0, items: [] } });
    vi.stubGlobal("fetch", vi.fn(async () => json(result)));
    render(<Scan />);
    await user.upload(screen.getByLabelText(/Drop a project ZIP/), zip());
    await user.click(screen.getByRole("button", { name: "Scan project" }));
    expect(await screen.findByText(/OSV.dev could not be reached/)).toBeInTheDocument();
    expect(screen.getByText("Showing 3 of 3")).toBeInTheDocument();
  });

  it("rejects non-ZIP and oversized files before sending anything", async () => {
    const user = userEvent.setup({ applyAccept: false });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<Scan />);
    const input = screen.getByLabelText(/Drop a project ZIP/);

    await user.upload(input, new File(["x"], "notes.txt", { type: "text/plain" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Please choose a .zip file");

    await user.upload(input, zip("big.zip", 11 * 1024 * 1024));
    expect(await screen.findByRole("alert")).toHaveTextContent("The limit is 10.0 MB");
    expect(screen.getByRole("button", { name: "Scan project" })).toBeDisabled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows the server's error message when the scan fails", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("fetch", vi.fn(async () => json({ error: { code: "invalid_zip", message: "That file is not a valid ZIP archive." } }, 400)));
    render(<Scan />);
    await user.upload(screen.getByLabelText(/Drop a project ZIP/), zip());
    await user.click(screen.getByRole("button", { name: "Scan project" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("That file is not a valid ZIP archive.");
  });

  it("says so when there are no findings, without claiming the project is safe", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("fetch", vi.fn(async () => json(scanResult({ findings: [], total_findings: 0, score: 100, grade: "A" }))));
    render(<Scan />);
    await user.upload(screen.getByLabelText(/Drop a project ZIP/), zip());
    await user.click(screen.getByRole("button", { name: "Scan project" }));
    expect(await screen.findByText("No findings reported")).toBeInTheDocument();
    expect(screen.getByText(/not proof the project is secure/)).toBeInTheDocument();
  });

  it("scans a public GitHub repository by URL and shows its name", async () => {
    const user = userEvent.setup();
    const fetchMock = vi.fn(async () => json(scanResult({ source: "octo/repo", excluded_tests: 12 })));
    vi.stubGlobal("fetch", fetchMock);
    render(<Scan />);
    expect(screen.getByRole("button", { name: "Scan repo" })).toBeDisabled();

    await user.type(screen.getByLabelText("Scan a public GitHub repository"), "https://github.com/octo/repo");
    await user.click(screen.getByRole("button", { name: "Scan repo" }));

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toMatch(/\/api\/scan\/github$/);
    expect(JSON.parse(String(init.body))).toEqual({ url: "https://github.com/octo/repo", include_tests: false });
    expect(await screen.findByText(/octo\/repo/)).toBeInTheDocument();
    expect(screen.getByText(/12 test, sample and example file\(s\) were left out/)).toBeInTheDocument();
  });

  it("sends include_tests when the box is ticked, for both GitHub and ZIP scans", async () => {
    const user = userEvent.setup();
    const fetchMock = vi.fn(async () => json(scanResult()));
    vi.stubGlobal("fetch", fetchMock);
    render(<Scan />);
    await user.click(screen.getByLabelText("Include test and sample files"));

    await user.type(screen.getByLabelText("Scan a public GitHub repository"), "github.com/octo/repo{Enter}");
    await screen.findByRole("region", { name: "Scan summary" });
    expect(JSON.parse(String((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body)).include_tests).toBe(true);

    await user.upload(screen.getByLabelText(/Drop a project ZIP/), zip());
    await user.click(screen.getByRole("button", { name: /Scan project|Re-scan project/ }));
    expect(String((fetchMock.mock.calls[1] as unknown as [string])[0])).toMatch(/\/api\/scan\?include_tests=true$/);
  });

  it("shows GitHub errors such as a private or missing repository", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("fetch", vi.fn(async () => json({ error: { code: "repo_not_found", message: "Repository or branch not found. Only public repositories can be scanned." } }, 404)));
    render(<Scan />);
    await user.type(screen.getByLabelText("Scan a public GitHub repository"), "https://github.com/octo/nope");
    await user.click(screen.getByRole("button", { name: "Scan repo" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Only public repositories can be scanned.");
  });
});
