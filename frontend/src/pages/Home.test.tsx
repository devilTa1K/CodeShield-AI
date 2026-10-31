import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { finding, json, mockBackend, review } from "../test/fixtures";
import Home from "./Home";

beforeEach(() => {
  vi.unstubAllGlobals();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

async function loadVulnerableAndAnalyze(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "Vulnerable sample" }));
  await user.click(screen.getByRole("button", { name: "Analyze code" }));
}

describe("Home: review workflow", () => {
  it("starts empty, with Analyze disabled and a helpful empty state", async () => {
    mockBackend(() => json(review()));
    render(<Home />);
    expect(screen.getByRole("button", { name: "Analyze code" })).toBeDisabled();
    expect(screen.getByText("No review yet")).toBeInTheDocument();
    expect(await screen.findByText(/Backend online · AI ready \(qwen-3.8-27b\)/)).toBeInTheDocument();
  });

  it("loads a sample, sends it to the backend, and shows the dashboard and findings", async () => {
    const user = userEvent.setup();
    const fetchMock = mockBackend(() => json(review()));
    render(<Home />);

    await loadVulnerableAndAnalyze(user);

    const call = fetchMock.mock.calls.find(([u]) => String(u).endsWith("/api/review"))!;
    expect(call[1]?.method).toBe("POST");
    const body = JSON.parse(String(call[1]?.body));
    expect(body.language).toBe("python");
    expect(body.code).toContain("eval(expr)");

    expect(await screen.findByText("Complete")).toBeInTheDocument();
    expect(screen.getByText("Three issues need attention before this code is used.")).toBeInTheDocument();
    expect(screen.getByText("Showing 3 of 3")).toBeInTheDocument();

    const cards = screen.getAllByTestId("finding-card");
    expect(cards).toHaveLength(3);

    // Scanner findings and AI hypotheses are labelled differently.
    expect(screen.getAllByText(/Static analysis · Bandit/).length).toBeGreaterThan(0);
    await user.click(within(cards[2]).getByRole("button", { name: /Missing authorization check/ }));
    expect(screen.getByText(/AI hypothesis · unverified/)).toBeInTheDocument();

    // Button now offers a re-run.
    expect(screen.getByRole("button", { name: "Re-run review" })).toBeEnabled();
  });

  it("filters findings by severity, source and category", async () => {
    const user = userEvent.setup();
    mockBackend(() => json(review()));
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    await screen.findByText("Showing 3 of 3");

    const group = screen.getByRole("group", { name: "Filter by severity" });
    await user.click(within(group).getByRole("button", { name: "Critical" }));
    expect(screen.getByText("Showing 1 of 3")).toBeInTheDocument();
    expect(screen.getByText("Subprocess with shell=True (B602)")).toBeInTheDocument();
    expect(screen.queryByText("Missing authorization check")).not.toBeInTheDocument();

    await user.click(within(group).getByRole("button", { name: "All severities" }));
    await user.selectOptions(screen.getByLabelText("Filter by source"), "ai_hypothesis");
    expect(screen.getByText("Showing 1 of 3")).toBeInTheDocument();
    expect(screen.getByText("Missing authorization check")).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Filter by source"), "all");
    await user.selectOptions(screen.getByLabelText("Filter by category"), "Injection");
    expect(screen.getByText("Showing 1 of 3")).toBeInTheDocument();

    await user.click(within(group).getByRole("button", { name: "Medium" }));
    expect(screen.getByText("No findings match these filters.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getByText("Showing 3 of 3")).toBeInTheDocument();
  });

  it("shows original and suggested code side by side and copies the fix", async () => {
    const user = userEvent.setup();
    mockBackend(() => json(review()));
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    await screen.findByText("Showing 3 of 3");

    const first = screen.getAllByTestId("finding-card")[0];
    expect(within(first).getByText(/Your code/)).toBeInTheDocument();
    expect(within(first).getByText("Suggested replacement")).toBeInTheDocument();

    await user.click(within(first).getByRole("button", { name: "Copy fix" }));
    expect(await within(first).findByText("Copied")).toBeInTheDocument();
    expect(await navigator.clipboard.readText()).toBe('subprocess.run(["cat", filename], check=True)');
  });

  it("marks the results stale when the code changes and re-runs on demand", async () => {
    const user = userEvent.setup();
    const onReview = vi.fn(() => json(review()));
    mockBackend(onReview);
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    await screen.findByText("Complete");

    await user.type(screen.getByRole("textbox", { name: "Code" }), "\n# edited");
    expect(await screen.findByText(/Your code has changed since this review/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Re-run review" }));
    await waitFor(() => expect(onReview).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByText(/Your code has changed/)).not.toBeInTheDocument());
  });

  it("renders AI text as plain text, never as HTML", async () => {
    const user = userEvent.setup();
    const evil = '<img src=x onerror="window.__pwned = true">';
    mockBackend(() =>
      json(review({ summary: evil, findings: [finding({ title: evil, explanation: evil, snippet: evil })], total_findings: 1, counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } })),
    );
    const { container } = render(<Home />);
    await loadVulnerableAndAnalyze(user);
    await screen.findByText("Complete");
    expect(container.querySelector("img")).toBeNull();
    expect((window as unknown as { __pwned?: boolean }).__pwned).toBeUndefined();
    expect(screen.getAllByText(evil).length).toBeGreaterThan(0);
  });
});

describe("Home: failure and edge states", () => {
  it("shows the server's error message and offers a retry", async () => {
    const user = userEvent.setup();
    let calls = 0;
    mockBackend(() => {
      calls += 1;
      return calls === 1 ? json({ error: { code: "rate_limited", message: "Too many review requests. Please wait a minute and retry." } }, 429) : json(review());
    });
    render(<Home />);
    await loadVulnerableAndAnalyze(user);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Too many review requests");
    await user.click(within(alert).getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Complete")).toBeInTheDocument();
    expect(screen.queryByText("Review failed")).not.toBeInTheDocument();
  });

  it("explains a network failure instead of crashing", async () => {
    const user = userEvent.setup();
    mockBackend(() => {
      throw new TypeError("Failed to fetch");
    });
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not reach the CodeShield backend");
  });

  it("shows when the backend is offline", async () => {
    mockBackend(() => json(review()), () => {
      throw new TypeError("offline");
    });
    render(<Home />);
    expect(await screen.findByText("Backend offline")).toBeInTheDocument();
  });

  it("makes AI failures visible and keeps scanner results", async () => {
    const user = userEvent.setup();
    mockBackend(() =>
      json(
        review({
          status: "static_only",
          ai: { status: "error", model: "qwen-3.8-27b", error_code: "ai_plan_required", message: "BharatCode refused the request (HTTP 402).", dropped_items: 0 },
          best_practices: [],
          findings: [finding({ ai_explained: false, explanation: null, why_it_matters: null, suggested_code: null })],
          total_findings: 1,
          counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        }),
      ),
    );
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    expect(await screen.findByText("Static analysis only")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("AI review unavailable");
    expect(screen.getByRole("alert")).toHaveTextContent("HTTP 402");
    expect(screen.getAllByTestId("finding-card")).toHaveLength(1);
  });

  it("never claims code is secure when nothing is found", async () => {
    const user = userEvent.setup();
    mockBackend(() => json(review({ findings: [], total_findings: 0, counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } })));
    render(<Home />);
    await user.click(screen.getByRole("button", { name: "Safe sample" }));
    await user.click(screen.getByRole("button", { name: "Analyze code" }));
    expect(await screen.findByText("No findings reported")).toBeInTheDocument();
    expect(screen.getByText(/not proof that it is secure/)).toBeInTheDocument();
  });

  it("blocks oversized input before calling the backend", async () => {
    const user = userEvent.setup();
    const fetchMock = mockBackend(() => json(review()));
    render(<Home />);
    await screen.findByText(/Backend online/);
    const box = screen.getByRole("textbox", { name: "Code" });
    await user.click(box);
    await user.paste("a".repeat(40_001));
    expect(screen.getByRole("button", { name: "Analyze code" })).toBeDisabled();
    expect(fetchMock.mock.calls.some(([u]) => String(u).endsWith("/api/review"))).toBe(false);
  });

  it("switches samples with the language", async () => {
    const user = userEvent.setup();
    mockBackend(() => json(review()));
    render(<Home />);
    await user.selectOptions(screen.getByLabelText("Language"), "c");
    await user.click(screen.getByRole("button", { name: "Vulnerable sample" }));
    expect((screen.getByRole("textbox", { name: "Code" }) as HTMLTextAreaElement).value).toContain("gets(name)");
  });

  it("lets the user cancel a slow review without showing an error", async () => {
    const user = userEvent.setup();
    mockBackend((_url, init) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
    }));
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    expect(await screen.findByText("Analyzing")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Analyze code" })).toBeEnabled());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("Home: advanced features", () => {
  it("shows the review score, grade and OWASP/CWE chips", async () => {
    const user = userEvent.setup();
    mockBackend(() => json(review()));
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    const score = await screen.findByTestId("score");
    expect(score).toHaveTextContent("40");
    expect(score).toHaveTextContent("grade D");
    expect(score).toHaveTextContent("not proof that code is secure");
    expect(screen.getAllByText(/OWASP A03:2021 Injection/).length).toBeGreaterThan(0);
    const cwe = screen.getAllByRole("link", { name: /CWE-78/ })[0];
    expect(cwe).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/78.html");
    expect(cwe).toHaveAttribute("rel", expect.stringContaining("noopener"));
  });

  it("sends the chosen explanation language to the backend", async () => {
    const user = userEvent.setup();
    const fetchMock = mockBackend(() => json(review({ explain_language: "hinglish" })));
    render(<Home />);
    await user.selectOptions(screen.getByLabelText("Explain in"), "hinglish");
    await loadVulnerableAndAnalyze(user);
    await screen.findByTestId("score");
    const call = fetchMock.mock.calls.find(([u]) => String(u).endsWith("/api/review"))!;
    expect(JSON.parse(String(call[1]?.body)).explain_language).toBe("hinglish");
  });

  it("applies a fix to the editor, re-runs the review and shows the score improvement", async () => {
    const user = userEvent.setup();
    const bodies: { code: string }[] = [];
    const first = review({ findings: [finding({ id: "S1", severity: "critical", line_start: 26, line_end: 26, suggested_code: "return ast.literal_eval(expr)" })], total_findings: 1, score: 75, grade: "B" });
    const second = review({ review_id: "second", findings: [], total_findings: 0, score: 100, grade: "A" });
    mockBackend((_url, init) => {
      bodies.push(JSON.parse(String(init?.body)));
      return json(bodies.length === 1 ? first : second);
    });
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    await screen.findByText("Showing 1 of 1");

    await user.click(screen.getByRole("button", { name: /Apply fix & re-check/ }));

    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1].code).toContain("    return ast.literal_eval(expr)");
    expect(bodies[1].code).not.toContain("eval(expr)\n    return eval");
    expect((screen.getByRole("textbox", { name: "Code" }) as HTMLTextAreaElement).value).toBe(bodies[1].code);
    const delta = await screen.findByTestId("score-delta");
    expect(delta).toHaveTextContent("+25 points");
    expect(delta).toHaveTextContent("findings 1 → 0");
  });

  it("fixes everything at once, re-checks, and explains what happened", async () => {
    const user = userEvent.setup();
    const bodies: { code: string }[] = [];
    const first = review({
      findings: [
        finding({ id: "S1", severity: "critical", line_start: 14, line_end: 14, suggested_code: 'subprocess.run(["cat", filename], check=True)' }),
        finding({ id: "S2", severity: "critical", line_start: 22, line_end: 22, suggested_code: "return hashlib.sha256(password.encode()).hexdigest()" }),
        finding({ id: "S3", severity: "low", line_start: 3, line_end: 3, suggested_code: null }),
      ],
      total_findings: 3,
      score: 47,
      grade: "D",
    });
    const second = review({ review_id: "second", findings: [], total_findings: 0, score: 100, grade: "A" });
    mockBackend((_url, init) => {
      bodies.push(JSON.parse(String(init?.body)));
      return json(bodies.length === 1 ? first : second);
    });
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    await screen.findByText("Showing 3 of 3");

    await user.click(screen.getByRole("button", { name: /Fix all \(2\) & verify/ }));

    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1].code).toContain('    subprocess.run(["cat", filename], check=True)');
    expect(bodies[1].code).toContain("    return hashlib.sha256(password.encode()).hexdigest()");
    expect(bodies[1].code).not.toContain("md5");
    expect(await screen.findByText(/Applied 2 of 2 fixes/)).toBeInTheDocument();
    expect(await screen.findByTestId("score-delta")).toHaveTextContent("+53 points");
  });

  it("only offers Fix all when more than one finding has a fix", async () => {
    const user = userEvent.setup();
    mockBackend(() => json(review({ findings: [finding()], total_findings: 1 })));
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    await screen.findByText("Showing 1 of 1");
    expect(screen.queryByRole("button", { name: /Fix all/ })).not.toBeInTheDocument();
  });

  it("disables Apply fix when the code was edited after the review", async () => {
    const user = userEvent.setup();
    mockBackend(() => json(review({ findings: [finding()], total_findings: 1 })));
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    await screen.findByText("Showing 1 of 1");
    await user.type(screen.getByRole("textbox", { name: "Code" }), "# edit");
    expect(await screen.findByRole("button", { name: /Apply fix & re-check/ })).toBeDisabled();
  });

  it("explains when a fix cannot be applied automatically", async () => {
    const user = userEvent.setup();
    mockBackend(() => json(review({ findings: [finding({ line_start: 999, line_end: 999 })], total_findings: 1 })));
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    await screen.findByText("Showing 1 of 1");
    await user.click(screen.getByRole("button", { name: /Apply fix & re-check/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("could not be applied automatically");
  });

  it("exports Markdown, JSON and SARIF files", async () => {
    const user = userEvent.setup();
    mockBackend(() => json(review()));
    const downloads: string[] = [];
    const create = vi.fn((_blob: Blob) => "blob:x");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() }));
    const clicks = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      downloads.push(this.download);
    });
    render(<Home />);
    await loadVulnerableAndAnalyze(user);
    await screen.findByTestId("score");
    for (const name of ["Markdown", "JSON", "SARIF"]) await user.click(screen.getByRole("button", { name }));
    expect(downloads).toEqual(["codeshield-report.md", "codeshield-report.json", "codeshield.sarif"]);
    expect(create).toHaveBeenCalledTimes(3);
    clicks.mockRestore();
  });
});

