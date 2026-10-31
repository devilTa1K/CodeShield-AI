import type { Finding, ReviewResponse } from "../types";

export function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "S1",
    title: "Use of eval (B307)",
    severity: "high",
    category: "Code execution",
    origin: "static_analysis",
    tool: "Bandit",
    rule_id: "B307",
    cwe: "CWE-78",
    owasp: "A03:2021 Injection",
    line_start: 26,
    line_end: 26,
    snippet: "    return eval(expr)",
    description: "Use of possibly insecure function - consider using safer ast.literal_eval.",
    explanation: "eval runs text as code, so whoever controls the text controls your program.",
    why_it_matters: "An attacker could run arbitrary commands.",
    recommendation: "Parse the expression with ast.literal_eval instead.",
    suggested_code: "    return ast.literal_eval(expr)",
    confidence: "high",
    ai_explained: true,
    ...overrides,
  };
}

export function review(overrides: Partial<ReviewResponse> = {}): ReviewResponse {
  const findings = overrides.findings ?? [
    finding({ id: "S1", severity: "critical", title: "Subprocess with shell=True (B602)", category: "Injection", rule_id: "B602", line_start: 14, line_end: 14, snippet: 'subprocess.call("cat " + filename, shell=True)', suggested_code: 'subprocess.run(["cat", filename], check=True)' }),
    finding({ id: "S2", severity: "high" }),
    finding({
      id: "A1",
      severity: "medium",
      origin: "ai_hypothesis",
      tool: "BharatCode AI",
      rule_id: null,
      cwe: "CWE-862",
      title: "Missing authorization check",
      category: "Access control",
      line_start: 9,
      line_end: 9,
      snippet: "return conn.execute(query).fetchall()",
      confidence: "low",
      suggested_code: null,
    }),
  ];
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return {
    review_id: "abc123",
    status: "complete",
    language: "python",
    explain_language: "english",
    score: 40,
    grade: "D",
    total_findings: findings.length,
    counts,
    summary: "Three issues need attention before this code is used.",
    best_practices: ["Validate all external input"],
    findings,
    scanners: [
      { name: "CodeShield rules", status: "skipped", findings: 0, detail: "Python uses Bandit." },
      { name: "Bandit", status: "ran", findings: 2, detail: null },
      { name: "Semgrep", status: "skipped", findings: 0, detail: "Set SEMGREP_CONFIG" },
    ],
    ai: { status: "ok", model: "qwen-3.8-27b", error_code: null, message: null, dropped_items: 0 },
    disclaimer: "This review is automated assistance, not a guarantee. No review can prove that code is secure.",
    duration_ms: 2300,
    ...overrides,
  };
}

export const HEALTH = { status: "ok", version: "0.1.0", ai_configured: true, model: "qwen-3.8-27b", max_code_chars: 40000 };

type Handler = (url: string, init?: RequestInit) => Response | Promise<Response>;

/** Install a fetch mock that answers /health and delegates /api/review to `onReview`. */
export function mockBackend(onReview: Handler, health: Response | (() => Response) = () => json(HEALTH)) {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/health")) return typeof health === "function" ? health() : health;
    if (url.endsWith("/api/review")) return onReview(url, init);
    throw new Error(`unexpected fetch ${url}`);
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
