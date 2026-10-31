import { describe, expect, it } from "vitest";
import { finding, review } from "../test/fixtures";
import { applyAllFixes, applyFix, canApplyFix } from "./fix";
import { toJson, toMarkdown, toSarif } from "./report";

describe("applyFix", () => {
  const code = "import os\n\ndef run(f):\n    os.system('cat ' + f)\n    return 1\n";

  it("replaces the flagged line and keeps its indentation", () => {
    const f = finding({ line_start: 4, line_end: 4, suggested_code: "subprocess.run(['cat', f], check=True)" });
    expect(applyFix(code, f)).toBe("import os\n\ndef run(f):\n    subprocess.run(['cat', f], check=True)\n    return 1\n");
  });

  it("re-indents multi-line fixes relative to the original line", () => {
    const f = finding({ line_start: 4, line_end: 4, suggested_code: "if ok:\n    go()\n" });
    expect(applyFix(code, f)).toContain("    if ok:\n        go()\n    return 1");
  });

  it("does not double the indentation when the suggestion already has it", () => {
    const f = finding({ line_start: 4, line_end: 4, suggested_code: "    safe(f)" });
    expect(applyFix(code, f)).toContain("def run(f):\n    safe(f)\n    return 1");
  });

  it("replaces a line range", () => {
    const f = finding({ line_start: 4, line_end: 5, suggested_code: "return safe(f)" });
    expect(applyFix(code, f)).toBe("import os\n\ndef run(f):\n    return safe(f)\n");
  });

  it("preserves CRLF line endings", () => {
    const f = finding({ line_start: 2, line_end: 2, suggested_code: "b = 2" });
    expect(applyFix("a = 1\r\nbad()\r\nc = 3", f)).toBe("a = 1\r\nb = 2\r\nc = 3");
  });

  it("refuses when there is nothing to apply or the range does not fit", () => {
    expect(applyFix(code, finding({ suggested_code: null }))).toBeNull();
    expect(applyFix(code, finding({ line_start: null, suggested_code: "x" }))).toBeNull();
    expect(applyFix(code, finding({ line_start: 99, line_end: 99, suggested_code: "x" }))).toBeNull();
    expect(applyFix(code, finding({ line_start: 4, line_end: 2, suggested_code: "x" }))).toBeNull();
    expect(canApplyFix(finding({ suggested_code: "  " }))).toBe(false);
  });
});

describe("report export", () => {
  const result = review();

  it("markdown lists every finding, labels the source and keeps the disclaimer", () => {
    const md = toMarkdown(result);
    expect(md).toContain("# CodeShield AI review");
    expect(md).toContain("40/100 (grade D)");
    expect(md).toContain("Static analysis (Bandit)");
    expect(md).toContain("AI hypothesis (unverified)");
    expect(md).toContain("OWASP A03:2021 Injection");
    expect(md).toContain("No review can prove that code is secure");
    expect((md.match(/^### \d+\./gm) ?? []).length).toBe(result.findings.length);
  });

  it("markdown never claims code is secure when empty", () => {
    const md = toMarkdown(review({ findings: [], total_findings: 0 }));
    expect(md).toContain("not proof that the code is secure");
  });

  it("markdown fences survive backticks inside code", () => {
    const md = toMarkdown(review({ findings: [finding({ snippet: "x = ```y```" })], total_findings: 1 }));
    expect(md).toContain("````");
  });

  it("json round-trips", () => {
    expect(JSON.parse(toJson(result)).review_id).toBe(result.review_id);
  });

  it("sarif is valid 2.1.0 with levels, locations and rules", () => {
    const sarif = JSON.parse(toSarif(result));
    expect(sarif.version).toBe("2.1.0");
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("CodeShield AI");
    expect(run.results).toHaveLength(result.findings.length);
    const critical = run.results.find((r: { ruleId: string }) => r.ruleId === "B602");
    expect(critical.level).toBe("error");
    expect(critical.locations[0].physicalLocation.region.startLine).toBe(14);
    expect(critical.locations[0].physicalLocation.artifactLocation.uri).toBe("submission.py");
    const ai = run.results.find((r: { properties: { origin: string } }) => r.properties.origin === "ai_hypothesis");
    expect(ai.ruleId).toBe("ai/missing-authorization-check");
    expect(ai.level).toBe("warning");
    const ids = run.tool.driver.rules.map((r: { id: string }) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(run.tool.driver.rules[0].helpUri).toMatch(/^https:\/\/cwe\.mitre\.org\/data\/definitions\/\d+\.html$/);
  });
});

describe("applyAllFixes", () => {
  const fix = (id: string, start: number, end: number, code: string) =>
    ({ id, line_start: start, line_end: end, suggested_code: code }) as Parameters<typeof applyAllFixes>[1][number];
  const source = ["a = 1", "def f():", "    x = eval(s)", "    y = md5(p)", "    return x, y", "z = 3"].join("\n");

  it("applies every fix bottom-to-top so line numbers stay valid and indentation is kept", () => {
    const result = applyAllFixes(source, [fix("1", 3, 3, "x = safe(s)"), fix("2", 4, 4, "y = sha256(p)\nw = 0")]);
    expect(result.code.split("\n")).toEqual(["a = 1", "def f():", "    x = safe(s)", "    y = sha256(p)", "    w = 0", "    return x, y", "z = 3"]);
    expect(result.applied).toHaveLength(2);
    expect(result.skipped).toBe(0);
  });

  it("skips fixes that overlap an applied one and findings without usable fixes", () => {
    const result = applyAllFixes(source, [fix("1", 3, 4, "x = y = 0"), fix("2", 4, 4, "y = 1"), fix("3", 99, 99, "nope"), { id: "4", line_start: 1, line_end: 1, suggested_code: null } as never]);
    expect(result.applied.map((f) => f.id)).toEqual(["2"]);
    expect(result.skipped).toBe(2);
    expect(result.code).toContain("y = 1");
    expect(result.code).not.toContain("x = y = 0");
  });

  it("changes nothing when there is nothing to apply", () => {
    expect(applyAllFixes(source, [])).toEqual({ code: source, applied: [], skipped: 0 });
  });
});
