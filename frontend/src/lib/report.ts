import type { Finding, ReviewResponse, Severity } from "../types";
import { SEVERITIES, SEVERITY_LABEL } from "../types";

const EXTENSIONS: Record<string, string> = { python: "py", javascript: "js", typescript: "ts", java: "java", c: "c" };

export function artifactName(language: string): string {
  return `submission.${EXTENSIONS[language] ?? "txt"}`;
}

function fence(code: string, lang: string): string {
  const ticks = "`".repeat(Math.max(3, ...[...code.matchAll(/`+/g)].map((m) => m[0].length + 1)));
  return `${ticks}${lang}\n${code}\n${ticks}`;
}

function lineLabel(f: Finding): string {
  if (!f.line_start) return "";
  return f.line_end && f.line_end !== f.line_start ? `lines ${f.line_start}-${f.line_end}` : `line ${f.line_start}`;
}

export function toMarkdown(result: ReviewResponse): string {
  const out: string[] = [];
  out.push("# CodeShield AI review", "");
  out.push(
    `- **Language:** ${result.language}`,
    `- **Review score:** ${result.score}/100 (grade ${result.grade}); this summarizes reported findings only and is not proof of security`,
    `- **Findings:** ${result.total_findings} (${SEVERITIES.map((s) => `${result.counts[s] ?? 0} ${SEVERITY_LABEL[s].toLowerCase()}`).join(", ")})`,
    `- **Status:** ${result.status === "complete" ? "Static analysis and AI review" : "Static analysis only"}`,
    "",
    "## Summary",
    "",
    result.summary,
    "",
  );
  if (result.best_practices.length) {
    out.push("## Secure coding practices", "", ...result.best_practices.map((p) => `- ${p}`), "");
  }
  out.push("## Findings", "");
  if (!result.findings.length) out.push("_No findings were reported. That is not proof that the code is secure._", "");
  result.findings.forEach((f, i) => {
    const where = lineLabel(f);
    out.push(`### ${i + 1}. [${SEVERITY_LABEL[f.severity]}] ${f.title}`, "");
    out.push(
      `- **Source:** ${f.origin === "static_analysis" ? `Static analysis (${f.tool})` : "AI hypothesis (unverified)"}`,
      `- **Category:** ${f.category}${f.cwe ? ` · ${f.cwe}` : ""}${f.owasp ? ` · OWASP ${f.owasp}` : ""}`,
      ...(where ? [`- **Location:** ${where}`] : []),
      `- **Confidence:** ${f.confidence}`,
      "",
      f.description,
      "",
    );
    if (f.explanation) out.push(`**In plain words:** ${f.explanation}`, "");
    if (f.why_it_matters) out.push(`**Why it matters:** ${f.why_it_matters}`, "");
    out.push(`**Recommended fix:** ${f.recommendation}`, "");
    if (f.snippet) out.push("Your code:", "", fence(f.snippet, result.language), "");
    if (f.suggested_code) out.push("Suggested replacement:", "", fence(f.suggested_code, result.language), "");
  });
  out.push("---", "", result.disclaimer, "");
  return out.join("\n");
}

export function toJson(result: ReviewResponse): string {
  return JSON.stringify(result, null, 2);
}

const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

function ruleIdOf(f: Finding): string {
  if (f.rule_id) return f.rule_id;
  return `ai/${f.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "finding"}`;
}

/** SARIF 2.1.0, the format GitHub code scanning and many IDEs import. */
export function toSarif(result: ReviewResponse): string {
  const uri = artifactName(result.language);
  const rules = new Map<string, object>();
  for (const f of result.findings) {
    const id = ruleIdOf(f);
    if (rules.has(id)) continue;
    const cweNumber = f.cwe?.match(/\d+/)?.[0];
    rules.set(id, {
      id,
      name: f.title,
      shortDescription: { text: f.title },
      fullDescription: { text: f.description },
      help: { text: f.recommendation },
      ...(cweNumber ? { helpUri: `https://cwe.mitre.org/data/definitions/${cweNumber}.html` } : {}),
      properties: { tags: [f.category, ...(f.cwe ? [f.cwe] : []), ...(f.owasp ? [`OWASP ${f.owasp}`] : [])] },
    });
  }

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "CodeShield AI", informationUri: "https://github.com/devilTa1K/CodeShield-AI", rules: [...rules.values()] } },
        artifacts: [{ location: { uri } }],
        results: result.findings.map((f) => ({
          ruleId: ruleIdOf(f),
          level: SARIF_LEVEL[f.severity],
          message: { text: `${f.title}: ${f.description}` },
          ...(f.line_start
            ? {
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri },
                      region: {
                        startLine: f.line_start,
                        endLine: f.line_end ?? f.line_start,
                        ...(f.snippet ? { snippet: { text: f.snippet } } : {}),
                      },
                    },
                  },
                ],
              }
            : {}),
          properties: {
            origin: f.origin,
            tool: f.tool,
            confidence: f.confidence,
            severity: f.severity,
            ...(f.owasp ? { owasp: f.owasp } : {}),
          },
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

export function downloadText(filename: string, text: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
