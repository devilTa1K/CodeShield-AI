import type { Finding } from "../types";

const MAX_REPLACED_LINES = 60;

function indentOf(line: string): string {
  return /^[ \t]*/.exec(line)?.[0] ?? "";
}

/** Remove the indentation shared by every non-empty line. */
function dedent(lines: string[]): string[] {
  const indents = lines.filter((l) => l.trim()).map((l) => indentOf(l).length);
  const common = indents.length ? Math.min(...indents) : 0;
  return lines.map((l) => (l.trim() ? l.slice(common) : ""));
}

/** Whether a finding has everything needed to patch the code automatically. */
export function canApplyFix(finding: Finding): boolean {
  return Boolean(finding.suggested_code?.trim()) && finding.line_start !== null && finding.line_start > 0;
}

/**
 * Replace the finding's lines with its suggested code, keeping the original indentation.
 * Returns null when the line range does not fit the code (for example the code was edited).
 * The caller must pass the exact code that was reviewed, or line numbers will not line up.
 */
export function applyFix(code: string, finding: Finding): string | null {
  if (!canApplyFix(finding)) return null;
  const eol = code.includes("\r\n") ? "\r\n" : "\n";
  const lines = code.split(/\r?\n/);
  const start = finding.line_start as number;
  const end = finding.line_end ?? start;
  if (start > lines.length || end < start || end - start + 1 > MAX_REPLACED_LINES) return null;

  const suggestion = (finding.suggested_code as string).replace(/^\n+|\s+$/g, "").split(/\r?\n/);
  const indent = indentOf(lines[start - 1]);
  const replacement = dedent(suggestion).map((l) => (l ? indent + l : l));

  return [...lines.slice(0, start - 1), ...replacement, ...lines.slice(end)].join(eol);
}

export interface FixAllResult {
  /** The code with every non-overlapping fix applied. */
  code: string;
  applied: Finding[];
  /** Fixable findings that were left alone because they overlap another fix or no longer fit the code. */
  skipped: number;
}

/**
 * Apply every fixable finding at once. Fixes are applied bottom-to-top so earlier line numbers stay
 * valid, and a fix that overlaps one already applied is skipped instead of guessing.
 */
export function applyAllFixes(code: string, findings: Finding[]): FixAllResult {
  const candidates = findings
    .filter(canApplyFix)
    .sort((a, b) => (b.line_start as number) - (a.line_start as number) || (b.line_end ?? 0) - (a.line_end ?? 0));
  let current = code;
  let lowestApplied = Infinity;
  const applied: Finding[] = [];
  for (const finding of candidates) {
    const end = finding.line_end ?? (finding.line_start as number);
    if (end >= lowestApplied) continue; // overlaps a fix that is already in
    const patched = applyFix(current, finding);
    if (patched === null) continue;
    current = patched;
    lowestApplied = finding.line_start as number;
    applied.push(finding);
  }
  return { code: current, applied, skipped: candidates.length - applied.length };
}
