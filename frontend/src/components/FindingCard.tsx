import { useId, useState } from "react";
import { canApplyFix } from "../lib/fix";
import type { Finding } from "../types";
import CopyButton from "./CopyButton";
import SeverityBadge from "./SeverityBadge";

function lineLabel(f: Finding): string | null {
  if (!f.line_start) return null;
  return f.line_end && f.line_end !== f.line_start ? `Lines ${f.line_start}–${f.line_end}` : `Line ${f.line_start}`;
}

export function OriginBadge({ finding }: { finding: Finding }) {
  if (finding.origin === "static_analysis") {
    return (
      <span
        className="inline-flex items-center gap-1.5 rounded-md border border-ink-500 bg-ink-700 px-2 py-0.5 text-xs font-medium text-ink-100"
        title="Reported by a scanner rule. It is a rule match that still needs your review, not proof of exploitability."
      >
        <svg width="11" height="11" viewBox="0 0 12 12" fill="none" aria-hidden="true">
          <path d="M6 1 2 2.6v3c0 2.4 1.7 4.2 4 5.2 2.3-1 4-2.8 4-5.2v-3L6 1Z" stroke="currentColor" strokeWidth="1.2" />
        </svg>
        Static analysis · {finding.tool}
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md border border-dashed border-accent-400/60 bg-accent-500/10 px-2 py-0.5 text-xs font-medium text-accent-300"
      title="Proposed by the AI model. It is an unverified hypothesis: confirm it in your code before acting."
    >
      <svg width="11" height="11" viewBox="0 0 12 12" fill="none" aria-hidden="true">
        <path d="M6 1.5v2M6 8.5v2M1.5 6h2M8.5 6h2M3 3l1.4 1.4M7.6 7.6 9 9M9 3 7.6 4.4M4.4 7.6 3 9" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      </svg>
      AI hypothesis · unverified
    </span>
  );
}

function CodeBlock({ title, code, copy }: { title: string; code: string; copy?: boolean }) {
  return (
    <div className="min-w-0 rounded-lg border border-ink-700 bg-ink-900">
      <div className="flex items-center justify-between gap-2 border-b border-ink-700 px-3 py-1.5">
        <span className="text-xs font-medium text-ink-300">{title}</span>
        {copy && <CopyButton text={code} label="Copy fix" title="Copy the suggested replacement code" />}
      </div>
      {/* Rendered as text by React, never as HTML. */}
      <pre className="scroll-thin overflow-x-auto p-3 font-mono text-[12.5px] leading-relaxed text-ink-100">
        <code>{code}</code>
      </pre>
    </div>
  );
}

interface CardProps {
  finding: Finding;
  defaultOpen?: boolean;
  /** Patch the editor with this finding's suggested code and re-run the review. */
  onApplyFix?: (finding: Finding) => void;
  /** False while a review is running or the editor no longer matches the reviewed code. */
  canApply?: boolean;
}

function cweUrl(cwe: string): string | null {
  const n = /^CWE-(\d{1,5})$/.exec(cwe)?.[1];
  return n ? `https://cwe.mitre.org/data/definitions/${n}.html` : null;
}

export default function FindingCard({ finding, defaultOpen = false, onApplyFix, canApply = true }: CardProps) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();
  const lines = lineLabel(finding);

  return (
    <article className="animate-rise rounded-xl border border-ink-700 bg-ink-850 [overflow-wrap:anywhere]" data-testid="finding-card">
      <h3>
        <button
          type="button"
          className="flex w-full flex-wrap items-center gap-x-3 gap-y-2 rounded-xl px-4 py-3.5 text-left hover:bg-ink-800"
          aria-expanded={open}
          aria-controls={panelId}
          onClick={() => setOpen((v) => !v)}
        >
          <SeverityBadge severity={finding.severity} />
          <span className="min-w-0 flex-1 basis-60 text-sm font-semibold text-ink-100">{finding.title}</span>
          <span className="flex flex-wrap items-center gap-2 text-xs text-ink-400">
            {lines && <span className="font-mono">{lines}</span>}
            <span>{finding.category}</span>
            {finding.cwe && <span className="font-mono">{finding.cwe}</span>}
          </span>
          <svg
            width="14"
            height="14"
            viewBox="0 0 14 14"
            fill="none"
            aria-hidden="true"
            className={`text-ink-400 transition-transform ${open ? "rotate-180" : ""}`}
          >
            <path d="m3 5 4 4 4-4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </button>
      </h3>

      {open && (
        <div id={panelId} className="space-y-4 border-t border-ink-700 px-4 pb-4 pt-4">
          <div className="flex flex-wrap items-center gap-2">
            <OriginBadge finding={finding} />
            <span className="text-xs text-ink-400">Confidence: {finding.confidence}</span>
            {finding.rule_id && <span className="font-mono text-xs text-ink-400">{finding.rule_id}</span>}
            {finding.cwe && (
              <a
                href={cweUrl(finding.cwe) ?? undefined}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-md border border-ink-600 px-2 py-0.5 font-mono text-xs text-ink-300 hover:border-ink-400 hover:text-ink-100"
                title="Open the CWE entry in a new tab"
              >
                {finding.cwe} ↗
              </a>
            )}
            {finding.owasp && (
              <span className="rounded-md border border-ink-600 px-2 py-0.5 text-xs text-ink-300" title="OWASP Top 10 (2021) category">
                OWASP {finding.owasp}
              </span>
            )}
          </div>

          <p className="text-sm leading-relaxed text-ink-300">{finding.description}</p>

          {finding.explanation && (
            <section>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-400">In plain words</h4>
              <p className="text-sm leading-relaxed text-ink-100">{finding.explanation}</p>
            </section>
          )}
          {finding.why_it_matters && (
            <section>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-400">Why it matters</h4>
              <p className="text-sm leading-relaxed text-ink-100">{finding.why_it_matters}</p>
            </section>
          )}
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-400">Recommended fix</h4>
            <p className="text-sm leading-relaxed text-ink-100">{finding.recommendation}</p>
          </section>

          {(finding.snippet || finding.suggested_code) && (
            <div className={`grid grid-cols-[minmax(0,1fr)] gap-3 ${finding.snippet && finding.suggested_code ? "md:grid-cols-2" : ""}`}>
              {finding.snippet && <CodeBlock title={`Your code${lines ? ` · ${lines.toLowerCase()}` : ""}`} code={finding.snippet} />}
              {finding.suggested_code && <CodeBlock title="Suggested replacement" code={finding.suggested_code} copy />}
            </div>
          )}
          {onApplyFix && canApplyFix(finding) && (
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => onApplyFix(finding)}
                disabled={!canApply}
                className="rounded-md bg-accent-500 px-3 py-1.5 text-xs font-semibold text-ink-950 transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:bg-ink-700 disabled:text-ink-400"
              >
                Apply fix &amp; re-check
              </button>
              <span className="text-xs text-ink-400">
                {canApply
                  ? "Replaces the flagged lines in the editor, then re-runs the review. Review the change before you rely on it."
                  : "Re-run the review on your current code to apply fixes."}
              </span>
            </div>
          )}
          {finding.snippet && !finding.suggested_code && (
            <p className="text-xs text-ink-400">
              No replacement code was suggested for this finding. Apply the recommendation above, then re-run the review.
            </p>
          )}
        </div>
      )}
    </article>
  );
}
