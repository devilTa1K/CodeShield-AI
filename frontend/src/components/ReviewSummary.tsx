import type { ReactNode } from "react";
import { downloadText, toJson, toMarkdown, toSarif } from "../lib/report";
import type { Health, ReviewResponse, ScannerStatus, Severity } from "../types";
import { LANGUAGES, SEVERITIES, SEVERITY_LABEL } from "../types";
import SeverityBadge from "./SeverityBadge";

const BAR: Record<Severity, string> = {
  critical: "bg-red-400",
  high: "bg-orange-400",
  medium: "bg-yellow-300",
  low: "bg-sky-400",
  info: "bg-slate-400",
};

const SCANNER_DOT: Record<ScannerStatus["status"], string> = {
  ran: "bg-emerald-400",
  failed: "bg-red-400",
  unavailable: "bg-yellow-300",
  skipped: "bg-ink-500",
};
const SCANNER_LABEL: Record<ScannerStatus["status"], string> = {
  ran: "Ran",
  failed: "Failed",
  unavailable: "Unavailable",
  skipped: "Skipped",
};

function Panel({ children }: { children: ReactNode }) {
  return <div className="flex h-full flex-col rounded-xl border border-ink-700 bg-ink-850 p-5">{children}</div>;
}

function StatusPill({ tone, children }: { tone: "idle" | "busy" | "good" | "warn"; children: ReactNode }) {
  const tones = {
    idle: "border-ink-600 text-ink-300",
    busy: "border-accent-500/60 text-accent-300",
    good: "border-emerald-400/50 text-emerald-300",
    warn: "border-yellow-400/50 text-yellow-200",
  } as const;
  return (
    <span className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${tones[tone]}`} role="status">
      {children}
    </span>
  );
}

function Spinner() {
  return (
    <svg className="animate-spin text-accent-400" width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

function Tile({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900 px-3 py-2.5">
      <div className="text-[11px] font-medium uppercase tracking-wide text-ink-400">{label}</div>
      <div className="mt-0.5 truncate text-lg font-semibold text-ink-100">{value}</div>
    </div>
  );
}

const GRADE_RING: Record<string, string> = {
  A: "border-emerald-400 text-emerald-300",
  B: "border-lime-400 text-lime-300",
  C: "border-yellow-300 text-yellow-200",
  D: "border-orange-400 text-orange-300",
  F: "border-red-400 text-red-300",
};

const EXPORT_BTN =
  "rounded-md border border-ink-600 bg-ink-800 px-3 py-1.5 text-xs font-medium text-ink-100 transition hover:border-ink-400 hover:bg-ink-700";

interface Props {
  result: ReviewResponse | null;
  loading: boolean;
  stale: boolean;
  health: Health | null;
  /** The review before the latest re-run, used to show an improvement delta. */
  previous?: ReviewResponse | null;
}

export default function ReviewSummary({ result, loading, stale, health, previous }: Props) {
  if (loading) {
    return (
      <Panel>
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold">Review</h2>
          <StatusPill tone="busy">Analyzing</StatusPill>
        </div>
        <div className="mt-6 flex items-center gap-3 text-sm text-ink-300">
          <Spinner />
          <span>Running static analysis{health?.ai_configured ? " and the AI review" : ""}. This can take up to a minute.</span>
        </div>
        <div className="mt-6 space-y-3" aria-hidden="true">
          {[80, 60, 70, 45].map((w) => (
            <div key={w} className="h-3 animate-pulse rounded bg-ink-700" style={{ width: `${w}%` }} />
          ))}
        </div>
      </Panel>
    );
  }

  if (!result) {
    return (
      <Panel>
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold">Review</h2>
          <StatusPill tone="idle">Ready</StatusPill>
        </div>
        <div className="flex flex-1 flex-col items-center justify-center py-10 text-center">
          <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-ink-600 bg-ink-800 text-accent-400">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M12 3 4.5 6v5.5c0 4.4 3.1 8 7.5 9.5 4.4-1.5 7.5-5.1 7.5-9.5V6L12 3Z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
              <path d="m9 12 2.2 2.2L15.5 10" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <p className="text-sm font-medium text-ink-100">No review yet</p>
          <p className="mt-1 max-w-xs text-sm text-ink-400">
            Paste code, or load the vulnerable sample, then choose <span className="text-ink-100">Analyze code</span> to see findings, explanations and fixes here.
          </p>
        </div>
      </Panel>
    );
  }

  const languageLabel = LANGUAGES.find((l) => l.value === result.language)?.label ?? result.language;
  const max = Math.max(1, ...SEVERITIES.map((s) => result.counts[s] ?? 0));
  const complete = result.status === "complete";
  const delta = previous ? { score: result.score - previous.score } : null;

  return (
    <Panel>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-base font-semibold">Review</h2>
        <StatusPill tone={complete ? "good" : "warn"}>{complete ? "Complete" : "Static analysis only"}</StatusPill>
      </div>

      {stale && (
        <p role="note" className="mt-3 rounded-lg border border-accent-500/40 bg-accent-500/10 px-3 py-2 text-xs text-accent-300">
          Your code has changed since this review. Re-run the review to refresh the results.
        </p>
      )}

      <div className="mt-4 flex items-center gap-4 rounded-lg border border-ink-700 bg-ink-900 px-4 py-3" data-testid="score">
        <div
          className={`flex h-14 w-14 shrink-0 flex-col items-center justify-center rounded-full border-2 ${GRADE_RING[result.grade] ?? "border-ink-500"}`}
          aria-hidden="true"
        >
          <span className="text-lg font-bold leading-none">{result.grade}</span>
        </div>
        <div className="min-w-0">
          <div className="text-[11px] font-medium uppercase tracking-wide text-ink-400">Review score</div>
          <div className="text-2xl font-semibold tabular-nums">
            {result.score}
            <span className="text-sm font-normal text-ink-400"> / 100 · grade {result.grade}</span>
          </div>
          {delta && (
            <div className="mt-0.5 text-xs text-ink-300" data-testid="score-delta" aria-live="polite">
              <span className={delta.score > 0 ? "text-emerald-300" : delta.score < 0 ? "text-red-300" : ""}>
                {delta.score > 0 ? "▲" : delta.score < 0 ? "▼" : "•"} {delta.score > 0 ? "+" : ""}
                {delta.score} points
              </span>{" "}
              · findings {previous!.total_findings} → {result.total_findings} since your last review
            </div>
          )}
          <p className="mt-0.5 text-[11px] text-ink-400">Reflects reported findings only. It is not proof that code is secure.</p>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-3 gap-2">
        <Tile label="Findings" value={result.total_findings} />
        <Tile label="Language" value={languageLabel} />
        <Tile label="Time" value={`${(result.duration_ms / 1000).toFixed(1)}s`} />
      </div>

      <ul className="mt-4 space-y-2" aria-label="Findings by severity">
        {SEVERITIES.map((s) => {
          const count = result.counts[s] ?? 0;
          return (
            <li key={s} className="grid grid-cols-[7.5rem_1fr_2rem] items-center gap-3">
              <SeverityBadge severity={s} className="justify-self-start" />
              <div className="h-1.5 overflow-hidden rounded-full bg-ink-700" aria-hidden="true">
                <div className={`h-full rounded-full ${BAR[s]}`} style={{ width: `${(count / max) * 100}%` }} />
              </div>
              <span className="text-right text-sm tabular-nums text-ink-100" aria-label={`${count} ${SEVERITY_LABEL[s]}`}>
                {count}
              </span>
            </li>
          );
        })}
      </ul>

      <section className="mt-5">
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-400">Summary</h3>
        <p className="text-sm leading-relaxed text-ink-100">{result.summary}</p>
      </section>

      {result.ai.status !== "ok" && (
        <p role="alert" className="mt-3 rounded-lg border border-yellow-400/40 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-100">
          <span className="font-semibold">AI review unavailable.</span> {result.ai.message} Scanner findings are still shown.
        </p>
      )}
      {result.ai.status === "ok" && result.ai.dropped_items > 0 && (
        <p className="mt-3 text-xs text-ink-400">
          {result.ai.dropped_items} malformed item(s) in the AI reply were discarded during validation.
        </p>
      )}

      {result.best_practices.length > 0 && (
        <section className="mt-5">
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-400">Secure coding practices</h3>
          <ul className="list-disc space-y-1 pl-5 text-sm text-ink-300">
            {result.best_practices.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </section>
      )}

      <section className="mt-5">
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-400">Analyzers</h3>
        <ul className="space-y-1.5 text-sm">
          {result.scanners.map((s) => (
            <li key={s.name} className="flex flex-wrap items-center gap-x-2 text-ink-300" title={s.detail ?? undefined}>
              <span className={`h-2 w-2 rounded-full ${SCANNER_DOT[s.status]}`} aria-hidden="true" />
              <span className="text-ink-100">{s.name}</span>
              <span className="text-xs">{SCANNER_LABEL[s.status]}{s.status === "ran" ? ` · ${s.findings}` : ""}</span>
            </li>
          ))}
          <li className="flex flex-wrap items-center gap-x-2 text-ink-300">
            <span className={`h-2 w-2 rounded-full ${result.ai.status === "ok" ? "bg-emerald-400" : "bg-yellow-300"}`} aria-hidden="true" />
            <span className="text-ink-100">BharatCode AI</span>
            <span className="text-xs">{result.ai.status === "ok" ? `Ran · ${result.ai.model}` : result.ai.status === "not_configured" ? "Not configured" : "Failed"}</span>
          </li>
        </ul>
      </section>

      <section className="mt-5" aria-label="Export report">
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-400">Export report</h3>
        <div className="flex flex-wrap gap-2">
          <button type="button" className={EXPORT_BTN} onClick={() => downloadText("codeshield-report.md", toMarkdown(result), "text/markdown")}>
            Markdown
          </button>
          <button type="button" className={EXPORT_BTN} onClick={() => downloadText("codeshield-report.json", toJson(result), "application/json")}>
            JSON
          </button>
          <button
            type="button"
            className={EXPORT_BTN}
            title="SARIF 2.1.0, importable by GitHub code scanning and IDEs"
            onClick={() => downloadText("codeshield.sarif", toSarif(result), "application/sarif+json")}
          >
            SARIF
          </button>
        </div>
      </section>

      <p className="mt-auto pt-5 text-xs leading-relaxed text-ink-400">{result.disclaimer}</p>
    </Panel>
  );
}
