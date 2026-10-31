import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import CodeEditor, { EDITOR_ID } from "../components/CodeEditor";
import CopyButton from "../components/CopyButton";
import FindingsList from "../components/FindingsList";
import ReviewSummary from "../components/ReviewSummary";
import { SAMPLES } from "../samples";
import { ApiError, getHealth, reviewCode } from "../services/api";
import { applyAllFixes, applyFix, canApplyFix } from "../lib/fix";
import type { ExplainLanguage, Finding, Health, Language, ReviewResponse, Severity } from "../types";
import { EXPLAIN_LANGUAGES, LANGUAGES, SEVERITIES } from "../types";

const DEFAULT_MAX_CHARS = 40_000;

function Logo() {
  return (
    <div className="flex items-center gap-3">
      <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-accent-500/50 bg-ink-850 text-accent-400">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 3 4.5 6v5.5c0 4.4 3.1 8 7.5 9.5 4.4-1.5 7.5-5.1 7.5-9.5V6L12 3Z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
          <path d="m9 12 2.2 2.2L15.5 10" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
      <div className="leading-tight">
        <div className="text-[15px] font-semibold tracking-tight">
          CodeShield <span className="text-accent-400">AI</span>
        </div>
        <div className="text-xs text-ink-400">Secure code review</div>
      </div>
    </div>
  );
}

function HealthBadge({ health, checked }: { health: Health | null; checked: boolean }) {
  if (!checked) return <span className="text-xs text-ink-400">Checking backend…</span>;
  if (!health) {
    return (
      <span className="inline-flex items-center gap-2 text-xs text-red-200" role="status">
        <span className="h-2 w-2 rounded-full bg-red-400" aria-hidden="true" /> Backend offline
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-2 text-xs text-ink-300" role="status">
      <span className={`h-2 w-2 rounded-full ${health.ai_configured ? "bg-emerald-400" : "bg-yellow-300"}`} aria-hidden="true" />
      {health.ai_configured ? `Backend online · AI ready (${health.model})` : "Backend online · AI key not set, static analysis only"}
    </span>
  );
}

export default function Home() {
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState<Language>("python");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ReviewResponse | null>(null);
  const [reviewedCode, setReviewedCode] = useState<string | null>(null);
  const [previous, setPrevious] = useState<ReviewResponse | null>(null);
  const [explainLanguage, setExplainLanguage] = useState<ExplainLanguage>("english");
  const [error, setError] = useState<ApiError | null>(null);
  const [fixNote, setFixNote] = useState<string | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [healthChecked, setHealthChecked] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    let active = true;
    getHealth()
      .then((h) => active && setHealth(h))
      .catch(() => active && setHealth(null))
      .finally(() => active && setHealthChecked(true));
    return () => {
      active = false;
      abortRef.current?.abort();
    };
  }, []);

  const maxChars = health?.max_code_chars ?? DEFAULT_MAX_CHARS;
  const overLimit = code.length > maxChars;
  const empty = code.trim().length === 0;
  const stale = result !== null && reviewedCode !== null && code !== reviewedCode;

  const flaggedLines = useMemo(() => {
    if (!result || stale) return undefined;
    const map = new Map<number, Severity>();
    for (const f of result.findings) {
      if (!f.line_start) continue;
      const end = f.line_end ?? f.line_start;
      for (let line = f.line_start; line <= end; line++) {
        const current = map.get(line);
        if (!current || SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(current)) map.set(line, f.severity);
      }
    }
    return map;
  }, [result, stale]);

  const runReview = useCallback(
    async (submitted: string) => {
      if (loading || submitted.trim().length === 0 || submitted.length > maxChars) return;
      const controller = new AbortController();
      abortRef.current = controller;
      setLoading(true);
      setError(null);
      try {
        const response = await reviewCode(
          { code: submitted, language, explain_language: explainLanguage },
          { signal: controller.signal },
        );
        // Keep the last review of *different* code so the dashboard can show the improvement.
        if (result && reviewedCode !== submitted) setPrevious(result);
        else if (!result) setPrevious(null);
        setResult(response);
        setReviewedCode(submitted);
      } catch (err) {
        if (err instanceof DOMException && err.name === "AbortError") return; // cancelled by the user
        setError(err instanceof ApiError ? err : new ApiError("unknown", "Something went wrong. Please try again."));
      } finally {
        setLoading(false);
        abortRef.current = null;
      }
    },
    [explainLanguage, language, loading, maxChars, result, reviewedCode],
  );

  const analyze = useCallback(() => runReview(code), [code, runReview]);

  const applySuggestedFix = useCallback(
    (finding: Finding) => {
      if (stale || loading || !result) return;
      const patched = applyFix(code, finding);
      if (patched === null) {
        setError(new ApiError("fix_not_applicable", "This fix could not be applied automatically. Copy it and edit the code by hand."));
        return;
      }
      setCode(patched);
      void runReview(patched);
    },
    [code, loading, result, runReview, stale],
  );

  const fixableCount = useMemo(() => (result ? result.findings.filter(canApplyFix).length : 0), [result]);

  const applyAllSuggestedFixes = useCallback(() => {
    if (stale || loading || !result) return;
    const { code: patched, applied, skipped } = applyAllFixes(code, result.findings);
    if (applied.length === 0) {
      setError(new ApiError("fix_not_applicable", "These fixes could not be applied automatically. Copy them and edit the code by hand."));
      return;
    }
    setFixNote(
      `Applied ${applied.length} of ${applied.length + skipped} fixes${skipped ? ` (${skipped} skipped because they overlap or no longer fit)` : ""}. ` +
        "The scanners re-checked the patched code; compare the score below, and run your own tests before relying on the changes.",
    );
    setCode(patched);
    void runReview(patched);
  }, [code, loading, result, runReview, stale]);

  function loadSample(kind: "vulnerable" | "safe") {
    setCode(SAMPLES[language][kind]);
    setFixNote(null);
    setError(null);
    setPrevious(null);
  }

  const hasResult = result !== null;

  return (
    <div className="min-h-screen">
      <header className="border-b border-ink-700/80 bg-ink-950/70 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3.5 sm:px-6">
          <Logo />
          <HealthBadge health={health} checked={healthChecked} />
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6 sm:py-8">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">Review code for security problems</h1>
          <p className="mt-1.5 max-w-2xl text-sm text-ink-300">
            Static analysis finds rule matches; the BharatCode AI explains them and proposes fixes. Your code is only read, never executed.
          </p>
        </div>

        <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
          <section aria-labelledby="editor-heading" className="min-w-0 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <label id="editor-heading" htmlFor={EDITOR_ID} className="text-base font-semibold">
                Code
              </label>
              <div className="flex flex-wrap items-center gap-2">
                <label htmlFor="language" className="sr-only">
                  Language
                </label>
                <select
                  id="language"
                  value={language}
                  onChange={(e) => setLanguage(e.target.value as Language)}
                  className="rounded-md border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-sm text-ink-100"
                >
                  {LANGUAGES.map((l) => (
                    <option key={l.value} value={l.value}>
                      {l.label}
                    </option>
                  ))}
                </select>
                <label htmlFor="explain-language" className="sr-only">
                  Explain in
                </label>
                <select
                  id="explain-language"
                  value={explainLanguage}
                  onChange={(e) => setExplainLanguage(e.target.value as ExplainLanguage)}
                  title="Language of the AI explanations"
                  className="rounded-md border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-sm text-ink-100"
                >
                  {EXPLAIN_LANGUAGES.map((l) => (
                    <option key={l.value} value={l.value}>
                      Explain in {l.label}
                    </option>
                  ))}
                </select>
                <button type="button" onClick={() => loadSample("vulnerable")} className="rounded-md border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs font-medium hover:border-ink-400">
                  Vulnerable sample
                </button>
                <button type="button" onClick={() => loadSample("safe")} className="rounded-md border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs font-medium hover:border-ink-400">
                  Safe sample
                </button>
              </div>
            </div>

            <div
              onKeyDown={(e) => {
                if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
                  e.preventDefault();
                  void analyze();
                }
              }}
            >
              <CodeEditor value={code} onChange={(v) => { setCode(v); setFixNote(null); }} language={language} flaggedLines={flaggedLines} disabled={loading} />
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3 text-xs text-ink-400">
                <span className={overLimit ? "text-red-300" : ""}>
                  {code.length.toLocaleString()} / {maxChars.toLocaleString()} characters
                </span>
                {!empty && <CopyButton text={code} label="Copy code" />}
                {!empty && (
                  <button type="button" onClick={() => setCode("")} className="underline-offset-2 hover:text-ink-100 hover:underline">
                    Clear
                  </button>
                )}
              </div>

              <div className="flex items-center gap-2">
                {loading && (
                  <button type="button" onClick={() => abortRef.current?.abort()} className="rounded-md border border-ink-600 px-3 py-2 text-sm font-medium hover:border-ink-400">
                    Cancel
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => void analyze()}
                  disabled={loading || empty || overLimit}
                  className="rounded-md bg-accent-500 px-4 py-2 text-sm font-semibold text-ink-950 shadow-sm transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:bg-ink-700 disabled:text-ink-400"
                >
                  {loading ? "Analyzing…" : hasResult ? "Re-run review" : "Analyze code"}
                </button>
              </div>
            </div>
            <p className="text-xs text-ink-400">
              Tip: press <kbd className="rounded border border-ink-600 px-1 font-mono">Ctrl</kbd>/<kbd className="rounded border border-ink-600 px-1 font-mono">⌘</kbd> + <kbd className="rounded border border-ink-600 px-1 font-mono">Enter</kbd> to run. Likely secrets are redacted before code is sent to the AI.
            </p>

            {fixNote && !error && (
              <p role="status" className="rounded-lg border border-emerald-400/30 bg-emerald-500/10 px-4 py-3 text-xs text-emerald-100">
                {fixNote}
              </p>
            )}

            {error && (
              <div role="alert" className="flex flex-wrap items-start justify-between gap-3 rounded-lg border border-red-400/40 bg-red-500/10 px-4 py-3 text-sm text-red-100">
                <div>
                  <p className="font-semibold">Review failed</p>
                  <p className="mt-0.5 text-red-100/90">{error.message}</p>
                </div>
                {!["empty_code", "unsupported_language", "code_too_large", "fix_not_applicable"].includes(error.code) && (
                  <button type="button" onClick={() => void analyze()} className="rounded-md border border-red-300/40 px-3 py-1.5 text-xs font-medium hover:bg-red-500/10">
                    Try again
                  </button>
                )}
              </div>
            )}
          </section>

          <ReviewSummary result={result} loading={loading} stale={stale} health={health} previous={previous} />
        </div>

        {hasResult && result.findings.length > 0 && (
          <FindingsList
            key={result.review_id}
            findings={result.findings}
            onApplyFix={applySuggestedFix}
            canApply={!stale && !loading}
            onApplyAll={applyAllSuggestedFixes}
            fixableCount={fixableCount}
          />
        )}
        {hasResult && result.findings.length === 0 && (
          <section className="rounded-xl border border-ink-700 bg-ink-850 p-6 text-center">
            <h2 className="text-base font-semibold">No findings reported</h2>
            <p className="mx-auto mt-1 max-w-xl text-sm text-ink-300">
              The analyzers did not report anything for this code. That is not proof that it is secure: scanners miss issues, and the AI review is only as good as what it can see. Keep reviewing manually.
            </p>
          </section>
        )}
      </main>

      <footer className="mx-auto max-w-7xl px-4 pb-10 pt-4 text-xs text-ink-400 sm:px-6">
        CodeShield AI assists code review and does not replace a security audit. Built for the BharatCode Build League.
      </footer>
    </div>
  );
}
