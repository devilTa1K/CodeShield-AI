import { useMemo, useRef, useState } from "react";
import type { DragEvent } from "react";
import FindingCard from "../components/FindingCard";
import SeverityBadge from "../components/SeverityBadge";
import { MAX_ZIP_BYTES } from "../scanTypes";
import type { ProjectScanResponse, ScanFinding } from "../scanTypes";
import { ApiError } from "../services/api";
import { scanGithub, scanProject } from "../services/scanApi";
import { SEVERITIES, SEVERITY_LABEL } from "../types";
import type { Severity } from "../types";
import { downloadText } from "../lib/report";

const GRADE_TONE: Record<string, string> = {
  A: "text-emerald-300 border-emerald-400/60",
  B: "text-lime-300 border-lime-400/60",
  C: "text-yellow-200 border-yellow-400/60",
  D: "text-orange-300 border-orange-400/60",
  F: "text-red-300 border-red-400/60",
};

function formatSize(bytes: number): string {
  return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

function Stat({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900/60 px-3.5 py-3">
      <div className="text-[11px] font-medium uppercase tracking-wide text-ink-400">{label}</div>
      <div className="mt-1 text-xl font-semibold">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-ink-400">{hint}</div>}
    </div>
  );
}

function Results({ result }: { result: ProjectScanResponse }) {
  const [severity, setSeverity] = useState<"all" | Severity>("all");

  const visible = useMemo(
    () => result.findings.filter((f) => severity === "all" || f.severity === severity),
    [result.findings, severity],
  );
  const groups = useMemo(() => {
    const map = new Map<string, ScanFinding[]>();
    for (const f of visible) map.set(f.file, [...(map.get(f.file) ?? []), f]);
    return [...map.entries()];
  }, [visible]);

  const deps = result.dependencies;
  const chip = (active: boolean) =>
    `rounded-md border px-2.5 py-1 text-xs font-medium transition ${
      active ? "border-accent-500 bg-accent-500/15 text-accent-300" : "border-ink-600 bg-ink-800 text-ink-300 hover:border-ink-400"
    }`;

  return (
    <div className="space-y-6">
      <section aria-label="Scan summary" className="rounded-xl border border-ink-700 bg-ink-850 p-5">
        <div className="flex flex-wrap items-center gap-5">
          <div
            className={`flex h-16 w-16 items-center justify-center rounded-full border-2 text-2xl font-bold ${GRADE_TONE[result.grade] ?? GRADE_TONE.F}`}
            aria-label={`Grade ${result.grade}`}
          >
            {result.grade}
          </div>
          <div>
            <div className="text-xs font-medium uppercase tracking-wide text-ink-400">
              Project score{result.source && <span className="normal-case tracking-normal"> · {result.source}</span>}
            </div>
            <div className="text-2xl font-semibold">
              {result.score}
              <span className="text-sm font-normal text-ink-400"> / 100</span>
            </div>
            <p className="text-xs text-ink-400">Reflects reported findings only. It is not proof that the project is secure.</p>
          </div>
          <button
            type="button"
            onClick={() => downloadText(`codeshield-scan-${result.scan_id}.json`, JSON.stringify(result, null, 2), "application/json")}
            className="ml-auto rounded-md border border-ink-600 bg-ink-800 px-3 py-1.5 text-xs font-medium hover:border-ink-400"
          >
            Download JSON report
          </button>
        </div>

        <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="Files scanned" value={result.files_scanned} hint={Object.entries(result.languages).map(([l, n]) => `${n} ${l}`).join(" · ") || undefined} />
          <Stat label="Findings" value={result.total_findings} />
          <Stat
            label="Vulnerable packages"
            value={deps.status === "ok" ? deps.vulnerable : "—"}
            hint={deps.status === "ok" ? `of ${deps.checked} checked` : deps.status === "none" ? "no manifests" : "check unavailable"}
          />
          <Stat label="Time" value={`${(result.duration_ms / 1000).toFixed(1)}s`} />
        </div>

        <ul className="mt-5 flex flex-wrap gap-x-5 gap-y-2" aria-label="Findings by severity">
          {SEVERITIES.map((s) => (
            <li key={s} className="flex items-center gap-2 text-sm">
              <SeverityBadge severity={s} />
              <span className="font-mono">{result.counts[s]}</span>
            </li>
          ))}
        </ul>

        {deps.status === "unavailable" && (
          <p role="status" className="mt-4 rounded-md border border-yellow-400/40 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-100">
            {deps.message ?? "The dependency check could not run."} Your code findings are still shown.
          </p>
        )}
        {deps.unpinned > 0 && (
          <p className="mt-3 text-xs text-ink-400">
            {deps.unpinned} dependency declaration(s) use version ranges and were not checked. Pin versions or include a lockfile for full coverage.
          </p>
        )}
        {result.excluded_tests > 0 && (
          <p className="mt-3 text-xs text-ink-400">
            {result.excluded_tests} test, sample and example file(s) were left out. Tick “Include test and sample files” and scan again to include them.
          </p>
        )}
        {result.files_skipped > 0 && (
          <details className="mt-3 text-xs text-ink-400">
            <summary className="cursor-pointer hover:text-ink-100">{result.files_skipped} file(s) skipped</summary>
            <ul className="mt-2 space-y-1 font-mono">
              {result.skipped.map((s) => (
                <li key={s.path}>
                  {s.path} <span className="font-sans text-ink-500">— {s.reason}</span>
                </li>
              ))}
            </ul>
          </details>
        )}
      </section>

      {result.findings.length === 0 ? (
        <section className="rounded-xl border border-ink-700 bg-ink-850 p-6 text-center">
          <h2 className="text-base font-semibold">No findings reported</h2>
          <p className="mx-auto mt-1 max-w-xl text-sm text-ink-300">
            The scanners did not report anything. That is not proof the project is secure: scanners miss issues, so keep reviewing manually.
          </p>
        </section>
      ) : (
        <section aria-labelledby="scan-findings-heading" className="space-y-4">
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 id="scan-findings-heading" className="text-base font-semibold">
                Findings by file
              </h2>
              <p className="text-xs text-ink-400" aria-live="polite">
                Showing {visible.length} of {result.total_findings}
                {result.truncated && " (the most severe findings are listed first; the rest are in the JSON report)"}
              </p>
            </div>
            <div className="flex flex-wrap gap-2" role="group" aria-label="Filter by severity">
              <button type="button" className={chip(severity === "all")} aria-pressed={severity === "all"} onClick={() => setSeverity("all")}>
                All severities
              </button>
              {SEVERITIES.filter((s) => result.counts[s] > 0).map((s) => (
                <button key={s} type="button" className={chip(severity === s)} aria-pressed={severity === s} onClick={() => setSeverity(s)}>
                  {SEVERITY_LABEL[s]}
                </button>
              ))}
            </div>
          </div>

          {groups.map(([file, items], index) => (
            <details key={file} open={index < 3} className="rounded-xl border border-ink-700 bg-ink-900/40">
              <summary className="flex cursor-pointer flex-wrap items-center gap-3 px-4 py-3 text-sm hover:bg-ink-850">
                <span className="font-mono font-semibold [overflow-wrap:anywhere]">{file}</span>
                <span className="text-xs text-ink-400">{items.length} finding{items.length === 1 ? "" : "s"}</span>
              </summary>
              <div className="space-y-3 px-3 pb-3">
                {items.map((f) => (
                  <FindingCard key={f.id} finding={f} />
                ))}
              </div>
            </details>
          ))}
        </section>
      )}

      <p className="text-xs text-ink-400">{result.disclaimer}</p>
    </div>
  );
}

export default function Scan() {
  const [file, setFile] = useState<File | null>(null);
  const [repoUrl, setRepoUrl] = useState("");
  const [includeTests, setIncludeTests] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ProjectScanResponse | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [dragging, setDragging] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  function choose(candidate: File | undefined | null) {
    if (!candidate) return;
    setResult(null);
    if (!candidate.name.toLowerCase().endsWith(".zip")) {
      setFile(null);
      setError(new ApiError("not_a_zip", "Please choose a .zip file. On GitHub use Code → Download ZIP."));
      return;
    }
    if (candidate.size > MAX_ZIP_BYTES) {
      setFile(null);
      setError(new ApiError("zip_too_large", `That ZIP is ${formatSize(candidate.size)}. The limit is ${formatSize(MAX_ZIP_BYTES)}.`));
      return;
    }
    setError(null);
    setFile(candidate);
  }

  function onDrop(e: DragEvent<HTMLLabelElement>) {
    e.preventDefault();
    setDragging(false);
    choose(e.dataTransfer.files?.[0]);
  }

  async function run(kind: "zip" | "github") {
    if (loading || (kind === "zip" && !file) || (kind === "github" && !repoUrl.trim())) return;
    const controller = new AbortController();
    abortRef.current = controller;
    setLoading(true);
    setError(null);
    try {
      const options = { signal: controller.signal, includeTests };
      setResult(kind === "zip" ? await scanProject(file as File, options) : await scanGithub(repoUrl.trim(), options));
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setError(err instanceof ApiError ? err : new ApiError("unknown", "Something went wrong. Please try again."));
    } finally {
      setLoading(false);
      abortRef.current = null;
    }
  }

  const primary =
    "rounded-md bg-accent-500 px-4 py-2 text-sm font-semibold text-ink-950 shadow-sm transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:bg-ink-700 disabled:text-ink-400";

  return (
    <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6 sm:py-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">Scan a whole project</h1>
        <p className="mt-1.5 max-w-2xl text-sm text-ink-300">
          Paste a public GitHub repository or upload a ZIP. CodeShield reviews every Python, JavaScript, TypeScript, Java and C file, flags
          committed secrets and .env files, and checks your dependencies against the OSV.dev vulnerability database. Files are only read, never executed.
        </p>
      </div>

      <section className="space-y-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void run("github");
          }}
          className="space-y-2"
        >
          <label htmlFor="repo-url" className="text-sm font-semibold">
            Scan a public GitHub repository
          </label>
          <div className="flex flex-wrap gap-2">
            <input
              id="repo-url"
              type="text"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
              className="min-w-0 flex-1 basis-72 rounded-md border border-ink-600 bg-ink-800 px-3 py-2 font-mono text-sm text-ink-100 placeholder:text-ink-500"
            />
            <button type="submit" disabled={loading || !repoUrl.trim()} className={primary}>
              {loading ? "Scanning…" : "Scan repo"}
            </button>
          </div>
        </form>

        <div className="flex items-center gap-3 text-xs text-ink-400">
          <span className="h-px flex-1 bg-ink-700" /> or upload a ZIP <span className="h-px flex-1 bg-ink-700" />
        </div>

        <label
          htmlFor="project-zip"
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={`flex cursor-pointer flex-col items-center justify-center gap-1.5 rounded-xl border-2 border-dashed px-6 py-8 text-center transition ${
            dragging ? "border-accent-400 bg-accent-500/10" : "border-ink-600 bg-ink-850 hover:border-ink-400"
          }`}
        >
          <span className="text-sm font-semibold">{file ? file.name : "Drop a project ZIP here, or click to choose one"}</span>
          <span className="text-xs text-ink-400">
            {file ? `${formatSize(file.size)} · ready to scan` : `Up to ${formatSize(MAX_ZIP_BYTES)}. On GitHub: Code → Download ZIP.`}
          </span>
          <input
            id="project-zip"
            type="file"
            accept=".zip,application/zip,application/x-zip-compressed"
            className="sr-only"
            onChange={(e) => {
              choose(e.target.files?.[0]);
              e.target.value = "";
            }}
          />
        </label>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="flex items-center gap-2 text-xs text-ink-300">
            <input type="checkbox" checked={includeTests} onChange={(e) => setIncludeTests(e.target.checked)} />
            Include test and sample files
          </label>
          <div className="flex items-center gap-2">
            {loading && (
              <button type="button" onClick={() => abortRef.current?.abort()} className="rounded-md border border-ink-600 px-3 py-2 text-sm font-medium hover:border-ink-400">
                Cancel
              </button>
            )}
            <button type="button" onClick={() => void run("zip")} disabled={!file || loading} className={primary}>
              {loading ? "Scanning…" : result && !result.source ? "Re-scan project" : "Scan project"}
            </button>
          </div>
        </div>
        <p className="text-xs text-ink-400">Only package names and versions are sent to OSV.dev. Your source code stays on the CodeShield server.</p>

        {error && (
          <div role="alert" className="rounded-lg border border-red-400/40 bg-red-500/10 px-4 py-3 text-sm text-red-100">
            <p className="font-semibold">Scan failed</p>
            <p className="mt-0.5 text-red-100/90">{error.message}</p>
          </div>
        )}
      </section>

      {result && <Results result={result} />}
    </main>
  );
}
