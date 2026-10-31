import { useMemo, useState } from "react";
import type { Finding, Origin, Severity } from "../types";
import { SEVERITIES, SEVERITY_LABEL } from "../types";
import FindingCard from "./FindingCard";

type SeverityFilter = "all" | Severity;
type OriginFilter = "all" | Origin;

const ORIGIN_OPTIONS: { value: OriginFilter; label: string }[] = [
  { value: "all", label: "All sources" },
  { value: "static_analysis", label: "Static analysis" },
  { value: "ai_hypothesis", label: "AI hypotheses" },
];

interface ListProps {
  findings: Finding[];
  onApplyFix?: (finding: Finding) => void;
  canApply?: boolean;
}

export default function FindingsList({ findings, onApplyFix, canApply }: ListProps) {
  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const [category, setCategory] = useState("all");
  const [origin, setOrigin] = useState<OriginFilter>("all");

  const categories = useMemo(() => [...new Set(findings.map((f) => f.category))].sort(), [findings]);
  const present = useMemo(() => new Set(findings.map((f) => f.severity)), [findings]);

  const visible = findings.filter(
    (f) =>
      (severity === "all" || f.severity === severity) &&
      (category === "all" || f.category === category) &&
      (origin === "all" || f.origin === origin),
  );
  const filtered = severity !== "all" || category !== "all" || origin !== "all";

  function reset() {
    setSeverity("all");
    setCategory("all");
    setOrigin("all");
  }

  const chip = (active: boolean) =>
    `rounded-md border px-2.5 py-1 text-xs font-medium transition ${
      active
        ? "border-accent-500 bg-accent-500/15 text-accent-300"
        : "border-ink-600 bg-ink-800 text-ink-300 hover:border-ink-400 hover:text-ink-100"
    }`;

  return (
    <section aria-labelledby="findings-heading" className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 id="findings-heading" className="text-base font-semibold">
            Findings
          </h2>
          <p className="text-xs text-ink-400" aria-live="polite">
            Showing {visible.length} of {findings.length}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <label className="sr-only" htmlFor="filter-category">
            Filter by category
          </label>
          <select
            id="filter-category"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="rounded-md border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-100"
          >
            <option value="all">All categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>

          <label className="sr-only" htmlFor="filter-origin">
            Filter by source
          </label>
          <select
            id="filter-origin"
            value={origin}
            onChange={(e) => setOrigin(e.target.value as OriginFilter)}
            className="rounded-md border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-100"
          >
            {ORIGIN_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div role="group" aria-label="Filter by severity" className="flex flex-wrap gap-2">
        <button type="button" className={chip(severity === "all")} aria-pressed={severity === "all"} onClick={() => setSeverity("all")}>
          All severities
        </button>
        {SEVERITIES.filter((s) => present.has(s)).map((s) => (
          <button key={s} type="button" className={chip(severity === s)} aria-pressed={severity === s} onClick={() => setSeverity(s)}>
            {SEVERITY_LABEL[s]}
          </button>
        ))}
      </div>

      {visible.length === 0 ? (
        <div className="rounded-xl border border-dashed border-ink-600 p-8 text-center text-sm text-ink-300">
          <p>No findings match these filters.</p>
          {filtered && (
            <button type="button" onClick={reset} className="mt-3 rounded-md border border-ink-600 px-3 py-1.5 text-xs font-medium hover:border-ink-400">
              Clear filters
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {visible.map((f, i) => (
            <FindingCard key={f.id} finding={f} defaultOpen={i < 2 && !filtered} onApplyFix={onApplyFix} canApply={canApply} />
          ))}
        </div>
      )}
    </section>
  );
}
