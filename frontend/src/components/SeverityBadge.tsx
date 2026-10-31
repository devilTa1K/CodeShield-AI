import type { Severity } from "../types";
import { SEVERITY_LABEL } from "../types";

// Each severity has a distinct shape and a text label, so colour is never the only signal.
const STYLE: Record<Severity, string> = {
  critical: "text-red-200 bg-red-500/15 border-red-400/50",
  high: "text-orange-200 bg-orange-500/15 border-orange-400/50",
  medium: "text-yellow-200 bg-yellow-500/15 border-yellow-400/50",
  low: "text-sky-200 bg-sky-500/15 border-sky-400/50",
  info: "text-slate-200 bg-slate-500/15 border-slate-400/50",
};

function Icon({ severity }: { severity: Severity }) {
  const common = { width: 10, height: 10, viewBox: "0 0 10 10", "aria-hidden": true, fill: "currentColor" } as const;
  switch (severity) {
    case "critical":
      return (
        <svg {...common}>
          <path d="M5 0.5 9.5 5 5 9.5 0.5 5Z" />
        </svg>
      );
    case "high":
      return (
        <svg {...common}>
          <path d="M5 0.8 9.6 9H0.4Z" />
        </svg>
      );
    case "medium":
      return (
        <svg {...common}>
          <circle cx="5" cy="5" r="4.2" />
        </svg>
      );
    case "low":
      return (
        <svg {...common}>
          <rect x="1" y="1" width="8" height="8" rx="1" />
        </svg>
      );
    default:
      return (
        <svg {...common} fill="none" stroke="currentColor" strokeWidth="1.5">
          <circle cx="5" cy="5" r="3.8" />
        </svg>
      );
  }
}

export default function SeverityBadge({ severity, className = "" }: { severity: Severity; className?: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-semibold ${STYLE[severity]} ${className}`}
      aria-label={`Severity: ${SEVERITY_LABEL[severity]}`}
      data-severity={severity}
    >
      <Icon severity={severity} />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}
