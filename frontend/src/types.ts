export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Language = "python" | "javascript" | "typescript" | "java" | "c";
export type Origin = "static_analysis" | "ai_hypothesis";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Informational",
};

export const LANGUAGES: { value: Language; label: string }[] = [
  { value: "python", label: "Python" },
  { value: "javascript", label: "JavaScript" },
  { value: "typescript", label: "TypeScript" },
  { value: "java", label: "Java" },
  { value: "c", label: "C" },
];

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  origin: Origin;
  tool: string;
  rule_id: string | null;
  cwe: string | null;
  line_start: number | null;
  line_end: number | null;
  snippet: string;
  description: string;
  explanation: string | null;
  why_it_matters: string | null;
  recommendation: string;
  suggested_code: string | null;
  confidence: "low" | "medium" | "high";
  ai_explained: boolean;
}

export interface ScannerStatus {
  name: string;
  status: "ran" | "unavailable" | "skipped" | "failed";
  findings: number;
  detail: string | null;
}

export interface AIStatus {
  status: "ok" | "not_configured" | "error";
  model: string | null;
  error_code: string | null;
  message: string | null;
  dropped_items: number;
}

export interface ReviewResponse {
  review_id: string;
  status: "complete" | "static_only";
  language: Language;
  total_findings: number;
  counts: Record<Severity, number>;
  summary: string;
  best_practices: string[];
  findings: Finding[];
  scanners: ScannerStatus[];
  ai: AIStatus;
  disclaimer: string;
  duration_ms: number;
}

export interface Health {
  status: string;
  version: string;
  ai_configured: boolean;
  model: string;
  max_code_chars: number;
}
