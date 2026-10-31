import type { Finding, ScannerStatus, Severity } from "./types";

export const MAX_ZIP_BYTES = 10 * 1024 * 1024;

export interface ScanFinding extends Finding {
  file: string;
}

export interface FileSummary {
  path: string;
  language: string;
  lines: number;
  total_findings: number;
  counts: Record<Severity, number>;
}

export interface SkippedFile {
  path: string;
  reason: string;
}

export interface DependencyItem {
  ecosystem: string;
  name: string;
  version: string;
  source: string;
  vulnerabilities: string[];
}

export interface DependencyReport {
  status: "ok" | "unavailable" | "none";
  message: string | null;
  checked: number;
  vulnerable: number;
  unpinned: number;
  items: DependencyItem[];
}

export interface ProjectScanResponse {
  scan_id: string;
  source: string | null;
  status: "complete";
  files_scanned: number;
  files_skipped: number;
  excluded_tests: number;
  skipped: SkippedFile[];
  languages: Record<string, number>;
  total_findings: number;
  counts: Record<Severity, number>;
  score: number;
  grade: string;
  findings: ScanFinding[];
  truncated: boolean;
  files: FileSummary[];
  dependencies: DependencyReport;
  scanners: ScannerStatus[];
  disclaimer: string;
  duration_ms: number;
}
