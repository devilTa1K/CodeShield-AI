import type { ProjectScanResponse } from "../scanTypes";
import { ApiError } from "./api";

const BASE = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

export const SCAN_TIMEOUT_MS = 180_000;

async function toError(res: Response): Promise<ApiError> {
  try {
    const err = (await res.json())?.error;
    if (err && typeof err.message === "string") return new ApiError(String(err.code ?? "error"), err.message, res.status);
  } catch {
    // fall through
  }
  return new ApiError("http_error", `The server returned an error (HTTP ${res.status}).`, res.status);
}

interface ScanOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  includeTests?: boolean;
}

async function send(path: string, init: RequestInit, { signal, timeoutMs = SCAN_TIMEOUT_MS }: ScanOptions): Promise<ProjectScanResponse> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const onCallerAbort = () => controller.abort();
  signal?.addEventListener("abort", onCallerAbort);
  if (signal?.aborted) controller.abort();

  try {
    const res = await fetch(`${BASE}${path}`, { method: "POST", ...init, signal: controller.signal });
    if (!res.ok) throw await toError(res);
    return (await res.json()) as ProjectScanResponse;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (timedOut) throw new ApiError("client_timeout", "The scan is taking too long. Try a smaller project.");
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError("network_error", "Could not reach the CodeShield backend. Is it running?");
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onCallerAbort);
  }
}

/** Upload a project ZIP as the raw request body and return the scan. */
export function scanProject(file: File, options: ScanOptions = {}): Promise<ProjectScanResponse> {
  const query = options.includeTests ? "?include_tests=true" : "";
  return send(`/api/scan${query}`, { headers: { "Content-Type": "application/zip" }, body: file }, options);
}

/** Ask the server to download a public GitHub repository and scan it. */
export function scanGithub(url: string, options: ScanOptions = {}): Promise<ProjectScanResponse> {
  return send(
    "/api/scan/github",
    { headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, include_tests: Boolean(options.includeTests) }) },
    options,
  );
}
