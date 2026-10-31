import type { ExplainLanguage, Health, Language, ReviewResponse } from "../types";

// Empty by default: the Vite dev server proxies /api and /health to the backend.
// Set VITE_API_BASE_URL (for example https://api.example.com) for deployed builds.
const BASE = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

export const REVIEW_TIMEOUT_MS = 300_000;

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status = 0) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

async function toApiError(res: Response): Promise<ApiError> {
  try {
    const body = await res.json();
    const err = body?.error;
    if (err && typeof err.message === "string") {
      return new ApiError(String(err.code ?? "error"), err.message, res.status);
    }
  } catch {
    // fall through to the generic message
  }
  return new ApiError("http_error", `The server returned an error (HTTP ${res.status}).`, res.status);
}

export interface ReviewOptions {
  /** Abort from the caller (the Cancel button). Rejects with an AbortError. */
  signal?: AbortSignal;
  timeoutMs?: number;
}

export async function reviewCode(
  request: { code: string; language: Language; explain_language?: ExplainLanguage },
  { signal, timeoutMs = REVIEW_TIMEOUT_MS }: ReviewOptions = {},
): Promise<ReviewResponse> {
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
    const res = await fetch(`${BASE}/api/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    if (!res.ok) throw await toApiError(res);
    return (await res.json()) as ReviewResponse;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (timedOut) {
      throw new ApiError("client_timeout", "The review is taking too long. Try again with less code.");
    }
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError("network_error", "Could not reach the CodeShield backend. Is it running?");
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onCallerAbort);
  }
}

export async function getHealth(): Promise<Health> {
  const res = await fetch(`${BASE}/health`);
  if (!res.ok) throw await toApiError(res);
  return (await res.json()) as Health;
}

