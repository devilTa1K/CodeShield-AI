import { afterEach, describe, expect, it, vi } from "vitest";
import { json, review } from "../test/fixtures";
import { ApiError, reviewCode } from "./api";

afterEach(() => vi.unstubAllGlobals());

const REQUEST = { code: "x = 1", language: "python" as const };

describe("reviewCode", () => {
  it("returns the parsed review on success", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(review())));
    const result = await reviewCode(REQUEST);
    expect(result.review_id).toBe("abc123");
  });

  it("turns structured server errors into ApiError", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ error: { code: "empty_code", message: "Paste some code to review." } }, 400)));
    await expect(reviewCode(REQUEST)).rejects.toMatchObject({ name: "ApiError", code: "empty_code", status: 400, message: "Paste some code to review." });
  });

  it("handles non-JSON error pages", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<html>Bad gateway</html>", { status: 502 })));
    const err = await reviewCode(REQUEST).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.code).toBe("http_error");
    expect(err.message).toContain("502");
  });

  it("maps fetch failures to a network error", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("Failed to fetch"); }));
    await expect(reviewCode(REQUEST)).rejects.toMatchObject({ code: "network_error" });
  });

  it("times out slow requests with a clear error", async () => {
    vi.stubGlobal("fetch", vi.fn((_u: string, init?: RequestInit) => new Promise((_r, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
    })));
    await expect(reviewCode(REQUEST, { timeoutMs: 20 })).rejects.toMatchObject({ code: "client_timeout" });
  });

  it("propagates a caller abort as an AbortError", async () => {
    vi.stubGlobal("fetch", vi.fn((_u: string, init?: RequestInit) => new Promise((_r, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
    })));
    const controller = new AbortController();
    const promise = reviewCode(REQUEST, { signal: controller.signal });
    controller.abort();
    await expect(promise).rejects.toMatchObject({ name: "AbortError" });
  });
});
