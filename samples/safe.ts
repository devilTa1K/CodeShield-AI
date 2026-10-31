import { execFileSync } from "child_process";
import { createHash } from "crypto";

const ALLOWED_DIRS = new Set(["logs", "reports"]);

export function listFiles(dir: string): string {
  if (!ALLOWED_DIRS.has(dir)) {
    throw new Error("Directory not allowed");
  }
  return execFileSync("ls", ["-la", dir]).toString();
}

export function renderComment(el: HTMLElement, comment: string): void {
  el.textContent = comment;
}

export function fingerprint(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}
