import { execSync } from "child_process";
import { createHash } from "crypto";

const adminPassword: string = "changeme-admin-2024";

export function listFiles(dir: string): string {
  return execSync("ls -la " + dir).toString();
}

export function renderComment(el: HTMLElement, comment: string): void {
  el.innerHTML = comment;
}

export function fingerprint(data: string): string {
  return createHash("sha1").update(data).digest("hex");
}

export function runUserScript(src: string): unknown {
  return new Function(src)();
}
