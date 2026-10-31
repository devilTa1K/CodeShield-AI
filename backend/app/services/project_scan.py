"""Scan a whole project uploaded as a ZIP: static analysis per file plus a dependency check.

The archive is read in memory. Nothing is extracted to disk, nothing is executed, and entry names are
only used as labels, so path-traversal names cannot write anywhere.
"""

from __future__ import annotations

import asyncio
import io
import logging
import re
import time
import uuid
import zipfile
from collections import Counter
from dataclasses import dataclass
from typing import Optional, Protocol

from ..config import Settings
from ..schemas import SEVERITY_RANK, Finding, ScannerStatus, Severity
from ..schemas_scan import (
    DependencyItem,
    DependencyReport,
    FileSummary,
    ProjectScanResponse,
    ScanFinding,
    SkippedFile,
)
from .analyzer import analyze_static, run_builtin_rules, severity_counts
from .osv import OsvResult, Package, is_requirements_file, parse_manifests
from .scoring import compute_score, with_owasp

logger = logging.getLogger("codeshield.scan")

MAX_ZIP_BYTES = 10 * 1024 * 1024
MAX_ENTRIES = 5_000
MAX_UNCOMPRESSED_BYTES = 60 * 1024 * 1024  # declared sizes; guards against zip bombs
MAX_FILE_BYTES = 300_000
MAX_CODE_FILES = 150
MAX_MANIFEST_BYTES = 3 * 1024 * 1024
MAX_FINDINGS_RETURNED = 500
MAX_FILE_SUMMARIES = 300
MAX_SKIPPED_LISTED = 50
CONCURRENCY = 4

LANGUAGE_BY_EXT = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".c": "c", ".h": "c",
}
CONFIG_EXTS = (".env", ".yml", ".yaml", ".properties", ".ini", ".cfg", ".conf", ".toml")
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", "target", "vendor",
    ".next", ".idea", ".vscode", "coverage", "site-packages", ".mypy_cache", ".pytest_cache", "__MACOSX",
}
EXAMPLE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e", "fixtures", "samples", "examples", "example", "testdata"}
_TEST_FILE = re.compile(r"(^test_.*\.py$|_test\.py$|^conftest\.py$|\.(test|spec)\.[jt]sx?$|Tests?\.java$|_test\.c$)")


def _is_test_path(path: str) -> bool:
    """Test, sample and example files are noisy (asserts, deliberately vulnerable demos), so skip them by default."""
    parts = path.split("/")
    return any(p.lower() in TEST_DIRS for p in parts[:-1]) or bool(_TEST_FILE.search(parts[-1]))




class ScanInputError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


class DependencyChecker(Protocol):
    async def check(self, packages: list[Package]) -> OsvResult: ...


@dataclass
class _Entry:
    path: str
    info: zipfile.ZipInfo


# --------------------------------------------------------------------------- #
# Reading the archive
# --------------------------------------------------------------------------- #
def _normalize(name: str) -> Optional[str]:
    """Return a clean relative path, or None for unsafe or empty names."""
    cleaned = name.replace("\\", "/").lstrip("/")
    parts = [p for p in cleaned.split("/") if p not in ("", ".")]
    if not parts or ".." in parts or re.match(r"^[A-Za-z]:", parts[0]):
        return None
    return "/".join(parts)


def _strip_common_root(paths: list[str]) -> dict[str, str]:
    roots = {p.split("/", 1)[0] for p in paths if "/" in p}
    if len(roots) == 1 and all("/" in p for p in paths):
        root = next(iter(roots)) + "/"
        return {p: p[len(root):] for p in paths}
    return {p: p for p in paths}


def _is_env_file(base: str) -> bool:
    lowered = base.lower()
    return (lowered == ".env" or lowered.startswith(".env.")) and not lowered.endswith(EXAMPLE_ENV_SUFFIXES)


def _classify(path: str) -> Optional[str]:
    """code | config | manifest | None (ignore)."""
    base = path.rsplit("/", 1)[-1]
    lowered = base.lower()
    if lowered in ("package.json", "package-lock.json") or is_requirements_file(path):
        return "manifest"
    if lowered.endswith(".min.js") or lowered.endswith(".d.ts"):
        return None
    if _is_env_file(base) or lowered.endswith(CONFIG_EXTS):
        return "config"
    ext = "." + lowered.rsplit(".", 1)[-1] if "." in lowered else ""
    return "code" if ext in LANGUAGE_BY_EXT else None


def _decode(raw: bytes) -> Optional[str]:
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# Findings helpers
# --------------------------------------------------------------------------- #
def _to_scan(finding: Finding, path: str) -> ScanFinding:
    return ScanFinding(**finding.model_dump(), file=path)


def _config_findings(path: str, text: str) -> list[Finding]:
    lines = text.splitlines()
    found = [f for f in run_builtin_rules(lines, "javascript") if (f.rule_id or "").startswith("CS-SECRET")]
    base = path.rsplit("/", 1)[-1]
    if _is_env_file(base):
        filled = [i for i, ln in enumerate(lines, 1)
                  if re.match(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S", ln) and not ln.lstrip().startswith("#")]
        if filled:
            found.insert(0, Finding(
                id="", title="Environment file included in the project", severity=Severity.HIGH,
                category="Secrets", origin="static_analysis", tool="CodeShield rules", rule_id="CS-ENV-001",
                cwe="CWE-540", line_start=filled[0], line_end=filled[0],
                snippet=f"{len(filled)} variable(s) with values (values hidden)",
                description="A .env file with values is part of the project archive. These files usually hold real secrets.",
                recommendation="Remove the file from version control, add it to .gitignore, rotate any real secrets it held, "
                               "and commit a .env.example with empty values instead.",
                confidence="high"))
    return found


def _find_line(text: str, needle: str) -> Optional[int]:
    lowered = needle.lower()
    for i, line in enumerate(text.splitlines(), 1):
        if lowered in line.lower():
            return i
    return None


def _aggregate_scanners(statuses: list[list[ScannerStatus]], files: int) -> list[ScannerStatus]:
    by_name: dict[str, list[ScannerStatus]] = {}
    for per_file in statuses:
        for s in per_file:
            by_name.setdefault(s.name, []).append(s)
    out: list[ScannerStatus] = []
    for name, items in by_name.items():
        ran = [s for s in items if s.status == "ran"]
        if ran:
            out.append(ScannerStatus(name=name, status="ran", findings=sum(s.findings for s in ran),
                                     detail=f"Ran on {len(ran)} of {files} file(s)."))
            continue
        for state in ("failed", "unavailable", "skipped"):
            match = next((s for s in items if s.status == state), None)
            if match:
                out.append(ScannerStatus(name=name, status=state, detail=match.detail))  # type: ignore[arg-type]
                break
    return out


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
async def scan_project(
    data: bytes, settings: Settings, checker: DependencyChecker, include_tests: bool = False
) -> ProjectScanResponse:
    started = time.perf_counter()
    excluded_tests = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ScanInputError("invalid_zip", "That file is not a valid ZIP archive.") from None

    with archive:
        infos = [i for i in archive.infolist() if not i.is_dir()]
        if len(archive.infolist()) > MAX_ENTRIES:
            raise ScanInputError("too_many_files", f"The archive has more than {MAX_ENTRIES:,} entries.", 413)
        if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED_BYTES:
            raise ScanInputError("zip_too_large", "The archive expands to more than 60 MB.", 413)

        cleaned: dict[str, zipfile.ZipInfo] = {}
        skipped: list[SkippedFile] = []
        for info in infos:
            path = _normalize(info.filename)
            if path is None:
                skipped.append(SkippedFile(path=info.filename[:120], reason="unsafe path"))
            else:
                cleaned[path] = info
        display = _strip_common_root(list(cleaned))
        entries = [_Entry(display[p], cleaned[p]) for p in cleaned]

        code: list[tuple[str, str, str]] = []  # (path, language, text)
        config: list[tuple[str, str]] = []
        manifests: dict[str, str] = {}

        for entry in sorted(entries, key=lambda e: e.path):
            parts = entry.path.split("/")
            if any(p in SKIP_DIRS for p in parts[:-1]):
                continue
            kind = _classify(entry.path)
            if kind is None:
                continue
            if kind in ("code", "config") and not include_tests and _is_test_path(entry.path):
                excluded_tests += 1
                continue
            info = entry.info
            if info.flag_bits & 0x1:
                skipped.append(SkippedFile(path=entry.path, reason="encrypted"))
                continue
            limit = MAX_MANIFEST_BYTES if kind == "manifest" else MAX_FILE_BYTES
            if info.file_size > limit:
                skipped.append(SkippedFile(path=entry.path, reason=f"too large ({info.file_size // 1024} KB)"))
                continue
            try:
                text = _decode(archive.read(info))
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError):
                skipped.append(SkippedFile(path=entry.path, reason="could not be read"))
                continue
            if text is None:
                skipped.append(SkippedFile(path=entry.path, reason="binary file"))
                continue
            if kind == "manifest":
                manifests[entry.path] = text
            elif kind == "config":
                config.append((entry.path, text))
            else:
                if len(text) > settings.max_code_chars or text.count("\n") + 1 > settings.max_code_lines:
                    skipped.append(SkippedFile(path=entry.path, reason="over the per-file size limit"))
                elif len(code) >= MAX_CODE_FILES:
                    skipped.append(SkippedFile(path=entry.path, reason=f"file limit reached ({MAX_CODE_FILES})"))
                else:
                    ext = "." + entry.path.rsplit(".", 1)[-1].lower()
                    code.append((entry.path, LANGUAGE_BY_EXT[ext], text))

    # ---- static analysis, a few files at a time ----
    sem = asyncio.Semaphore(CONCURRENCY)

    async def analyze(path: str, language: str, text: str):
        async with sem:
            try:
                return path, language, text, await analyze_static(text, language, settings)
            except Exception:  # noqa: BLE001 - one bad file must not sink the scan
                logger.exception("analysis failed for a file")
                return path, language, text, None

    results = await asyncio.gather(*(analyze(*c) for c in code))

    all_findings: list[ScanFinding] = []
    summaries: list[FileSummary] = []
    scanner_runs: list[list[ScannerStatus]] = []
    scanned = 0
    for path, language, text, result in results:
        if result is None:
            skipped.append(SkippedFile(path=path, reason="analysis failed"))
            continue
        scanned += 1
        scanner_runs.append(result.scanners)
        file_findings = with_owasp(result.findings)
        all_findings += [_to_scan(f, path) for f in file_findings]
        summaries.append(FileSummary(path=path, language=language, lines=text.count("\n") + 1,
                                     total_findings=len(file_findings), counts=severity_counts(file_findings)))

    for path, text in config:
        found = with_owasp(_config_findings(path, text))
        if found:
            all_findings += [_to_scan(f, path) for f in found]
        scanned += 1
        summaries.append(FileSummary(path=path, language="config", lines=text.count("\n") + 1,
                                     total_findings=len(found), counts=severity_counts(found)))

    # ---- dependencies ----
    packages, unpinned = parse_manifests(manifests)
    if not packages:
        deps = DependencyReport(status="none", unpinned=unpinned,
                                message="No pinned dependencies found in requirements*.txt, package.json or package-lock.json."
                                if manifests else "No dependency manifests found.")
    else:
        osv = await checker.check(packages)
        if osv.status != "ok":
            deps = DependencyReport(status="unavailable", message=osv.message, checked=len(packages), unpinned=unpinned)
        else:
            items: list[DependencyItem] = []
            for (eco, name, version), vulns in osv.vulns.items():
                source = next(p.source for p in packages if (p.ecosystem, p.name, p.version) == (eco, name, version))
                items.append(DependencyItem(ecosystem=eco, name=name, version=version, source=source,
                                            vulnerabilities=[v.id for v in vulns]))
                for v in vulns:
                    line = _find_line(manifests.get(source, ""), name)
                    fix = f"Upgrade {name} to {v.fixed} or later." if v.fixed else \
                        "Check the advisory for a fixed version and upgrade."
                    all_findings.append(ScanFinding(
                        id="", file=source, title=f"{name} {version}: {v.id}", severity=v.severity,
                        category="Vulnerable dependency", origin="static_analysis", tool="OSV.dev", rule_id=v.id,
                        line_start=line, line_end=line, snippet=f"{name} {version}",
                        description=v.summary or "A known vulnerability affects this version. See the OSV advisory.",
                        recommendation=fix, confidence="high"))
            deps = DependencyReport(status="ok", message=osv.message, checked=len(packages),
                                    vulnerable=len(items), unpinned=unpinned, items=items[:200])

    # ---- assemble ----
    all_findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.file, f.line_start or 10**9, f.title))
    all_findings = [f.model_copy(update={"id": f"P{i}"}) for i, f in enumerate(all_findings, start=1)]
    counts = severity_counts(all_findings)
    score, grade = compute_score(all_findings)
    summaries.sort(key=lambda s: (-s.total_findings, s.path))
    scanners = _aggregate_scanners(scanner_runs, len(code))
    if deps.status != "none":
        scanners.append(ScannerStatus(
            name="OSV.dev", status="ran" if deps.status == "ok" else "unavailable",
            findings=sum(len(i.vulnerabilities) for i in deps.items), detail=deps.message))

    scan_id = uuid.uuid4().hex[:12]
    logger.info("scan_id=%s files=%d findings=%d deps=%s", scan_id, scanned, len(all_findings), deps.status)
    return ProjectScanResponse(
        scan_id=scan_id,
        files_scanned=scanned,
        files_skipped=len(skipped),
        excluded_tests=excluded_tests,
        skipped=skipped[:MAX_SKIPPED_LISTED],
        languages=dict(Counter(s.language for s in summaries)),
        total_findings=len(all_findings),
        counts=counts,
        score=score,
        grade=grade,
        findings=all_findings[:MAX_FINDINGS_RETURNED],
        truncated=len(all_findings) > MAX_FINDINGS_RETURNED,
        files=summaries[:MAX_FILE_SUMMARIES],
        dependencies=deps,
        scanners=scanners,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
