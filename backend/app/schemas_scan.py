"""Pydantic models for the project (ZIP) scan."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

from .schemas import DISCLAIMER, Finding, ScannerStatus


class GithubScanRequest(BaseModel):
    url: str
    include_tests: bool = False


class ScanFinding(Finding):
    """A finding plus the file it was found in (a manifest path for dependency findings)."""

    file: str


class FileSummary(BaseModel):
    path: str
    language: str
    lines: int
    total_findings: int
    counts: dict[str, int]


class SkippedFile(BaseModel):
    path: str
    reason: str


class DependencyItem(BaseModel):
    ecosystem: str
    name: str
    version: str
    source: str
    vulnerabilities: list[str]


class DependencyReport(BaseModel):
    status: Literal["ok", "unavailable", "none"]
    message: Optional[str] = None
    checked: int = 0
    vulnerable: int = 0
    unpinned: int = 0
    items: list[DependencyItem] = Field(default_factory=list)


class ProjectScanResponse(BaseModel):
    scan_id: str
    status: Literal["complete"] = "complete"
    source: Optional[str] = None  # e.g. "owner/repo" for GitHub scans
    files_scanned: int
    files_skipped: int
    excluded_tests: int = 0  # test/sample/example files left out (include_tests=false)
    skipped: list[SkippedFile]
    languages: dict[str, int]
    total_findings: int
    counts: dict[str, int]
    score: int
    grade: str
    findings: list[ScanFinding]
    truncated: bool = False
    files: list[FileSummary]
    dependencies: DependencyReport
    scanners: list[ScannerStatus]
    disclaimer: str = DISCLAIMER
    duration_ms: int
