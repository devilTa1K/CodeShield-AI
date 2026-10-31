"""Pydantic models for requests, responses and validated AI output."""

from __future__ import annotations

import re
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

SUPPORTED_LANGUAGES: tuple[str, ...] = ("python", "javascript", "typescript", "java", "c")

DISCLAIMER = (
    "This review is automated assistance, not a guarantee. Scanner results are rule matches "
    "that still need human triage, AI findings are unverified hypotheses, and no review can "
    "prove that code is secure."
)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

Origin = Literal["static_analysis", "ai_hypothesis"]
Confidence = Literal["low", "medium", "high"]


# --------------------------------------------------------------------------- #
# API request / response
# --------------------------------------------------------------------------- #
class ReviewRequest(BaseModel):
    code: str
    language: str


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    origin: Origin
    tool: str
    rule_id: Optional[str] = None
    cwe: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    snippet: str = ""
    description: str
    explanation: Optional[str] = None
    why_it_matters: Optional[str] = None
    recommendation: str
    suggested_code: Optional[str] = None
    confidence: Confidence = "medium"
    ai_explained: bool = False


class ScannerStatus(BaseModel):
    name: str
    status: Literal["ran", "unavailable", "skipped", "failed"]
    findings: int = 0
    detail: Optional[str] = None


class AIStatus(BaseModel):
    status: Literal["ok", "not_configured", "error"]
    model: Optional[str] = None
    error_code: Optional[str] = None
    message: Optional[str] = None
    dropped_items: int = 0


class ReviewResponse(BaseModel):
    review_id: str
    status: Literal["complete", "static_only"]
    language: str
    total_findings: int
    counts: dict[str, int]
    summary: str
    best_practices: list[str]
    findings: list[Finding]
    scanners: list[ScannerStatus]
    ai: AIStatus
    disclaimer: str = DISCLAIMER
    duration_ms: int


# --------------------------------------------------------------------------- #
# Validated shape of the model's JSON output
# --------------------------------------------------------------------------- #
_SEVERITY_ALIASES = {
    "informational": "info",
    "information": "info",
    "warning": "medium",
    "moderate": "medium",
    "error": "high",
}


def _norm_lower(value):
    return value.strip().lower() if isinstance(value, str) else value


def _norm_cwe(value):
    if value is None:
        return None
    text = f"CWE-{value}" if isinstance(value, int) else str(value).strip()
    match = re.search(r"(\d{1,5})", text)
    return f"CWE-{match.group(1)}" if match else None


class AINote(BaseModel):
    """AI explanation attached to a finding that a static scanner reported."""

    id: str = Field(min_length=1, max_length=40)
    explanation: Optional[str] = Field(default=None, max_length=2000)
    why_it_matters: Optional[str] = Field(default=None, max_length=1500)
    recommendation: Optional[str] = Field(default=None, max_length=2000)
    fixed_code: Optional[str] = Field(default=None, max_length=6000)


class AIFinding(BaseModel):
    """A finding the model proposes on its own; always treated as a hypothesis."""

    title: str = Field(min_length=1, max_length=160)
    severity: Severity
    category: str = Field(min_length=1, max_length=60)
    line_start: Optional[int] = Field(default=None, ge=1)
    line_end: Optional[int] = Field(default=None, ge=1)
    description: str = Field(min_length=1, max_length=2000)
    explanation: Optional[str] = Field(default=None, max_length=2000)
    why_it_matters: Optional[str] = Field(default=None, max_length=1500)
    recommendation: str = Field(min_length=1, max_length=2000)
    fixed_code: Optional[str] = Field(default=None, max_length=6000)
    confidence: Confidence = "low"
    cwe: Optional[str] = None

    @field_validator("severity", mode="before")
    @classmethod
    def _severity(cls, v):
        v = _norm_lower(v)
        return _SEVERITY_ALIASES.get(v, v) if isinstance(v, str) else v

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence(cls, v):
        return _norm_lower(v)

    @field_validator("cwe", mode="before")
    @classmethod
    def _cwe(cls, v):
        return _norm_cwe(v)


class AIReview(BaseModel):
    summary: str
    best_practices: list[str] = Field(default_factory=list)
    static_finding_notes: list[AINote] = Field(default_factory=list)
    additional_findings: list[AIFinding] = Field(default_factory=list)
    dropped_items: int = 0
