"""Review score and OWASP Top 10 (2021) mapping.

The score summarizes *reported findings only*. A high score is not evidence that code is secure.
"""

from __future__ import annotations

from typing import Optional, Sequence

from ..schemas import Finding, Severity

_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}
AI_WEIGHT_FACTOR = 0.5  # unverified AI hypotheses count for half


def compute_score(findings: Sequence[Finding]) -> tuple[int, str]:
    penalty = 0.0
    for f in findings:
        weight = _WEIGHTS[f.severity]
        penalty += weight * (AI_WEIGHT_FACTOR if f.origin == "ai_hypothesis" else 1.0)
    score = max(0, int(100 - penalty + 0.5))  # round half up
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return score, grade


_INJECTION = "A03:2021 Injection"
_CRYPTO = "A02:2021 Cryptographic Failures"
_AUTH = "A07:2021 Identification and Authentication Failures"
_ACCESS = "A01:2021 Broken Access Control"
_INTEGRITY = "A08:2021 Software and Data Integrity Failures"

# Only well-established CWE -> OWASP 2021 category pairs; unmapped CWEs return None.
OWASP_BY_CWE: dict[str, str] = {
    **{c: _INJECTION for c in ("CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-95", "CWE-917")},
    **{c: _CRYPTO for c in ("CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338", "CWE-916")},
    **{c: _AUTH for c in ("CWE-259", "CWE-295", "CWE-798")},
    **{c: _ACCESS for c in ("CWE-22", "CWE-284", "CWE-862", "CWE-863")},
    "CWE-502": _INTEGRITY,
    "CWE-209": "A04:2021 Insecure Design",
}


def owasp_for(cwe: Optional[str]) -> Optional[str]:
    return OWASP_BY_CWE.get(cwe) if cwe else None


def with_owasp(findings: Sequence[Finding]) -> list[Finding]:
    return [f.model_copy(update={"owasp": owasp_for(f.cwe)}) for f in findings]
