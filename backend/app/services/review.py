"""Orchestrates one review: static analysis -> AI analysis -> validated, merged result."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Protocol, Sequence

from ..config import Settings
from ..schemas import AIReview, AIStatus, Finding, ReviewResponse
from .analyzer import analyze_static, merge_ai, severity_counts
from .bharatcode import BharatCodeError
from .scoring import compute_score, with_owasp

logger = logging.getLogger("codeshield.review")


class AIClient(Protocol):
    @property
    def configured(self) -> bool: ...

    async def review(
        self, code: str, language: str, static_findings: Sequence[Finding], explain_language: str = "english"
    ) -> AIReview: ...


class AnalysisUnavailable(Exception):
    """No analyzer was able to process the submission."""


def _fallback_summary(counts: dict[str, int], total: int, language: str, ai: AIStatus) -> str:
    if total:
        parts = [f"{counts[k]} {k}" for k in ("critical", "high", "medium", "low", "info") if counts[k]]
        text = f"Static analysis reported {total} finding(s) in this {language} code ({', '.join(parts)})."
    else:
        text = f"Static analysis reported no findings in this {language} code. That is not proof the code is secure."
    if ai.status != "ok":
        text += " AI-assisted explanations are unavailable for this run, so findings use scanner descriptions only."
    return text


async def perform_review(
    code: str, language: str, settings: Settings, ai_client: AIClient, explain_language: str = "english"
) -> ReviewResponse:
    started = time.perf_counter()
    review_id = uuid.uuid4().hex[:12]

    static = await analyze_static(code, language, settings)

    ai_review: AIReview | None = None
    if not ai_client.configured:
        ai_status = AIStatus(
            status="not_configured",
            error_code="ai_not_configured",
            message="AI analysis is disabled because BHARATCODE_API_KEY is not set on the server.",
        )
    else:
        try:
            ai_review = await ai_client.review(code, language, static.findings, explain_language)
            ai_status = AIStatus(status="ok", model=settings.bharatcode_model, dropped_items=ai_review.dropped_items)
        except BharatCodeError as exc:
            logger.warning("AI review failed review_id=%s code=%s", review_id, exc.code)
            ai_status = AIStatus(status="error", model=settings.bharatcode_model, error_code=exc.code, message=str(exc))
        except Exception:  # noqa: BLE001 - never surface internals to the client
            logger.exception("Unexpected AI failure review_id=%s", review_id)
            ai_status = AIStatus(
                status="error", model=settings.bharatcode_model, error_code="ai_error",
                message="The AI review failed unexpectedly.",
            )

    if ai_review is None and not any(s.status == "ran" for s in static.scanners):
        details = "; ".join(s.detail for s in static.scanners if s.status in {"failed", "unavailable"} and s.detail)
        raise AnalysisUnavailable(
            "No analyzer could process this submission."
            + (f" {details}" if details else "")
            + (f" AI: {ai_status.message}" if ai_status.message else "")
        )

    findings = merge_ai(code, static.findings, ai_review) if ai_review else static.findings
    findings = with_owasp(findings)
    counts = severity_counts(findings)
    total = len(findings)
    score, grade = compute_score(findings)

    summary = ai_review.summary if ai_review else _fallback_summary(counts, total, language, ai_status)
    logger.info(
        "review_id=%s language=%s chars=%d findings=%d ai=%s",
        review_id, language, len(code), total, ai_status.status,
    )  # source code is never logged

    return ReviewResponse(
        review_id=review_id,
        status="complete" if ai_status.status == "ok" else "static_only",
        language=language,
        explain_language=explain_language,
        total_findings=total,
        score=score,
        grade=grade,
        counts=counts,
        summary=summary,
        best_practices=ai_review.best_practices if ai_review else [],
        findings=findings,
        scanners=static.scanners,
        ai=ai_status,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
