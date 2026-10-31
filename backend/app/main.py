"""FastAPI application: /health, /api/rules, POST /api/review."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .config import Settings, get_settings
from .schemas import SUPPORTED_LANGUAGES, ReviewRequest, ReviewResponse
from .services.analyzer import BUILTIN_RULES, bandit_available, semgrep_available
from .services.bharatcode import BharatCodeClient
from .services.review import AIClient, AnalysisUnavailable, perform_review

logger = logging.getLogger("codeshield")


class AppError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


class RateLimiter:
    """Tiny in-memory sliding-window limiter (per client address, per process)."""

    def __init__(self, limit: int, window: float = 60.0):
        self.limit, self.window = limit, window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(self._hits) > 5000:  # bound memory
            for k in [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]:
                self._hits.pop(k, None)
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True


def create_app(settings: Optional[Settings] = None, ai_client: Optional[AIClient] = None) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    ai_client = ai_client or BharatCodeClient(settings)
    limiter = RateLimiter(settings.rate_limit_per_minute)
    max_body = settings.max_code_chars * 4 + 10_000  # JSON escaping can inflate the code

    app = FastAPI(title="CodeShield AI", version=__version__, docs_url="/docs", redoc_url=None)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @app.middleware("http")
    async def guard(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > max_body:
            return _error(413, "code_too_large", "The request body is too large.")
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError):
        return _error(exc.status, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, __: RequestValidationError):
        return _error(422, "invalid_request", "Request must be JSON with string fields 'code' and 'language'.")

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        logger.error("Unhandled error: %s", type(exc).__name__)  # no stack trace or payload to the client
        return _error(500, "internal_error", "Something went wrong on the server.")

    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "version": __version__,
            "ai_configured": ai_client.configured,
            "model": settings.bharatcode_model,
            "max_code_chars": settings.max_code_chars,
        }

    @app.get("/api/rules")
    async def rules():
        return {
            "languages": list(SUPPORTED_LANGUAGES),
            "limits": {"max_code_chars": settings.max_code_chars, "max_code_lines": settings.max_code_lines},
            "scanners": {
                "bandit": {"available": bandit_available(), "languages": ["python"]},
                "semgrep": {
                    "available": semgrep_available(),
                    "enabled": bool(settings.semgrep_config.strip()) and semgrep_available(),
                },
                "codeshield_rules": {
                    "available": True,
                    "rules": [
                        {"id": r.id, "title": r.title, "severity": r.severity.value, "category": r.category,
                         "cwe": r.cwe, "languages": list(r.languages)}
                        for r in BUILTIN_RULES
                    ],
                },
            },
            "ai": {"configured": ai_client.configured, "model": settings.bharatcode_model},
        }

    @app.post("/api/review", response_model=ReviewResponse)
    async def review(body: ReviewRequest, request: Request):
        client_key = request.client.host if request.client else "unknown"
        if not limiter.allow(client_key):
            raise AppError(429, "rate_limited", "Too many review requests. Please wait a minute and retry.")

        language = body.language.strip().lower()
        if language not in SUPPORTED_LANGUAGES:
            raise AppError(400, "unsupported_language",
                           f"Unsupported language. Choose one of: {', '.join(SUPPORTED_LANGUAGES)}.")
        if not body.code.strip():
            raise AppError(400, "empty_code", "Paste some code to review.")
        if "\x00" in body.code:
            raise AppError(400, "invalid_code", "The code contains null bytes and cannot be reviewed.")
        if len(body.code) > settings.max_code_chars:
            raise AppError(413, "code_too_large",
                           f"Code is limited to {settings.max_code_chars:,} characters.")
        if body.code.count("\n") + 1 > settings.max_code_lines:
            raise AppError(413, "code_too_large", f"Code is limited to {settings.max_code_lines:,} lines.")

        try:
            return await perform_review(body.code, language, settings, ai_client)
        except AnalysisUnavailable as exc:
            raise AppError(503, "analysis_unavailable", str(exc)) from None

    return app


app = create_app()
