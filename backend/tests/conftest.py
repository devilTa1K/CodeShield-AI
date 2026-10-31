from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.schemas import AIReview, Finding
from app.services.bharatcode import BharatCodeError

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
EXTENSIONS = {"python": "py", "javascript": "js", "typescript": "ts", "java": "java", "c": "c"}


def sample(kind: str, language: str) -> str:
    return (SAMPLES / f"{kind}.{EXTENSIONS[language]}").read_text(encoding="utf-8")


def make_settings(**overrides) -> Settings:
    base = dict(
        bharatcode_api_key="test-key-not-real",
        bharatcode_base_url="https://bharatcode.test/api/model/v1",
        bharatcode_max_retries=2,
        rate_limit_per_minute=1000,
        _env_file=None,
    )
    base.update(overrides)
    return Settings(**base)


class FakeAI:
    """Stands in for BharatCodeClient in API-level tests."""

    def __init__(self, review: Optional[AIReview] = None, error: Optional[Exception] = None, configured: bool = True):
        self._review, self._error, self._configured = review, error, configured
        self.calls: list[tuple[str, str, int]] = []

    @property
    def configured(self) -> bool:
        return self._configured

    async def review(self, code: str, language: str, static_findings: Sequence[Finding]) -> AIReview:
        self.calls.append((language, code, len(static_findings)))
        if self._error:
            raise self._error
        assert self._review is not None
        return self._review


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def api():
    """Factory: api(ai=FakeAI(...), **settings) -> TestClient."""

    def _make(ai: Optional[FakeAI] = None, **overrides) -> TestClient:
        s = make_settings(**overrides)
        return TestClient(create_app(s, ai or FakeAI(configured=False)), raise_server_exceptions=False)

    return _make
