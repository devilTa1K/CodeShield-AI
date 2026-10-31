"""Score, grade, OWASP mapping and explanation-language plumbing."""

from __future__ import annotations

import pytest

from app.schemas import AIReview, Finding, Severity
from app.services.bharatcode import build_messages
from app.services.scoring import compute_score, owasp_for
from conftest import FakeAI, sample


def f(severity: Severity, origin="static_analysis", cwe=None) -> Finding:
    return Finding(id="S1", title="t", severity=severity, category="c", origin=origin, tool="x",
                   description="d", recommendation="r", cwe=cwe)


def test_no_findings_scores_100_grade_a():
    assert compute_score([]) == (100, "A")


@pytest.mark.parametrize(
    "findings, score, grade",
    [
        ([f(Severity.CRITICAL)], 75, "B"),
        ([f(Severity.CRITICAL), f(Severity.HIGH)], 60, "C"),
        ([f(Severity.CRITICAL), f(Severity.CRITICAL)], 50, "D"),
        ([f(Severity.CRITICAL)] * 4, 0, "F"),
        ([f(Severity.INFO)] * 10, 100, "A"),
        ([f(Severity.LOW)] * 3, 91, "A"),
    ],
)
def test_score_and_grade(findings, score, grade):
    assert compute_score(findings) == (score, grade)


def test_ai_hypotheses_count_half():
    assert compute_score([f(Severity.HIGH, origin="ai_hypothesis")])[0] == 93  # 100 - 7.5 -> 93 (rounded)


def test_score_never_negative():
    assert compute_score([f(Severity.CRITICAL)] * 20)[0] == 0


def test_owasp_mapping():
    assert owasp_for("CWE-89") == "A03:2021 Injection"
    assert owasp_for("CWE-327").startswith("A02:2021")
    assert owasp_for("CWE-798").startswith("A07:2021")
    assert owasp_for("CWE-502").startswith("A08:2021")
    assert owasp_for("CWE-12345") is None and owasp_for(None) is None


def post(client, **body):
    return client.post("/api/review", json={"language": "python", "code": sample("vulnerable", "python"), **body})


def test_response_has_score_grade_and_owasp(api):
    body = post(api()).json()
    assert 0 <= body["score"] < 100 and body["grade"] in "ABCDF"
    assert body["explain_language"] == "english"
    owasp = {x["rule_id"]: x["owasp"] for x in body["findings"]}
    assert owasp["B608"] == "A03:2021 Injection"  # SQL injection
    assert owasp["B324"].startswith("A02:2021")  # weak hash


def test_safe_sample_scores_100(api):
    res = api().post("/api/review", json={"language": "python", "code": sample("safe", "python")}).json()
    assert (res["score"], res["grade"]) == (100, "A")


def test_unsupported_explain_language_rejected(api):
    res = post(api(), explain_language="klingon")
    assert res.status_code == 400 and res.json()["error"]["code"] == "unsupported_explain_language"


def test_explain_language_is_passed_to_the_ai(api):
    fake = FakeAI(AIReview(summary="ठीक है"))
    body = post(api(fake), explain_language=" Hindi ").json()
    assert fake.explain_languages == ["hindi"] and body["explain_language"] == "hindi"


@pytest.mark.parametrize("lang, marker", [("hindi", "Devanagari"), ("hinglish", "Hinglish")])
def test_prompt_asks_for_requested_language(lang, marker):
    system = build_messages("x = 1\n", "python", [], lang)[0]["content"]
    assert marker in system and "JSON keys" in system


def test_english_prompt_has_no_language_rule():
    system = build_messages("x = 1\n", "python", [], "english")[0]["content"]
    assert "Output language" not in system
