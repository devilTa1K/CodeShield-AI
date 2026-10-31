"""End-to-end behaviour of POST /api/review with a fake AI client."""

from __future__ import annotations

from app.schemas import AIFinding, AINote, AIReview
from app.services.bharatcode import BadResponseError, BharatCodeTimeout, PlanError
from conftest import FakeAI, sample


def post(client, code, language="python"):
    return client.post("/api/review", json={"code": code, "language": language})


def ai_review(**kw) -> AIReview:
    base = dict(summary="AI summary of the review.", best_practices=["Validate all input"])
    base.update(kw)
    return AIReview(**base)


def extra(**kw) -> AIFinding:
    base = dict(title="Missing authorization check", severity="critical", category="Access control",
                line_start=9, line_end=10, description="No check that the caller may read this user.",
                recommendation="Verify ownership before returning data.", confidence="medium", cwe="CWE-862")
    base.update(kw)
    return AIFinding(**base)


def test_static_only_when_ai_not_configured(api):
    res = post(api(FakeAI(configured=False)), sample("vulnerable", "python"))
    body = res.json()
    assert res.status_code == 200
    assert body["status"] == "static_only"
    assert body["ai"]["status"] == "not_configured"
    assert body["total_findings"] == len(body["findings"]) > 0
    assert all(f["origin"] == "static_analysis" and not f["ai_explained"] for f in body["findings"])
    assert "AI-assisted explanations are unavailable" in body["summary"]
    assert "not proof" not in body["summary"] or body["total_findings"] == 0  # never claims safety


def test_full_review_merges_ai_and_keeps_origins_separate(api):
    code = sample("vulnerable", "python")
    fake = FakeAI(ai_review(
        static_finding_notes=[AINote(id="S1", explanation="Plain words.", why_it_matters="Attackers run commands.",
                                     recommendation="Pass a list.", fixed_code="```python\nsubprocess.run(['cat', filename])\n```")],
        additional_findings=[extra()],
    ))
    body = post(api(fake), code).json()
    assert body["status"] == "complete" and body["ai"]["status"] == "ok"
    assert body["summary"] == "AI summary of the review."
    static = [f for f in body["findings"] if f["origin"] == "static_analysis"]
    hypotheses = [f for f in body["findings"] if f["origin"] == "ai_hypothesis"]
    assert len(hypotheses) == 1 and hypotheses[0]["tool"] == "BharatCode AI" and hypotheses[0]["id"] == "A1"
    explained = next(f for f in static if f["id"] == "S1")
    assert explained["ai_explained"] and explained["explanation"] == "Plain words."
    assert explained["suggested_code"] == "subprocess.run(['cat', filename])"  # fences stripped
    assert sum(body["counts"].values()) == body["total_findings"] == len(body["findings"])
    assert fake.calls and fake.calls[0][0] == "python"


def test_ai_hypotheses_are_capped_below_critical(api):
    body = post(api(FakeAI(ai_review(additional_findings=[extra(severity="critical")]))), sample("vulnerable", "python")).json()
    hyp = next(f for f in body["findings"] if f["origin"] == "ai_hypothesis")
    assert hyp["severity"] == "high"


def test_ai_snippet_comes_from_user_code_and_bad_lines_are_dropped(api):
    code = "a = 1\nb = 2\nc = 3\n"
    fake = FakeAI(ai_review(additional_findings=[
        extra(title="In range", line_start=2, line_end=2),
        extra(title="Out of range", line_start=99, line_end=120),
    ]))
    findings = {f["title"]: f for f in post(api(fake), code).json()["findings"]}
    assert findings["In range"]["snippet"] == "b = 2"
    assert findings["Out of range"]["line_start"] is None and findings["Out of range"]["snippet"] == ""


def test_ai_duplicate_of_scanner_finding_is_not_repeated(api):
    code = "x = 1\nresult = eval(user_input)\n"
    dup = extra(title="eval is dangerous", severity="high", category="Code execution", line_start=2, line_end=2, cwe="CWE-95")
    body = post(api(FakeAI(ai_review(additional_findings=[dup]))), code).json()
    assert [f for f in body["findings"] if f["origin"] == "ai_hypothesis"] == []


def test_unknown_note_ids_are_ignored(api):
    fake = FakeAI(ai_review(static_finding_notes=[AINote(id="S999", explanation="ghost")]))
    body = post(api(fake), sample("vulnerable", "python")).json()
    assert not any(f["explanation"] == "ghost" for f in body["findings"])


def test_ai_failure_degrades_to_static_results_without_fabrication(api):
    for error, code in [(PlanError(), "ai_plan_required"), (BharatCodeTimeout(), "ai_timeout"), (BadResponseError(), "ai_bad_response")]:
        res = post(api(FakeAI(error=error)), sample("vulnerable", "c"), "c")
        body = res.json()
        assert res.status_code == 200 and body["status"] == "static_only"
        assert body["ai"]["status"] == "error" and body["ai"]["error_code"] == code and body["ai"]["message"]
        assert body["findings"] and all(f["origin"] == "static_analysis" for f in body["findings"])
        assert body["best_practices"] == []


def test_unexpected_ai_exception_does_not_leak_details(api):
    res = post(api(FakeAI(error=RuntimeError("secret-internal-detail /srv/app.py"))), sample("vulnerable", "c"), "c")
    assert res.status_code == 200
    assert "secret-internal-detail" not in res.text and "Traceback" not in res.text


def test_safe_sample_reports_no_findings_and_never_claims_security(api):
    body = post(api(), sample("safe", "javascript"), "javascript").json()
    assert body["total_findings"] == 0
    assert "secure" not in body["summary"].lower() or "not proof" in body["summary"].lower()
    assert "no review can prove" in body["disclaimer"]


def test_ai_still_works_when_no_scanner_can_run(api, monkeypatch):
    from app.services import analyzer
    monkeypatch.setattr(analyzer, "bandit_available", lambda: False)
    body = post(api(FakeAI(ai_review(additional_findings=[extra(line_start=1, line_end=1)]))), "x = 1\n").json()
    assert body["status"] == "complete"
    assert next(s for s in body["scanners"] if s["name"] == "Bandit")["status"] == "unavailable"
    assert [f["origin"] for f in body["findings"]] == ["ai_hypothesis"]


def test_503_when_nothing_can_analyze(api, monkeypatch):
    from app.services import analyzer
    monkeypatch.setattr(analyzer, "bandit_available", lambda: False)
    res = post(api(FakeAI(configured=False)), "x = 1\n")
    assert res.status_code == 503 and res.json()["error"]["code"] == "analysis_unavailable"


def test_syntax_error_python_without_ai_is_a_clear_503(api):
    res = post(api(FakeAI(configured=False)), "def broken(:\n")
    assert res.status_code == 503 and "syntax" in res.json()["error"]["message"].lower()


def test_unhandled_error_returns_generic_500(api, monkeypatch):
    from app import main

    async def boom(*_a, **_k):
        raise ValueError("internal path /etc/shadow")

    monkeypatch.setattr(main, "perform_review", boom)
    res = post(api(), "x = 1\n")
    assert res.status_code == 500 and res.json() == {"error": {"code": "internal_error", "message": "Something went wrong on the server."}}


def test_review_works_for_every_supported_language(api):
    client = api()
    for language in ("python", "javascript", "typescript", "java", "c"):
        res = post(client, sample("vulnerable", language), language)
        assert res.status_code == 200 and res.json()["total_findings"] > 0, language
