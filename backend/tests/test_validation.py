"""Input validation on POST /api/review."""

from __future__ import annotations


def _post(client, **body):
    return client.post("/api/review", json=body)


def _code(res) -> str:
    return res.json()["error"]["code"]


def test_empty_code_rejected(api):
    res = _post(api(), code="", language="python")
    assert res.status_code == 400 and _code(res) == "empty_code"


def test_whitespace_only_code_rejected(api):
    res = _post(api(), code="   \n\t  \n", language="python")
    assert res.status_code == 400 and _code(res) == "empty_code"


def test_unsupported_language_rejected(api):
    res = _post(api(), code="print(1)", language="brainfuck")
    assert res.status_code == 400 and _code(res) == "unsupported_language"


def test_language_is_case_insensitive(api):
    res = _post(api(), code="x = 1\n", language="  Python ")
    assert res.status_code == 200 and res.json()["language"] == "python"


def test_oversized_code_rejected(api):
    res = _post(api(max_code_chars=100), code="a" * 101, language="python")
    assert res.status_code == 413 and _code(res) == "code_too_large"


def test_too_many_lines_rejected(api):
    res = _post(api(max_code_lines=5), code="x = 1\n" * 6, language="python")
    assert res.status_code == 413 and _code(res) == "code_too_large"


def test_null_bytes_rejected(api):
    res = _post(api(), code="x = 1\x00", language="python")
    assert res.status_code == 400 and _code(res) == "invalid_code"


def test_missing_fields_give_clean_422(api):
    res = api().post("/api/review", json={"code": "x"})
    assert res.status_code == 422 and _code(res) == "invalid_request"


def test_non_json_body_gives_clean_422(api):
    res = api().post("/api/review", content="not json", headers={"content-type": "application/json"})
    assert res.status_code == 422 and _code(res) == "invalid_request"


def test_huge_body_rejected_before_parsing(api):
    client = api(max_code_chars=100)
    res = client.post("/api/review", json={"code": "a" * 5000, "language": "python"})
    assert res.status_code == 413


def test_rate_limit(api):
    client = api(rate_limit_per_minute=2)
    statuses = [_post(client, code="x = 1\n", language="python").status_code for _ in range(3)]
    assert statuses == [200, 200, 429]
    assert _code(_post(client, code="x = 1\n", language="python")) == "rate_limited"


def test_health_and_rules(api):
    client = api()
    health = client.get("/health").json()
    assert health["status"] == "ok" and health["ai_configured"] is False
    rules = client.get("/api/rules").json()
    assert set(rules["languages"]) == {"python", "javascript", "typescript", "java", "c"}
    assert rules["scanners"]["codeshield_rules"]["rules"]


def test_responses_never_expose_the_api_key(api):
    client = api()
    for res in (client.get("/health"), client.get("/api/rules"), _post(client, code="x", language="zzz")):
        assert "test-key-not-real" not in res.text


def test_security_headers_present(api):
    res = api().get("/health")
    assert res.headers["x-content-type-options"] == "nosniff"


def test_cors_only_allows_configured_origin(api):
    client = api(cors_origins="http://localhost:5173")
    ok = client.get("/health", headers={"Origin": "http://localhost:5173"})
    bad = client.get("/health", headers={"Origin": "https://evil.example"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in bad.headers
