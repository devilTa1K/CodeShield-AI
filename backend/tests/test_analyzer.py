"""Scanner integration: Bandit, built-in rules, optional Semgrep."""

from __future__ import annotations

import asyncio
import json
import subprocess

import pytest

from app.services import analyzer
from app.services.analyzer import analyze_static, run_builtin_rules
from conftest import make_settings, sample


def run(code: str, language: str, **settings):
    return asyncio.run(analyze_static(code, language, make_settings(**settings)))


def rule_ids(result) -> set[str]:
    return {f.rule_id for f in result.findings}


def status(result, name: str):
    return next(s for s in result.scanners if s.name == name)


# --- Bandit (Python) ------------------------------------------------------- #
def test_bandit_flags_vulnerable_python():
    result = run(sample("vulnerable", "python"), "python")
    assert status(result, "Bandit").status == "ran"
    assert {"B602", "B608", "B301", "B307", "B324", "B105"} <= rule_ids(result)
    assert all(f.origin == "static_analysis" and f.tool == "Bandit" for f in result.findings)


def test_bandit_line_numbers_and_snippets_are_real():
    code = sample("vulnerable", "python")
    result = run(code, "python")
    eval_finding = next(f for f in result.findings if f.rule_id == "B307")
    assert "eval(" in eval_finding.snippet
    assert code.splitlines()[eval_finding.line_start - 1] in eval_finding.snippet


def test_bandit_clean_on_safe_python():
    result = run(sample("safe", "python"), "python")
    assert status(result, "Bandit").status == "ran"
    assert result.findings == []


def test_ids_are_sequential_and_sorted_by_severity():
    result = run(sample("vulnerable", "python"), "python")
    assert [f.id for f in result.findings] == [f"S{i}" for i in range(1, len(result.findings) + 1)]
    order = ["critical", "high", "medium", "low", "info"]
    ranks = [order.index(f.severity.value) for f in result.findings]
    assert ranks == sorted(ranks)


def test_bandit_syntax_error_is_reported_as_failed_not_crash():
    result = run("def broken(:\n    pass\n", "python")
    s = status(result, "Bandit")
    assert s.status == "failed" and "syntax" in s.detail.lower()


def test_bandit_unavailable_is_reported(monkeypatch):
    monkeypatch.setattr(analyzer, "bandit_available", lambda: False)
    result = run("x = 1\n", "python")
    assert status(result, "Bandit").status == "unavailable"


def test_bandit_timeout_is_reported(monkeypatch):
    def boom(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="bandit", timeout=1)

    monkeypatch.setattr(analyzer, "_run_bandit", boom)
    assert status(run("x = 1\n", "python"), "Bandit").status == "failed"


def test_submitted_code_is_never_executed(tmp_path):
    marker = tmp_path / "executed.txt"
    code = f"open({str(marker)!r}, 'w').write('pwned')\nimport os; os.system('touch {marker}')\n"
    run(code, "python")
    assert not marker.exists()


# --- Built-in rules -------------------------------------------------------- #
@pytest.mark.parametrize(
    "language, expected",
    [
        ("javascript", {"CS-SECRET-001", "CS-SQLI-001", "CS-JS-001", "CS-JS-003", "CS-JS-005", "CS-JS-007"}),
        ("typescript", {"CS-SECRET-001", "CS-JS-002", "CS-JS-003", "CS-JS-005", "CS-JS-007"}),
        ("java", {"CS-SECRET-001", "CS-SQLI-001", "CS-JV-001", "CS-JV-002", "CS-JV-003"}),
        ("c", {"CS-C-001", "CS-C-002", "CS-C-003", "CS-C-005", "CS-C-006"}),
    ],
)
def test_builtin_rules_flag_vulnerable_samples(language, expected):
    result = run(sample("vulnerable", language), language)
    assert expected <= rule_ids(result)
    assert status(result, "CodeShield rules").status == "ran"


@pytest.mark.parametrize("language", ["javascript", "typescript", "java", "c"])
def test_builtin_rules_quiet_on_safe_samples(language):
    assert run(sample("safe", language), language).findings == []


def test_gets_is_critical_and_has_cwe():
    f = next(f for f in run("char b[4];\ngets(b);\n", "c").findings if f.rule_id == "CS-C-001")
    assert f.severity.value == "critical" and f.cwe == "CWE-242" and f.line_start == 2


def test_comments_do_not_trigger_code_rules():
    assert run_builtin_rules(["// eval(userInput) is dangerous", "/* new Function(x) */"], "javascript") == []


def test_hardcoded_secret_in_comment_is_still_reported():
    findings = run_builtin_rules(['// password = "hunter2hunter2"'], "javascript")
    assert [f.rule_id for f in findings] == ["CS-SECRET-001"]


def test_unrelated_language_rules_do_not_leak():
    assert run_builtin_rules(["gets(buf);"], "javascript") == []


# --- Semgrep (optional) ---------------------------------------------------- #
def test_semgrep_skipped_when_not_configured():
    assert status(run("x = 1\n", "python"), "Semgrep").status == "skipped"


def test_semgrep_unavailable_when_configured_but_missing(monkeypatch):
    monkeypatch.setattr(analyzer, "semgrep_available", lambda: False)
    result = run("x = 1\n", "python", semgrep_config="rules.yml")
    assert status(result, "Semgrep").status == "unavailable"


def test_semgrep_results_are_parsed(monkeypatch):
    payload = {"results": [{
        "check_id": "rules.python.no-eval", "start": {"line": 1}, "end": {"line": 1},
        "extra": {"severity": "ERROR", "message": "Avoid eval", "metadata": {"cwe": ["CWE-95: Eval Injection"], "category": "security"}},
    }]}
    monkeypatch.setattr(analyzer, "semgrep_available", lambda: True)
    monkeypatch.setattr(
        analyzer, "_run",
        lambda cmd, cwd, timeout: subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(payload), stderr=""),
    )
    # a line the built-in rules do not flag, so the only finding comes from Semgrep
    result = run("dangerous(x)\n", "javascript", semgrep_config="rules.yml")
    s = status(result, "Semgrep")
    assert s.status == "ran" and s.findings == 1
    f = next(f for f in result.findings if f.tool == "Semgrep")
    assert f.severity.value == "high" and f.cwe == "CWE-95" and f.line_start == 1 and f.origin == "static_analysis"


def test_semgrep_duplicate_of_builtin_finding_is_skipped(monkeypatch):
    payload = {"results": [{
        "check_id": "rules.js.no-eval", "start": {"line": 1}, "end": {"line": 1},
        "extra": {"severity": "ERROR", "message": "Avoid eval", "metadata": {"cwe": ["CWE-95: Eval Injection"]}},
    }]}
    monkeypatch.setattr(analyzer, "semgrep_available", lambda: True)
    monkeypatch.setattr(
        analyzer, "_run",
        lambda cmd, cwd, timeout: subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(payload), stderr=""),
    )
    result = run("eval(x)\n", "javascript", semgrep_config="rules.yml")  # CS-JS-001 already reports this line + CWE
    assert status(result, "Semgrep").findings == 0
    assert [f.tool for f in result.findings] == ["CodeShield rules"]


def test_semgrep_garbage_output_is_reported_as_failed(monkeypatch):
    monkeypatch.setattr(analyzer, "semgrep_available", lambda: True)
    monkeypatch.setattr(
        analyzer, "_run",
        lambda cmd, cwd, timeout: subprocess.CompletedProcess(cmd, 0, stdout="not json", stderr=""),
    )
    assert status(run("x\n", "javascript", semgrep_config="r.yml"), "Semgrep").status == "failed"
