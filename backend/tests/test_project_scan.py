"""Project (ZIP) scan: archive handling, per-file findings, dependency checks, and OSV parsing."""

from __future__ import annotations

import asyncio
import io
import json
import zipfile

import httpx
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import Severity
from app.services.osv import (
    OsvClient,
    OsvResult,
    OsvVuln,
    Package,
    parse_manifests,
    parse_package_json,
    parse_package_lock,
    parse_requirements,
)
from conftest import FakeAI, make_settings, sample


def make_zip(files: dict[str, str | bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


class FakeChecker:
    def __init__(self, result: OsvResult | None = None):
        self.result = result or OsvResult(status="ok")
        self.calls: list[list[Package]] = []

    async def check(self, packages):
        self.calls.append(list(packages))
        return self.result


def client(checker=None, **settings) -> TestClient:
    app = create_app(make_settings(**settings), FakeAI(configured=False), checker or FakeChecker())
    return TestClient(app, raise_server_exceptions=False)


def scan(c: TestClient, data: bytes):
    return c.post("/api/scan", content=data, headers={"Content-Type": "application/zip"})


# --------------------------------------------------------------------------- #
# Archive handling
# --------------------------------------------------------------------------- #
def test_scans_every_supported_file_and_labels_findings_with_paths():
    data = make_zip({
        "proj/app.py": sample("vulnerable", "python"),
        "proj/web/app.js": sample("vulnerable", "javascript"),
        "proj/README.md": "# hello",
    })
    res = scan(client(), data)
    body = res.json()
    assert res.status_code == 200
    assert body["files_scanned"] == 2
    assert body["languages"] == {"python": 1, "javascript": 1}
    files = {f["file"] for f in body["findings"]}
    assert files == {"app.py", "web/app.js"}  # the common top-level folder is stripped
    assert body["total_findings"] == len(body["findings"]) > 0
    assert body["grade"] in "ABCDF" and 0 <= body["score"] <= 100
    assert all(f["id"].startswith("P") for f in body["findings"])
    assert [f["severity"] for f in body["findings"]] == sorted(
        (f["severity"] for f in body["findings"]), key=lambda s: ["critical", "high", "medium", "low", "info"].index(s))


def test_skips_vendored_and_build_folders():
    data = make_zip({
        "app.py": "print('ok')\n",
        "node_modules/lib/index.js": sample("vulnerable", "javascript"),
        ".venv/lib/x.py": sample("vulnerable", "python"),
        "dist/bundle.js": sample("vulnerable", "javascript"),
    })
    body = scan(client(), data).json()
    assert body["files_scanned"] == 1
    assert body["total_findings"] == 0


def test_path_traversal_names_are_skipped_not_scanned():
    data = make_zip({"../../evil.py": sample("vulnerable", "python"), "ok.py": "x = 1\n"})
    body = scan(client(), data).json()
    assert body["files_scanned"] == 1
    assert any(s["reason"] == "unsafe path" for s in body["skipped"])


def test_binary_and_oversized_files_are_reported_as_skipped():
    data = make_zip({"a.py": b"\x00\x01\x02binary", "big.py": "x = 1\n" * 100_000, "fine.py": "y = 2\n"})
    body = scan(client(), data).json()
    reasons = {s["path"]: s["reason"] for s in body["skipped"]}
    assert reasons["a.py"] == "binary file"
    assert "too large" in reasons["big.py"]
    assert body["files_scanned"] == 1


def test_file_count_limit_is_enforced_and_reported():
    data = make_zip({f"src/f{i}.js": "const a = 1;\n" for i in range(152)})
    body = scan(client(), data).json()
    assert body["files_scanned"] == 150
    assert body["files_skipped"] == 2
    assert all("file limit" in s["reason"] for s in body["skipped"])


def test_env_file_is_flagged_but_examples_are_not():
    data = make_zip({
        ".env": "API_KEY=abc123\nDEBUG=true\n",
        ".env.example": "API_KEY=\n",
        "config.yml": 'db_password: "SuperSecret123!"\n',
    })
    body = scan(client(), data).json()
    by_file = {(f["file"], f["rule_id"]) for f in body["findings"]}
    assert (".env", "CS-ENV-001") in by_file
    assert not any(f["file"] == ".env.example" for f in body["findings"])
    assert ("config.yml", "CS-SECRET-001") in by_file
    env = next(f for f in body["findings"] if f["rule_id"] == "CS-ENV-001")
    assert "abc123" not in json.dumps(env)  # values are never echoed back


def test_invalid_empty_and_oversized_uploads_get_clear_errors():
    c = client()
    assert scan(c, b"this is not a zip").json()["error"]["code"] == "invalid_zip"
    res = scan(c, b"")
    assert res.status_code == 400 and res.json()["error"]["code"] == "empty_upload"
    res = scan(c, b"0" * (10 * 1024 * 1024 + 8192))
    assert res.status_code == 413


def test_zip_bomb_is_rejected_by_declared_size():
    bomb = make_zip({"zeros.py": b"\x00" * (70 * 1024 * 1024)})
    assert len(bomb) < 10 * 1024 * 1024  # small on the wire, huge when expanded
    res = scan(client(), bomb)
    assert res.status_code == 413 and res.json()["error"]["code"] == "zip_too_large"


def test_scan_endpoint_is_rate_limited():
    c = client(rate_limit_per_minute=1)
    data = make_zip({"a.py": "x = 1\n"})
    assert scan(c, data).status_code == 200
    assert scan(c, data).status_code == 429


# --------------------------------------------------------------------------- #
# Dependencies
# --------------------------------------------------------------------------- #
def test_vulnerable_dependency_becomes_a_finding_with_the_manifest_line():
    vuln = OsvVuln(id="GHSA-xxxx", summary="Header injection.", severity=Severity.HIGH, fixed="2.20.0")
    checker = FakeChecker(OsvResult(status="ok", vulns={("PyPI", "requests", "2.19.0"): [vuln]}))
    data = make_zip({"requirements.txt": "# deps\nflask>=2.0\nrequests==2.19.0\n"})
    body = scan(client(checker), data).json()
    dep = next(f for f in body["findings"] if f["tool"] == "OSV.dev")
    assert (dep["file"], dep["line_start"], dep["severity"]) == ("requirements.txt", 3, "high")
    assert dep["category"] == "Vulnerable dependency"
    assert "2.20.0" in dep["recommendation"]
    assert body["dependencies"]["status"] == "ok"
    assert body["dependencies"]["checked"] == 1 and body["dependencies"]["vulnerable"] == 1
    assert body["dependencies"]["unpinned"] == 1
    assert any(s["name"] == "OSV.dev" and s["status"] == "ran" for s in body["scanners"])


def test_scan_still_succeeds_when_osv_is_unreachable():
    checker = FakeChecker(OsvResult(status="unavailable", message="The vulnerability database (OSV.dev) could not be reached."))
    data = make_zip({"app.py": sample("vulnerable", "python"), "requirements.txt": "requests==2.19.0\n"})
    res = scan(client(checker), data)
    body = res.json()
    assert res.status_code == 200 and body["total_findings"] > 0
    assert body["dependencies"]["status"] == "unavailable"


def test_no_manifests_means_no_dependency_check():
    checker = FakeChecker()
    body = scan(client(checker), make_zip({"a.py": "x = 1\n"})).json()
    assert body["dependencies"]["status"] == "none" and checker.calls == []


def test_only_package_names_and_versions_are_sent_to_the_checker():
    checker = FakeChecker()
    data = make_zip({"app.py": sample("vulnerable", "python"), "requirements.txt": "requests==2.19.0\n"})
    scan(client(checker), data)
    assert checker.calls == [[Package("PyPI", "requests", "2.19.0", "requirements.txt")]]


# --------------------------------------------------------------------------- #
# Manifest parsing
# --------------------------------------------------------------------------- #
def test_parse_requirements_handles_extras_markers_comments_and_options():
    text = "\n".join([
        "# comment", "-r other.txt", "fastapi==0.1.0  # inline",
        "uvicorn[standard]==0.5.0 ; python_version > '3.8'", "django>=3.0", "numpy", "git+https://x/y.git",
    ])
    pkgs, unpinned = parse_requirements(text, "requirements.txt")
    assert [(p.name, p.version) for p in pkgs] == [("fastapi", "0.1.0"), ("uvicorn", "0.5.0")]
    assert unpinned == 2


def test_parse_package_json_reads_exact_and_caret_versions_only():
    text = json.dumps({"dependencies": {"a": "^1.2.3", "b": "2.0.0", "c": "latest", "d": ">=1 <2"},
                       "devDependencies": {"e": "~3.1.4"}})
    pkgs, unpinned = parse_package_json(text, "package.json")
    assert [(p.name, p.version) for p in pkgs] == [("a", "1.2.3"), ("b", "2.0.0"), ("e", "3.1.4")]
    assert unpinned == 2


def test_lockfile_wins_over_package_json_in_the_same_folder():
    lock = json.dumps({"packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"},
                                    "node_modules/a/node_modules/b": {"version": "1.0.0"}}})
    files = {"web/package.json": json.dumps({"dependencies": {"lodash": "^4.0.0"}}),
             "web/package-lock.json": lock, "api/package.json": json.dumps({"dependencies": {"x": "1.0.0"}})}
    pkgs, _ = parse_manifests(files)
    assert {(p.name, p.version) for p in pkgs} == {("lodash", "4.17.20"), ("b", "1.0.0"), ("x", "1.0.0")}
    assert parse_package_lock("not json", "p") == []


# --------------------------------------------------------------------------- #
# OSV client (mocked HTTP)
# --------------------------------------------------------------------------- #
def osv_client(handler) -> OsvClient:
    return OsvClient("https://osv.test", transport=httpx.MockTransport(handler))


def test_osv_client_maps_batch_hits_to_severity_and_fixed_version():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            body = json.loads(request.content)
            assert body["queries"][0] == {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.0"}
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-1"}]}, {}]})
        assert request.url.path == "/v1/vulns/GHSA-1"
        return httpx.Response(200, json={
            "id": "GHSA-1", "summary": "Bad thing", "aliases": ["CVE-2018-18074"],
            "database_specific": {"severity": "MODERATE"},
            "affected": [{"package": {"name": "requests"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}],
        })

    result = asyncio.run(osv_client(handler).check([Package("PyPI", "requests", "2.19.0", "r.txt"),
                                                    Package("PyPI", "flask", "3.0.0", "r.txt")]))
    assert result.status == "ok"
    (vuln,) = result.vulns[("PyPI", "requests", "2.19.0")]
    assert (vuln.id, vuln.severity, vuln.fixed, vuln.aliases) == ("GHSA-1", Severity.MEDIUM, "2.20.0", ["CVE-2018-18074"])
    assert ("PyPI", "flask", "3.0.0") not in result.vulns


def test_osv_client_keeps_the_advisory_when_details_fail():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "OSV-9"}]}]})
        return httpx.Response(500)

    result = asyncio.run(osv_client(handler).check([Package("npm", "x", "1.0.0", "package.json")]))
    (vuln,) = result.vulns[("npm", "x", "1.0.0")]
    assert vuln.id == "OSV-9" and vuln.severity == Severity.MEDIUM


def test_osv_client_reports_unavailable_on_network_or_server_errors():
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    def broken(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    pkg = [Package("npm", "x", "1.0.0", "package.json")]
    assert asyncio.run(osv_client(down).check(pkg)).status == "unavailable"
    assert asyncio.run(osv_client(broken).check(pkg)).status == "unavailable"


# --------------------------------------------------------------------------- #
# Test / sample files
# --------------------------------------------------------------------------- #
TEST_LAYOUT = {
    "app.py": "x = 1\n",
    "tests/test_app.py": sample("vulnerable", "python"),
    "samples/vulnerable.js": sample("vulnerable", "javascript"),
    "web/Button.test.tsx": "const a = eval('1');\n",
    "conftest.py": sample("vulnerable", "python"),
}


def test_test_and_sample_files_are_left_out_by_default_and_counted():
    body = scan(client(), make_zip(TEST_LAYOUT)).json()
    assert body["files_scanned"] == 1 and body["total_findings"] == 0
    assert body["excluded_tests"] == 4


def test_include_tests_flag_scans_them_too():
    res = client().post("/api/scan?include_tests=true", content=make_zip(TEST_LAYOUT), headers={"Content-Type": "application/zip"})
    body = res.json()
    assert body["files_scanned"] == 5 and body["total_findings"] > 0 and body["excluded_tests"] == 0
