"""Scan a public GitHub repository by URL (GitHub is mocked; nothing here touches the network)."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.github_fetch import GithubFetcher, parse_github_url
from app.services.project_scan import MAX_ZIP_BYTES, ScanInputError
from conftest import FakeAI, make_settings, sample
from test_project_scan import FakeChecker, make_zip


class FakeFetcher:
    def __init__(self, data: bytes | None = None, error: ScanInputError | None = None):
        self.data, self.error = data, error
        self.calls: list[tuple] = []

    async def fetch(self, owner, repo, ref):
        self.calls.append((owner, repo, ref))
        if self.error:
            raise self.error
        return self.data


def client(fetcher, **settings) -> TestClient:
    app = create_app(make_settings(**settings), FakeAI(configured=False), FakeChecker(), fetcher)
    return TestClient(app, raise_server_exceptions=False)


def post(c: TestClient, url: str):
    return c.post("/api/scan/github", json={"url": url})


# --------------------------------------------------------------------------- #
# URL parsing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("url, expected", [
    ("https://github.com/devilTa1K/CodeShield-AI", ("devilTa1K", "CodeShield-AI", None)),
    ("github.com/octo/repo.git", ("octo", "repo", None)),
    ("  https://www.github.com/octo/repo/  ", ("octo", "repo", None)),
    ("https://github.com/octo/repo/tree/feature/login", ("octo", "repo", "feature/login")),
    ("https://github.com/octo/repo?tab=readme#top", ("octo", "repo", None)),
])
def test_parse_accepts_normal_repository_urls(url, expected):
    assert parse_github_url(url) == expected


@pytest.mark.parametrize("url", [
    "", "not a url", "https://gitlab.com/a/b", "https://github.com/onlyowner",
    "https://evil.com/github.com/a/b", "https://github.com.evil.com/a/b",
    "https://github.com/../etc", "https://github.com/a/..", "https://github.com/a/b/tree/../x",
    "http://169.254.169.254/latest/meta-data", "file:///etc/passwd",
])
def test_parse_rejects_everything_that_is_not_a_github_repository(url):
    with pytest.raises(ScanInputError) as exc:
        parse_github_url(url)
    assert exc.value.code == "invalid_github_url"


# --------------------------------------------------------------------------- #
# Endpoint
# --------------------------------------------------------------------------- #
def test_scans_a_repository_and_reports_its_name():
    zipped = make_zip({"repo-HEAD/app.py": sample("vulnerable", "python"), "repo-HEAD/README.md": "hi"})
    fetcher = FakeFetcher(zipped)
    res = post(client(fetcher), "https://github.com/octo/repo/tree/dev")
    body = res.json()
    assert res.status_code == 200
    assert fetcher.calls == [("octo", "repo", "dev")]
    assert body["source"] == "octo/repo@dev"
    assert body["files_scanned"] == 1 and body["total_findings"] > 0
    assert {f["file"] for f in body["findings"]} == {"app.py"}


def test_bad_urls_never_reach_the_fetcher():
    fetcher = FakeFetcher(b"")
    res = post(client(fetcher), "http://169.254.169.254/latest/meta-data")
    assert res.status_code == 400 and res.json()["error"]["code"] == "invalid_github_url"
    assert fetcher.calls == []


@pytest.mark.parametrize("error, status, code", [
    (ScanInputError("repo_not_found", "Repository or branch not found.", 404), 404, "repo_not_found"),
    (ScanInputError("github_rate_limited", "Slow down.", 429), 429, "github_rate_limited"),
    (ScanInputError("github_unavailable", "GitHub is down.", 502), 502, "github_unavailable"),
    (ScanInputError("zip_too_large", "Too big.", 413), 413, "zip_too_large"),
])
def test_fetch_failures_become_clear_errors(error, status, code):
    res = post(client(FakeFetcher(error=error)), "https://github.com/octo/repo")
    assert res.status_code == status and res.json()["error"]["code"] == code


def test_a_non_zip_response_is_reported_as_invalid():
    res = post(client(FakeFetcher(b"<html>not a zip</html>")), "https://github.com/octo/repo")
    assert res.status_code == 400 and res.json()["error"]["code"] == "invalid_zip"


def test_github_scan_is_rate_limited():
    c = client(FakeFetcher(make_zip({"a.py": "x = 1\n"})), rate_limit_per_minute=1)
    assert post(c, "https://github.com/octo/repo").status_code == 200
    assert post(c, "https://github.com/octo/repo").status_code == 429


# --------------------------------------------------------------------------- #
# Fetcher (mocked HTTP)
# --------------------------------------------------------------------------- #
def fetcher_for(handler) -> GithubFetcher:
    return GithubFetcher("https://codeload.test", transport=httpx.MockTransport(handler))


def test_fetcher_requests_the_codeload_zip_for_head_or_a_branch():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, content=b"PK-data")

    f = fetcher_for(handler)
    assert asyncio.run(f.fetch("octo", "repo", None)) == b"PK-data"
    asyncio.run(f.fetch("octo", "repo", "dev"))
    assert seen == ["https://codeload.test/octo/repo/zip/HEAD", "https://codeload.test/octo/repo/zip/dev"]


@pytest.mark.parametrize("status, code", [(404, "repo_not_found"), (403, "github_rate_limited"),
                                          (429, "github_rate_limited"), (500, "github_unavailable"),
                                          (302, "github_unavailable")])
def test_fetcher_maps_http_statuses(status, code):
    f = fetcher_for(lambda request: httpx.Response(status))
    with pytest.raises(ScanInputError) as exc:
        asyncio.run(f.fetch("octo", "repo", None))
    assert exc.value.code == code


def test_fetcher_stops_oversized_downloads_by_header_and_by_streaming():
    declared = fetcher_for(lambda r: httpx.Response(200, headers={"content-length": str(MAX_ZIP_BYTES + 1)}, content=b"x"))
    streamed = fetcher_for(lambda r: httpx.Response(200, content=b"x" * (MAX_ZIP_BYTES + 10)))
    for f in (declared, streamed):
        with pytest.raises(ScanInputError) as exc:
            asyncio.run(f.fetch("octo", "repo", None))
        assert exc.value.code == "zip_too_large"


def test_fetcher_reports_network_errors():
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    with pytest.raises(ScanInputError) as exc:
        asyncio.run(fetcher_for(down).fetch("octo", "repo", None))
    assert exc.value.code == "github_unavailable" and exc.value.status == 502


def test_github_scan_can_include_test_files():
    zipped = make_zip({"repo-HEAD/app.py": "x = 1\n", "repo-HEAD/tests/test_x.py": sample("vulnerable", "python")})
    c = client(FakeFetcher(zipped))
    default = c.post("/api/scan/github", json={"url": "https://github.com/octo/repo"}).json()
    with_tests = c.post("/api/scan/github", json={"url": "https://github.com/octo/repo", "include_tests": True}).json()
    assert (default["files_scanned"], default["excluded_tests"], default["total_findings"]) == (1, 1, 0)
    assert with_tests["files_scanned"] == 2 and with_tests["total_findings"] > 0
