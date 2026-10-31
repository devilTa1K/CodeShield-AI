"""Download a public GitHub repository as a ZIP so it can be scanned like an uploaded project.

Only github.com repository URLs are accepted and only codeload.github.com is contacted, so a
user-supplied URL can never make the server fetch an arbitrary address.
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Protocol

import httpx

from .project_scan import MAX_ZIP_BYTES, ScanInputError

logger = logging.getLogger("codeshield.github")

_NAME = r"[A-Za-z0-9_.-]{1,100}"
_URL = re.compile(
    rf"^(?:https?://)?(?:www\.)?github\.com/({_NAME})/({_NAME})"
    r"(?:/tree/([A-Za-z0-9_./-]{1,200}))?/?(?:[?#].*)?$"
)


class RepoFetcher(Protocol):
    async def fetch(self, owner: str, repo: str, ref: Optional[str]) -> bytes: ...


def parse_github_url(url: str) -> tuple[str, str, Optional[str]]:
    """Return (owner, repo, branch-or-None) for a github.com repository URL."""
    match = _URL.match((url or "").strip())
    if not match:
        raise ScanInputError("invalid_github_url", "Enter a public repository URL like https://github.com/owner/repo.")
    owner, repo, ref = match.groups()
    repo = repo.removesuffix(".git")
    bad = lambda s: not s or set(s) <= {"."}  # noqa: E731 - rejects "." and ".."
    if bad(owner) or bad(repo) or (ref is not None and (".." in ref or ref.startswith("/"))):
        raise ScanInputError("invalid_github_url", "Enter a public repository URL like https://github.com/owner/repo.")
    return owner, repo, ref


class GithubFetcher:
    def __init__(
        self,
        base_url: str = "https://codeload.github.com",
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        timeout: float = 30.0,
    ):
        self._base = base_url.rstrip("/")
        self._transport = transport
        self._timeout = timeout

    async def fetch(self, owner: str, repo: str, ref: Optional[str]) -> bytes:
        url = f"{self._base}/{owner}/{repo}/zip/{ref or 'HEAD'}"
        too_big = ScanInputError(
            "zip_too_large", f"That repository is larger than {MAX_ZIP_BYTES // (1024 * 1024)} MB. Upload a ZIP of just the part you want scanned.", 413
        )
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout, follow_redirects=False) as client:
                async with client.stream("GET", url) as res:
                    if res.status_code == 404:
                        raise ScanInputError(
                            "repo_not_found", "Repository or branch not found. Only public repositories can be scanned.", 404
                        )
                    if res.status_code in (403, 429):
                        raise ScanInputError("github_rate_limited", "GitHub is limiting requests right now. Try again in a minute.", 429)
                    if res.status_code != 200:
                        raise ScanInputError("github_unavailable", "GitHub could not provide that repository. Try again later.", 502)
                    declared = res.headers.get("content-length", "")
                    if declared.isdigit() and int(declared) > MAX_ZIP_BYTES:
                        raise too_big
                    data = bytearray()
                    async for chunk in res.aiter_bytes():
                        data += chunk
                        if len(data) > MAX_ZIP_BYTES:
                            raise too_big
                    return bytes(data)
        except httpx.HTTPError as exc:
            logger.warning("GitHub download failed: %s", type(exc).__name__)
            raise ScanInputError("github_unavailable", "Could not reach GitHub. Try again later.", 502) from None
