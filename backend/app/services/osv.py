"""Dependency manifest parsing and vulnerability lookup through OSV.dev (free, no API key).

Only package names and versions leave the server; source code is never sent to OSV.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

import httpx

from ..schemas import Severity

logger = logging.getLogger("codeshield.osv")

MAX_PACKAGES = 1500
BATCH_SIZE = 500
MAX_DETAIL_LOOKUPS = 40


@dataclass(frozen=True)
class Package:
    ecosystem: str  # "PyPI" or "npm"
    name: str
    version: str
    source: str  # manifest path inside the ZIP


@dataclass
class OsvVuln:
    id: str
    summary: str = ""
    severity: Severity = Severity.MEDIUM
    fixed: Optional[str] = None
    aliases: list[str] = field(default_factory=list)


@dataclass
class OsvResult:
    status: str  # "ok" | "unavailable"
    message: Optional[str] = None
    # (ecosystem, name, version) -> vulnerabilities affecting that exact version
    vulns: dict[tuple[str, str, str], list[OsvVuln]] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Manifest parsing
# --------------------------------------------------------------------------- #
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?")
_REQ_PINNED = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)")
_NPM_EXACT = re.compile(r"^[\^~=v\s]*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")


def is_requirements_file(path: str) -> bool:
    base = path.rsplit("/", 1)[-1].lower()
    return base.endswith(".txt") and "requirements" in base


def parse_requirements(text: str, source: str) -> tuple[list[Package], int]:
    packages: list[Package] = []
    unpinned = 0
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith(("#", "-")) or "://" in line:
            continue
        pinned = _REQ_PINNED.match(line)
        if pinned:
            packages.append(Package("PyPI", pinned.group(1), pinned.group(2), source))
        elif _REQ_NAME.match(line):
            unpinned += 1
    return packages, unpinned


def parse_package_json(text: str, source: str) -> tuple[list[Package], int]:
    try:
        data = json.loads(text)
    except ValueError:
        return [], 0
    packages: list[Package] = []
    unpinned = 0
    if not isinstance(data, dict):
        return [], 0
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            match = _NPM_EXACT.match(spec.strip()) if isinstance(spec, str) else None
            if match:
                packages.append(Package("npm", str(name), match.group(1), source))
            else:
                unpinned += 1
    return packages, unpinned


def parse_package_lock(text: str, source: str) -> list[Package]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    entries = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(entries, dict):
        return []
    packages: list[Package] = []
    for key, meta in entries.items():
        if "node_modules/" not in key or not isinstance(meta, dict) or meta.get("link"):
            continue
        version = meta.get("version")
        if isinstance(version, str) and version:
            packages.append(Package("npm", key.rsplit("node_modules/", 1)[1], version, source))
    return packages


def parse_manifests(files: dict[str, str]) -> tuple[list[Package], int]:
    """Parse every supported manifest. A lockfile beats package.json in the same folder."""
    packages: list[Package] = []
    unpinned = 0
    lock_dirs = {p.rsplit("/", 1)[0] if "/" in p else "" for p in files if p.rsplit("/", 1)[-1] == "package-lock.json"}
    for path, text in files.items():
        base = path.rsplit("/", 1)[-1]
        folder = path.rsplit("/", 1)[0] if "/" in path else ""
        if base == "package-lock.json":
            packages += parse_package_lock(text, path)
        elif base == "package.json":
            if folder in lock_dirs:
                continue
            found, loose = parse_package_json(text, path)
            packages += found
            unpinned += loose
        elif is_requirements_file(path):
            found, loose = parse_requirements(text, path)
            packages += found
            unpinned += loose
    unique = list(dict.fromkeys(packages))
    return unique, unpinned


# --------------------------------------------------------------------------- #
# OSV client
# --------------------------------------------------------------------------- #
_SEVERITY_WORDS = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _parse_vuln(record: dict, package: Optional[Package]) -> OsvVuln:
    db = record.get("database_specific")
    word = str(db.get("severity", "")).upper() if isinstance(db, dict) else ""
    summary = str(record.get("summary") or record.get("details") or "").strip().replace("\n", " ")
    fixed = None
    if package:
        for affected in record.get("affected") or []:
            pkg = affected.get("package") or {}
            if str(pkg.get("name", "")).lower() != package.name.lower():
                continue
            for rng in affected.get("ranges") or []:
                for event in rng.get("events") or []:
                    if event.get("fixed"):
                        fixed = str(event["fixed"])
                        break
                if fixed:
                    break
            if fixed:
                break
    return OsvVuln(
        id=str(record.get("id", "")),
        summary=summary[:300],
        severity=_SEVERITY_WORDS.get(word, Severity.MEDIUM),
        fixed=fixed,
        aliases=[str(a) for a in (record.get("aliases") or [])][:5],
    )


class OsvClient:
    def __init__(
        self,
        base_url: str = "https://api.osv.dev",
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        timeout: float = 15.0,
    ):
        self._base = base_url.rstrip("/")
        self._transport = transport
        self._timeout = timeout

    async def check(self, packages: Iterable[Package]) -> OsvResult:
        pkgs = list(packages)[:MAX_PACKAGES]
        if not pkgs:
            return OsvResult(status="ok")
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as client:
                hits: dict[int, list[str]] = {}
                for start in range(0, len(pkgs), BATCH_SIZE):
                    chunk = pkgs[start : start + BATCH_SIZE]
                    res = await client.post(
                        f"{self._base}/v1/querybatch",
                        json={"queries": [
                            {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
                            for p in chunk
                        ]},
                    )
                    res.raise_for_status()
                    results = res.json().get("results") or []
                    for offset, item in enumerate(results[: len(chunk)]):
                        ids = [str(v.get("id")) for v in (item.get("vulns") or []) if v.get("id")]
                        if ids:
                            hits[start + offset] = ids

                unique_ids = list(dict.fromkeys(i for ids in hits.values() for i in ids))
                details: dict[str, dict] = {}
                sem = asyncio.Semaphore(8)

                async def fetch(vuln_id: str) -> None:
                    async with sem:
                        try:
                            r = await client.get(f"{self._base}/v1/vulns/{vuln_id}")
                            if r.status_code == 200:
                                details[vuln_id] = r.json()
                        except (httpx.HTTPError, ValueError):
                            pass

                await asyncio.gather(*(fetch(i) for i in unique_ids[:MAX_DETAIL_LOOKUPS]))
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            logger.warning("OSV lookup failed: %s", type(exc).__name__)
            return OsvResult(status="unavailable", message="The vulnerability database (OSV.dev) could not be reached.")

        result = OsvResult(status="ok")
        for index, ids in hits.items():
            pkg = pkgs[index]
            vulns = []
            for vuln_id in ids:
                record = details.get(vuln_id)
                vulns.append(_parse_vuln(record, pkg) if record else OsvVuln(id=vuln_id))
            result.vulns[(pkg.ecosystem, pkg.name, pkg.version)] = vulns
        if len(unique_ids) > MAX_DETAIL_LOOKUPS:
            result.message = f"Showing details for the first {MAX_DETAIL_LOOKUPS} of {len(unique_ids)} advisories."
        return result
