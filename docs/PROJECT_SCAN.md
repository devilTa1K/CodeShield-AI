# Project scan

Two ways in:

```bash
# 1. a public GitHub repository (the server downloads it from codeload.github.com)
curl -X POST http://127.0.0.1:8000/api/scan/github -H "Content-Type: application/json" \
     -d '{"url": "https://github.com/owner/repo"}'      # add "include_tests": true to scan tests/samples too

# 2. a ZIP upload
curl -X POST "http://127.0.0.1:8000/api/scan?include_tests=false" -H "Content-Type: application/zip" --data-binary @project.zip
```

Test, sample and example files (`tests/`, `samples/`, `*.test.ts`, `test_*.py`, ...) are left out by default, because they are noisy and often deliberately vulnerable. The response reports how many were excluded.

Only `github.com/owner/repo` (optionally `/tree/branch`) URLs are accepted, only public repositories can be scanned, and the server only ever contacts `codeload.github.com`.

Both endpoints return findings grouped by file.

**What it does**
- Runs the normal static analysis (Bandit for Python, built-in rules for JS/TS/Java/C) on every supported file.
- Flags committed `.env` files (values are never echoed back) and hardcoded secrets in YAML/INI/TOML/properties files.
- Reads `requirements*.txt`, `package.json` and `package-lock.json`, and checks pinned versions against OSV.dev. Only package names and versions are sent; no source code.

**Safety limits**: 10 MB ZIP, 60 MB expanded, 5,000 entries, 150 code files, 300 KB per file. The archive is read in memory, nothing is extracted to disk or executed, unsafe entry names are skipped, and `node_modules`, `.git`, virtualenvs and build folders are ignored.

If OSV.dev cannot be reached the scan still completes and the response says the dependency check was unavailable.
