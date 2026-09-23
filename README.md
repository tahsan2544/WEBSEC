<div align="center">

# WEBSEC V3

**Website Upgrade Intelligence System**

Professional, defensive auditing for authorized websites and local projects.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-3.1.0-orange)
[![WEBSEC CI](https://github.com/tahsan2544/WEBSEC/actions/workflows/ci.yml/badge.svg)](https://github.com/tahsan2544/WEBSEC/actions/workflows/ci.yml)

</div>

## Features

**Website audits**
- Security headers, cookie flags, CORS, clickjacking, TLS, HTTPS-downgrade and mixed-content checks
- Admin-route exposure heuristics and client-delivered secret detection
- SEO, accessibility and performance signals

**Local project audits**
- Local project secret scanning with classification-aware severity (values redacted)
- Supabase SQL RLS/policy review and read-only endpoint checks

**Reporting & planning**
- Website scorecard: Security / SEO / Accessibility / Performance
- Actionable NOW → NEXT → POLISH → OPTIONAL upgrade plan with impact, effort and verification
- JSON, HTML and SARIF reports, plus `--fail-on` exit thresholds for CI

**Portability**
- Standard library only — Termux, Kali Linux, Windows and GitHub Actions friendly

## Quick start

```bash
python -m pip install -e .
websec website https://example.com --plan --json --html
websec project ./your-project --plan
websec all ./your-project --url https://example.com --fail-on HIGH
python -m pytest -q
```

## Commands

| Command | Purpose |
| --- | --- |
| `websec website <url>` | Full website audit (alias: `url`) |
| `websec project [path]` | Local project secret/configuration audit |
| `websec all [path] --url <url>` | Project + website audit combined |
| `websec supabase-sql <file>` | Static Supabase SQL review (RLS, policies) |
| `websec supabase-live <url> --key <key> --table <name>` | Read-only endpoint check |

Common flags: `--plan`, `--json`, `--html`, `--sarif`, `--output-dir`, `--fail-on`.

## What you get

- **Findings** — every check result printed with severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `PASS`), a plain-language detail, a suggested fix and where it was found.
- **Scorecard** (website audits) — Security / SEO / Accessibility / Performance, each scored out of 100.
- **Upgrade plan** (`--plan`) — findings grouped into NOW → NEXT → POLISH → OPTIONAL, each with impact (`/10`), effort, the action to take and a verification step.
- **Reports** — `--json` writes `websec-report.json`, `--html` writes a standalone `websec-report.html` page (scorecard, plan and findings table), `--sarif` writes `websec-report.sarif` for GitHub code scanning.
- **CI gating** — `--fail-on HIGH` (or any severity) exits with code `1` when findings at or above that severity exist.

## Project structure

| Path | Purpose |
| --- | --- |
| `portfolio_security_auditor/` | Python package — CLI, website/project/Supabase audit engines, scoring, upgrade plan, report writers |
| `scripts/bump_version.py` | Patch-version bump for `VERSION` and `pyproject.toml` |
| `tests/` | Pytest suite — smoke, audit, project-audit and report tests |
| `.github/workflows/ci.yml` | CI: editable install + `pytest` on every push and pull request |

## Versioning

Semantic Versioning. Patch releases increase by exactly **0.0.1**:
`3.1.0 → 3.1.1 → 3.1.2 → ...`

Run `python scripts/bump_version.py` to bump the patch version in `VERSION` and `pyproject.toml`.

## Safety

Only audit systems you own or are explicitly authorized to assess. WEBSEC is read-only and does not brute-force credentials, bypass authentication, exploit targets, or modify target systems. Credential values found in findings are always redacted.

## More information

- [Contributing](CONTRIBUTING.md) — how to propose changes
- [Security policy](SECURITY.md) — how to report issues privately
- [Changelog](CHANGELOG.md) — release history

## License

MIT License — © 2026 tahsan2544. See [LICENSE](LICENSE) for the full text.
