# WEBSEC V3 — Website Upgrade Intelligence System

Professional, defensive auditing for authorized websites and local projects.

## Features
- Security headers, cookie flags, CORS, clickjacking, TLS, HTTPS-downgrade and mixed-content checks
- Admin-route exposure heuristics and client-delivered secret detection
- SEO, accessibility and performance signals
- Local project secret scanning with classification-aware severity (values redacted)
- Supabase SQL RLS/policy review and read-only endpoint checks
- Website scorecard: Security / SEO / Accessibility / Performance
- Actionable NOW → NEXT → POLISH → OPTIONAL upgrade plan with impact, effort and verification
- JSON, HTML and SARIF reports, plus `--fail-on` exit thresholds for CI
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

## Versioning
Semantic Versioning. Patch releases increase by exactly **0.0.1**:
`3.1.0 → 3.1.1 → 3.1.2 → ...`

Run `python scripts/bump_version.py` to bump the patch version in `VERSION` and `pyproject.toml`.

## Safety
Only audit systems you own or are explicitly authorized to assess. WEBSEC is read-only and does not brute-force credentials, bypass authentication, exploit targets, or modify target systems. Credential values found in findings are always redacted.
