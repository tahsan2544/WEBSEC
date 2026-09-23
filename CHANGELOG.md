# Changelog

## 3.1.0 — Full audit engine upgrade
- Security header hardening, cookie flags, CORS, clickjacking, TLS, redirect and mixed-content checks
- Admin-route exposure heuristics and client-delivered secret detection in HTML
- SEO, accessibility and performance audits
- Project scanner with classification-aware secret detection (values always redacted)
- Supabase SQL RLS/policy review and read-only live endpoint checks
- Website scorecard (Security / SEO / Accessibility / Performance)
- Richer upgrade plan with impact, effort and verification steps
- JSON, HTML and SARIF report output plus `--fail-on` exit thresholds
- Dropped the `requests` dependency — standard library HTTP client only

## 3.0.0 — Initial professional V3 release
- Website and project auditing foundation
- Security, SEO, accessibility and performance signals
- Upgrade planning
- JSON/HTML reporting
- GitHub Actions CI
- Patch-version automation
