# Portfolio Security Auditor V3 — Website Upgrade Intelligence

A defensive, read-only **Website Upgrade Intelligence System** for sites and local projects you own or are explicitly authorized to assess.

## What V3 changes

V3 is designed to answer:

> **What should I upgrade on my website, and what should I do next?**

It now combines security, SEO, accessibility and performance observations into an actionable upgrade plan.

### Website scorecard

Website audits produce four category scores:

- Security / 100
- SEO / 100
- Accessibility / 100
- Performance / 100

The score engine down-weights medium/low-confidence and heuristic findings and ignores informational/pass results, so a weak clue does not automatically look like a confirmed vulnerability.

### Upgrade Intelligence

Findings become prioritized actions:

- **NOW** — investigate high-impact issues first.
- **NEXT** — medium-impact improvements.
- **POLISH** — lower-risk hardening and quality improvements.
- **OPTIONAL** — informational improvements.

Each action contains the observed issue, why it matters, what to change, effort, impact and how to verify the result.

### Security

Examples include security headers, CSP, HSTS, cookies, CORS, clickjacking protection, TLS handshake, HTTPS downgrade redirects, mixed content, admin-route exposure heuristics, client-delivered secret detection, cache policy for sensitive routes, and Supabase/RLS checks.

### SEO

Checks include title, description, language, mobile viewport, H1 structure, image alt coverage, canonical URL, Open Graph, Twitter/X metadata, JSON-LD, noindex, HTTP status, robots.txt and sitemap reachability.

### Accessibility

Basic read-only HTML checks include form-control naming signals, button naming signals, missing image alt attributes, heading hierarchy jumps and main-landmark structure.

### Performance

Basic HTTP/HTML checks include response time bands, HTML payload size, script count, compression evidence and cache-policy visibility.

## Accuracy improvements

The V3 project scanner no longer treats a bare word such as `service_role` as a Supabase credential. A server-secret finding requires a credential-shaped value. Documentation, tests and examples are classified separately and can receive lower-confidence/low-severity treatment when appropriate.

Credential values are always redacted from findings.

## Install

Python 3.10+ and standard library only:

```bash
python -m pip install -e .
```

Termux:

```bash
pkg update -y
pkg install -y python git unzip
python -m pip install -e .
```

### Termux storage note

For the cleanest Git and virtual-environment behavior, keep the repository in Termux's private home (`~/projects/...`) rather than Android shared storage under `~/storage/downloads`.

## Usage

Website audit:

```bash
python -m portfolio_security_auditor website https://example.com --plan --html --json --sarif
```

Local project audit:

```bash
python -m portfolio_security_auditor project . --plan --html --json --sarif
```

Combined project + website audit:

```bash
python -m portfolio_security_auditor all . --url https://example.com --plan --html --json --sarif
```

The primary report is written to `security-reports/`.

## Safe scope

Use only on systems you own or have explicit permission to assess. This tool intentionally avoids brute force, authentication bypass, exploit payloads, credential collection, writes, destructive actions and secret disclosure.

A finding is an observation to investigate, not proof that a system is exploitable.
