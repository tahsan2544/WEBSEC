from dataclasses import dataclass

from .models import Finding, Severity, Confidence, Status


@dataclass
class UpgradeAction:
    priority: str
    area: str
    issue: str
    why: str
    action: str
    verify: str
    location: str = ""
    impact: int = 0
    effort: str = "Unknown"
    confidence: str = "MEDIUM"
    score_impact: int = 0


AREA_MAP = {
    "headers": "Security",
    "cookies": "Security",
    "redirects": "Security",
    "content": "Security",
    "admin-route": "Security",
    "client-secrets": "Security",
    "tls": "Security",
    "connection": "Security",
    "supabase": "Security",
    "supabase-live": "Security",
    "supabase-sql": "Security",
    "rls": "Security",
    "rls-policy": "Security",
    "functions": "Security",
    "project": "Security",
    "env": "Security",
    "gitignore": "Security",
    "secrets": "Security",
    "browser-auth": "Security",
    "dependencies": "Security",
    "seo": "SEO",
    "accessibility": "Accessibility",
    "performance": "Performance",
}

RULES = {
    "HSTS header is missing": (
        "NOW", 9, "Easy",
        "Enable HSTS after confirming all relevant site traffic works over HTTPS.",
        "Check that the next audit observes Strict-Transport-Security.",
    ),
    "Content Security Policy is missing": (
        "NOW", 8, "Medium",
        "Add a tested CSP that matches your scripts, styles, images, fonts and API endpoints.",
        "Reload the site and confirm CSP is present without breaking required resources.",
    ),
    "Admin-like content is publicly reachable": (
        "NOW", 10, "Medium",
        "Verify authentication and authorization are enforced server-side for the admin route and every privileged API operation.",
        "Re-audit the admin route and manually verify an unauthenticated request cannot perform privileged actions.",
    ),
    "Supabase server credential reference found": (
        "NOW", 10, "Easy",
        "Remove server-only credentials from browser-delivered code. Keep only publishable/anon credentials client-side and rotate any exposed secret.",
        "Re-run the project audit and confirm only intended public credentials remain.",
    ),
    "Possible private key in source": (
        "NOW", 10, "Easy",
        "Remove private keys from source control, move them to secret storage, and rotate if exposed.",
        "Re-run the secret scan and verify the key is absent from tracked files.",
    ),
    "Missing title tag": (
        "NEXT", 7, "Easy",
        "Add one unique, descriptive page title that clearly states the page purpose and brand.",
        "Inspect the rendered HTML for a single useful title and re-run the SEO audit.",
    ),
    "Missing meta description": (
        "NEXT", 6, "Easy",
        "Add a concise, page-specific meta description that accurately describes the page.",
        "Re-run the SEO audit and confirm a description is detected.",
    ),
    "Images missing alt attributes": (
        "NEXT", 5, "Easy",
        "Add meaningful alt text to informative images and empty alt only to intentionally decorative images.",
        "Re-run the accessibility/SEO checks and confirm the missing-alt finding is gone.",
    ),
    "Form controls may lack accessible names": (
        "NEXT", 6, "Easy",
        "Associate every user-editable form control with a visible label or an equivalent accessible name.",
        "Use an accessibility tree or audit tool to verify each control has an accessible name.",
    ),
    "Homepage response is slow": (
        "NEXT", 6, "Medium",
        "Investigate server response time, database calls, API waterfalls, caching and heavy middleware before optimizing frontend code.",
        "Run repeated audits and compare response time after each change.",
    ),
    "HTML payload is large": (
        "POLISH", 3, "Medium",
        "Reduce initial HTML, remove unnecessary inline data, and defer non-critical content.",
        "Re-run the audit and compare HTML byte size.",
    ),
    "Too many JavaScript files": (
        "POLISH", 3, "Medium",
        "Reduce script count where practical and defer non-critical JavaScript.",
        "Re-run the performance audit and compare script count.",
    ),
    "JavaScript dependencies are not locked": (
        "POLISH", 3, "Easy",
        "Commit the package-manager lockfile to make dependency resolution reproducible.",
        "Confirm a lockfile is present at the project root.",
    ),
}


def _area(f: Finding) -> str:
    return f.metadata.get("area") or AREA_MAP.get(f.check, f.check.replace("-", " ").title())


def _rule(f: Finding):
    if f.title in RULES:
        return RULES[f.title]
    if f.severity in {Severity.CRITICAL, Severity.HIGH}:
        return (
            "NOW", 10 if f.severity is Severity.CRITICAL else 9, "Medium",
            f.recommendation or "Resolve or investigate this high-impact finding.",
            "Rerun the same audit and verify the condition is no longer detected.",
        )
    if f.severity is Severity.MEDIUM:
        return (
            "NEXT", 6, "Medium",
            f.recommendation or "Apply the recommended remediation.",
            "Rerun the same audit and confirm the finding is resolved.",
        )
    if f.severity is Severity.LOW:
        return (
            "POLISH", 3, "Easy",
            f.recommendation or "Apply the recommended hardening.",
            "Rerun the same audit and confirm the finding is resolved.",
        )
    return (
        "OPTIONAL", 1, "Easy",
        f.recommendation or "Review this informational finding.",
        "Re-run the audit after deciding whether the change is needed.",
    )


def build_upgrade_plan(findings):
    actions = []
    seen = set()
    for f in findings:
        if f.severity in {Severity.PASS, Severity.INFO} or f.status is Status.PASS:
            continue
        key = (f.check, f.title, f.location)
        if key in seen:
            continue
        seen.add(key)
        priority, impact, effort, action, verify = _rule(f)
        classification = f.metadata.get("classification")
        if classification in {"documentation", "test", "sample"} and f.severity in {Severity.LOW, Severity.INFO}:
            priority = "OPTIONAL" if classification in {"documentation", "sample"} else "POLISH"
            impact = min(impact, 2)
            effort = "Review"
            action = (
                "Review the example/test content and confirm it is clearly synthetic"
                " and never contains a real credential."
            )
            verify = (
                "Re-run the project audit and confirm real source files contain"
                " no credential-shaped values."
            )
        score_impact = max(
            1,
            round(
                impact
                * (
                    1
                    if f.confidence is Confidence.HIGH
                    else 0.6
                    if f.confidence is Confidence.MEDIUM
                    else 0.35
                )
            ),
        )
        actions.append(UpgradeAction(
            priority=priority,
            area=_area(f),
            issue=f.title,
            why=f.detail,
            action=action,
            verify=verify,
            location=f.location,
            impact=impact,
            effort=effort,
            confidence=f.confidence.value,
            score_impact=score_impact,
        ))
    order = {"NOW": 0, "NEXT": 1, "POLISH": 2, "OPTIONAL": 3}
    return sorted(actions, key=lambda x: (order[x.priority], -x.impact, x.area, x.issue, x.location))
