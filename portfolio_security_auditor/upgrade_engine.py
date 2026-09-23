from collections import defaultdict

from .models import Finding, Severity, SEVERITY_ORDER
from .upgrade_plan import build_upgrade_plan


AREA_WEIGHTS = {
    "Security": {Severity.CRITICAL: 20, Severity.HIGH: 12, Severity.MEDIUM: 7, Severity.LOW: 3},
    "SEO": {Severity.CRITICAL: 15, Severity.HIGH: 10, Severity.MEDIUM: 6, Severity.LOW: 3},
    "Accessibility": {Severity.CRITICAL: 15, Severity.HIGH: 10, Severity.MEDIUM: 6, Severity.LOW: 3},
    "Performance": {Severity.CRITICAL: 15, Severity.HIGH: 10, Severity.MEDIUM: 6, Severity.LOW: 3},
}


def build_plan(findings):
    groups = {"NOW": [], "NEXT": [], "POLISH": [], "OPTIONAL": []}
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER[x.severity]):
        s = f.severity.value
        if s in {"CRITICAL", "HIGH"}:
            bucket = "NOW"
        elif s == "MEDIUM":
            bucket = "NEXT"
        elif s == "LOW":
            bucket = "POLISH"
        else:
            bucket = "OPTIONAL"
        groups[bucket].append(f)
    return groups


def area_for(f: Finding) -> str:
    return f.metadata.get("area") or {
        "headers": "Security", "cookies": "Security", "redirects": "Security",
        "content": "Security", "admin-route": "Security", "client-secrets": "Security",
        "tls": "Security", "connection": "Security",
        "supabase": "Security", "supabase-live": "Security", "supabase-sql": "Security",
        "rls": "Security", "rls-policy": "Security", "functions": "Security",
        "project": "Security", "env": "Security", "gitignore": "Security",
        "secrets": "Security", "browser-auth": "Security", "dependencies": "Security",
        "seo": "SEO", "accessibility": "Accessibility", "performance": "Performance",
    }.get(f.check, f.check.replace("-", " ").title())


def _unique_relevant(findings):
    best = {}
    confidence_order = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
    for f in findings:
        if f.severity in {Severity.INFO, Severity.PASS}:
            continue
        key = (area_for(f), f.check, f.title)
        old = best.get(key)
        if old is None or confidence_order.get(f.confidence.value, 0) > confidence_order.get(old.confidence.value, 0):
            best[key] = f
    return list(best.values())


def score_area(findings, area):
    deduction = 0.0
    for f in _unique_relevant(findings):
        if area_for(f) != area:
            continue
        base = AREA_WEIGHTS.get(area, {}).get(f.severity, 0)
        multiplier = {"HIGH": 1.0, "MEDIUM": 0.65, "LOW": 0.35}.get(f.confidence.value, 0.35)
        if f.status.value == "HEURISTIC":
            multiplier *= 0.5
        deduction += base * multiplier
    return max(0, min(100, round(100 - deduction)))


def build_scorecard(findings):
    areas = ["Security", "SEO", "Accessibility", "Performance"]
    website = [f for f in findings if f.metadata.get("target") == "website"]
    source = website if website else findings
    return {area: score_area(source, area) for area in areas}


def build_upgrade_summary(findings):
    plan = build_upgrade_plan(findings)
    groups = defaultdict(list)
    for item in plan:
        groups[item.priority].append(item)
    return {
        "now": len(groups["NOW"]),
        "next": len(groups["NEXT"]),
        "polish": len(groups["POLISH"]),
        "optional": len(groups["OPTIONAL"]),
        "top_actions": [x.__dict__ for x in plan[:8]],
    }
