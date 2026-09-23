import json

from portfolio_security_auditor.models import Confidence, Finding, Severity, Status
from portfolio_security_auditor.report import summary, to_html, to_json, to_sarif
from portfolio_security_auditor.upgrade_engine import build_scorecard, build_upgrade_summary
from portfolio_security_auditor.upgrade_plan import build_upgrade_plan


def website_findings():
    return [
        Finding(
            "headers", Severity.MEDIUM, "HSTS header is missing", "missing", "fix",
            confidence=Confidence.HIGH, status=Status.VERIFIED,
            metadata={"target": "website", "area": "Security"},
        ),
        Finding(
            "seo", Severity.LOW, "Missing mobile viewport", "missing", "fix",
            confidence=Confidence.HIGH, status=Status.VERIFIED,
            metadata={"target": "website", "area": "SEO"},
        ),
    ]


def test_scorecard_deducts_only_relevant_areas():
    score = build_scorecard(website_findings())
    assert score["Security"] < 100
    assert score["SEO"] < 100
    assert score["Performance"] == 100
    assert score["Accessibility"] == 100


def test_upgrade_plan_skips_pass_and_info_and_orders_by_priority():
    findings = [
        Finding("tls", Severity.PASS, "TLS handshake succeeded", "ok", ""),
        Finding("seo", Severity.INFO, "Open Graph image is missing", "none", "add"),
        Finding("headers", Severity.LOW, "Referrer-Policy is missing", "none", "set"),
        Finding("headers", Severity.HIGH, "Admin-like content is publicly reachable", "open", "fix"),
    ]
    plan = build_upgrade_plan(findings)
    priorities = [x.priority for x in plan]
    assert "OPTIONAL" not in priorities
    assert priorities[0] == "NOW"
    assert priorities[-1] == "POLISH"
    assert plan[0].verify


def test_upgrade_summary_counts():
    summary_data = build_upgrade_summary(website_findings())
    assert summary_data["now"] == 1
    assert summary_data["next"] == 0
    assert summary_data["polish"] == 1
    assert len(summary_data["top_actions"]) == 2


def test_to_json_payload_shape():
    data = json.loads(to_json(website_findings()))
    assert data["tool"] == "WEBSEC"
    assert data["version"]
    assert set(data["scorecard"]) == {"Security", "SEO", "Accessibility", "Performance"}
    assert len(data["findings"]) == 2
    assert data["findings"][0]["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"}
    assert data["upgrade_plan"]


def test_to_html_escapes_untrusted_content():
    findings = [
        Finding(
            "x", Severity.HIGH, "<script>alert(1)</script>", "detail", "fix",
            evidence="<b>evidence</b>", location="<img src=x>",
        )
    ]
    html = to_html(findings)
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x&gt;" in html
    assert "<script>alert" not in html
    assert "<table" in html


def test_to_sarif_maps_levels_and_skips_pass():
    findings = [
        Finding("a", Severity.CRITICAL, "t", "d", ""),
        Finding("b", Severity.MEDIUM, "t2", "d2", ""),
        Finding("c", Severity.PASS, "ok", "d3", ""),
    ]
    data = json.loads(to_sarif(findings))
    results = data["runs"][0]["results"]
    assert len(results) == 2
    assert results[0]["level"] == "error"
    assert results[1]["level"] == "warning"


def test_summary_counts_severities():
    assert summary(website_findings()) == {"MEDIUM": 1, "LOW": 1}
