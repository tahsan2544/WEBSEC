from portfolio_security_auditor.accessibility_audit import audit_accessibility
from portfolio_security_auditor.http import HttpResponse
from portfolio_security_auditor.performance_audit import audit_performance
from portfolio_security_auditor.seo_audit import audit_seo
from portfolio_security_auditor.url_audit import UrlAuditor


def make_response(body="", headers=None, url="https://example.com", status=200,
                  set_cookies=None, redirect_chain=None, elapsed_ms=100.0):
    return HttpResponse(
        url=url,
        status=status,
        headers=headers or {},
        set_cookies=set_cookies or [],
        body=body,
        redirect_chain=redirect_chain or [],
        elapsed_ms=elapsed_ms,
        content_length=len(body),
    )


def test_seo_flags_missing_title_and_description():
    resp = make_response(status=200)
    findings = audit_seo("https://example.com", "<html><body><p>hi</p></body></html>", resp, probe_aux=False)
    titles = [f.title for f in findings]
    assert "Missing title tag" in titles
    assert "Missing meta description" in titles
    assert "No H1 heading found" in titles


def test_seo_clean_page_has_no_core_gap_findings():
    body = (
        '<html lang="en"><head>'
        "<title>Example Site</title>"
        '<meta name="description" content="A short description.">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<link rel="canonical" href="https://example.com/">'
        "</head><body><main><h1>Hello</h1></main></body></html>"
    )
    resp = make_response(status=200)
    findings = audit_seo("https://example.com", body, resp, probe_aux=False)
    titles = [f.title for f in findings]
    assert "Missing title tag" not in titles
    assert "Missing meta description" not in titles
    assert "No H1 heading found" not in titles


def test_accessibility_pass_when_structure_is_present():
    body = '<html><body><main><h1>Title</h1></main></body></html>'
    findings = audit_accessibility(body)
    assert len(findings) == 1
    assert findings[0].severity.value == "PASS"


def test_accessibility_flags_missing_main_and_alt():
    body = '<html><body><h1>T</h1><img src="a.png"></body></html>'
    titles = [f.title for f in audit_accessibility(body)]
    assert "Main landmark is not detected" in titles
    assert "Images may be missing alt text" in titles


def test_performance_flags_slow_response():
    resp = make_response(body="<html></html>", elapsed_ms=2000)
    findings = audit_performance(resp)
    assert any(f.title == "Homepage response is slow" for f in findings)


def test_performance_pass_on_fast_small_page():
    resp = make_response(
        body="<html><body>ok</body></html>",
        headers={"cache-control": "max-age=60"},
        elapsed_ms=80,
    )
    findings = audit_performance(resp)
    assert len(findings) == 1
    assert findings[0].severity.value == "PASS"


def test_headers_find_missing_clickjacking_and_hsts():
    auditor = UrlAuditor("https://example.com")
    findings = auditor._headers(make_response(url="https://example.com"))
    titles = [f.title for f in findings]
    assert "HSTS header is missing" in titles
    assert "Content Security Policy is missing" in titles
    assert "Clickjacking protection is not evident" in titles


def test_sensitive_cookie_flags_missing_secure_httponly():
    auditor = UrlAuditor("https://example.com")
    r = make_response(set_cookies=["sessionid=abc123; Path=/"])
    titles = [f.title for f in auditor._cookies(r)]
    assert "Sensitive cookie lacks Secure" in titles
    assert "Sensitive cookie lacks HttpOnly" in titles
    assert "Sensitive cookie has no explicit SameSite" in titles


def test_well_set_cookie_produces_no_cookie_findings():
    auditor = UrlAuditor("https://example.com")
    r = make_response(set_cookies=["sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"])
    assert auditor._cookies(r) == []


def test_mixed_content_and_https_downgrade_detected():
    auditor = UrlAuditor("https://example.com")
    r = make_response(
        url="https://example.com",
        body='<html><img src="http://cdn.example.com/a.png"></html>',
        redirect_chain=[{"from": "https://example.com", "status": 301, "to": "http://example.com/"}],
    )
    assert any(f.title == "HTTP mixed-content references found" for f in auditor._mixed(r))
    assert any(f.title == "HTTPS redirect downgrades to HTTP" for f in auditor._redirects(r))
