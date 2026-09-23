import re
from urllib.parse import urljoin, urlparse

from .http import request, normalize_url, tls_info
from .models import Finding, Severity, Confidence, Status
from .seo_audit import audit_seo
from .accessibility_audit import audit_accessibility
from .performance_audit import audit_performance


class UrlAuditor:
    def __init__(self, url, admin_path="/admin", timeout=12):
        self.url = normalize_url(url)
        self.admin_path = "/" + admin_path.strip("/")
        self.timeout = timeout

    def audit(self):
        r = request(self.url, timeout=self.timeout)
        if r.status == 0:
            return [Finding(
                "connection", Severity.HIGH, "Site could not be reached", r.error,
                "Verify URL, DNS, TLS, firewall and network access.",
                confidence=Confidence.HIGH, status=Status.VERIFIED,
            )]
        findings = (
            self._headers(r)
            + self._cookies(r)
            + self._redirects(r)
            + self._mixed(r)
            + self._admin()
            + self._secrets(r.body)
            + self._tls()
            + self._security_hardening(r)
            + audit_seo(self.url, r.body, r, self.timeout)
            + audit_accessibility(r.body)
            + audit_performance(r)
        )
        for finding in findings:
            if finding.check not in {"seo", "accessibility", "performance"}:
                finding.metadata.setdefault("area", "Security")
            finding.metadata.setdefault("target", "website")
        return findings

    def _headers(self, r):
        h = r.headers
        f = []
        csp = h.get("content-security-policy", "")
        if r.url.startswith("https://") and "strict-transport-security" not in h:
            f.append(Finding(
                "headers", Severity.MEDIUM, "HSTS header is missing",
                "No Strict-Transport-Security header was observed.",
                "Add HSTS after confirming relevant domains support HTTPS.",
                confidence=Confidence.HIGH, status=Status.VERIFIED,
            ))
        if not csp:
            f.append(Finding(
                "headers", Severity.MEDIUM, "Content Security Policy is missing",
                "No Content-Security-Policy header was observed.",
                "Deploy a CSP appropriate to the application.",
                confidence=Confidence.HIGH, status=Status.VERIFIED,
            ))
        elif "'unsafe-eval'" in csp.lower():
            f.append(Finding(
                "headers", Severity.MEDIUM, "CSP allows unsafe-eval",
                "The CSP contains 'unsafe-eval'.",
                "Remove it unless a documented dependency requires it.",
                evidence=csp[:500], confidence=Confidence.HIGH, status=Status.DETECTED,
            ))
        if h.get("x-content-type-options", "").lower() != "nosniff":
            f.append(Finding(
                "headers", Severity.LOW, "X-Content-Type-Options is not nosniff",
                "MIME sniffing protection was not explicitly set to nosniff.",
                "Set X-Content-Type-Options: nosniff.",
                evidence=h.get("x-content-type-options", ""),
                confidence=Confidence.HIGH, status=Status.VERIFIED,
            ))
        if "referrer-policy" not in h:
            f.append(Finding(
                "headers", Severity.LOW, "Referrer-Policy is missing",
                "No explicit Referrer-Policy was observed.",
                "Set an explicit referrer policy.",
                confidence=Confidence.HIGH, status=Status.VERIFIED,
            ))
        if not h.get("x-frame-options") and "frame-ancestors" not in csp.lower():
            f.append(Finding(
                "headers", Severity.MEDIUM, "Clickjacking protection is not evident",
                "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
                "Use CSP frame-ancestors and/or X-Frame-Options.",
                confidence=Confidence.HIGH, status=Status.VERIFIED,
            ))
        if h.get("access-control-allow-origin") == "*":
            f.append(Finding(
                "headers", Severity.LOW, "CORS allows every origin",
                "Access-Control-Allow-Origin is wildcard.",
                "Use an allowlist when access is not intentionally public.",
                evidence="*", confidence=Confidence.HIGH, status=Status.VERIFIED,
            ))
        return f

    def _cookies(self, r):
        f = []
        for raw in r.set_cookies:
            parts = [x.strip() for x in raw.split(";")]
            name = parts[0].split("=", 1)[0].lower()
            sensitive = bool(re.search(r"(session|sid|auth|token|jwt|access|refresh)", name))
            attrs = {x.split("=", 1)[0].lower() for x in parts[1:]}
            if not sensitive:
                continue
            for attr, title, fix in [
                ("secure", "Sensitive cookie lacks Secure", "Set Secure on authentication/session cookies."),
                ("httponly", "Sensitive cookie lacks HttpOnly", "Set HttpOnly when JavaScript does not need to read the cookie."),
            ]:
                if attr not in attrs:
                    f.append(Finding(
                        "cookies", Severity.MEDIUM, title,
                        f"Cookie '{name}' appears authentication-related and lacks {attr}.",
                        fix, evidence=f"{name}=<redacted>",
                        confidence=Confidence.HIGH, status=Status.DETECTED,
                    ))
            if not any(x.startswith("samesite") for x in attrs):
                f.append(Finding(
                    "cookies", Severity.LOW, "Sensitive cookie has no explicit SameSite",
                    f"Cookie '{name}' has no explicit SameSite attribute.",
                    "Choose an explicit SameSite value.",
                    evidence=f"{name}=<redacted>",
                    confidence=Confidence.HIGH, status=Status.DETECTED,
                ))
        return f

    def _redirects(self, r):
        return [
            Finding(
                "redirects", Severity.HIGH, "HTTPS redirect downgrades to HTTP",
                "A redirect moved from HTTPS to HTTP.",
                "Keep application/authentication traffic on HTTPS",
                evidence=f"{x['from']} -> {x['to']}",
                confidence=Confidence.HIGH, status=Status.VERIFIED,
            )
            for x in r.redirect_chain
            if urlparse(x["from"]).scheme == "https" and urlparse(x["to"]).scheme == "http"
        ]

    def _mixed(self, r):
        if not r.url.startswith("https://"):
            return []
        m = re.findall(r'''(?:src|href|action)\s*=\s*["'](http://[^"']+)''', r.body, re.I)
        if not m:
            return []
        return [Finding(
            "content", Severity.MEDIUM, "HTTP mixed-content references found",
            f"{len(m)} HTTP resource/form reference(s) were found.",
            "Serve application resources/forms over HTTPS",
            evidence="; ".join(m[:5]),
            confidence=Confidence.HIGH, status=Status.DETECTED,
        )]

    def _admin(self):
        r = request(urljoin(self.url + "/", self.admin_path.lstrip("/")), timeout=self.timeout)
        if r.status in (401, 403):
            return [Finding(
                "admin-route", Severity.PASS, "Admin route is access-controlled",
                f"The route returned HTTP {r.status}.",
                confidence=Confidence.HIGH, status=Status.PASS,
            )]
        low = r.body.lower()
        if any(x in r.url.lower() for x in ("/login", "/signin", "/auth")) or any(
            x in low for x in ("sign in", "log in", "login", "authenticate")
        ):
            return [Finding(
                "admin-route", Severity.PASS, "Admin route appears to require authentication",
                "Authentication markers were observed; this is not proof of server-side authorization.",
                "Verify privileged API operations are protected server-side.",
                confidence=Confidence.MEDIUM, status=Status.HEURISTIC,
            )]
        if r.status == 200 and any(
            x in low for x in ("admin dashboard", "manage users", "user management", "admin panel")
        ):
            return [Finding(
                "admin-route", Severity.HIGH, "Admin-like content is publicly reachable",
                "The admin path returned 200 with admin markers and no obvious login markers.",
                "Verify server-side authorization for every privileged operation.",
                evidence="HTTP 200 + admin markers",
                confidence=Confidence.MEDIUM, status=Status.HEURISTIC,
            )]
        return [Finding(
            "admin-route", Severity.INFO, "Admin route exposure is unverified",
            f"The route returned HTTP {r.status}, but there was insufficient evidence of an authorization flaw.",
            "Manually verify privileged data/actions are protected server-side.",
            confidence=Confidence.HIGH, status=Status.INFO,
        )]

    def _secrets(self, body):
        pats = [
            r"AIza[0-9A-Za-z_-]{30,}",
            r"sb_secret_[A-Za-z0-9._-]{20,}",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        ]
        return [
            Finding(
                "client-secrets", Severity.HIGH, "Possible secret exposed in HTML",
                "A secret-like credential pattern was detected; the value is redacted.",
                "Remove server-only credentials from client-delivered code and rotate exposed credentials.",
                evidence="<redacted>",
                confidence=Confidence.MEDIUM, status=Status.DETECTED,
            )
            for p in pats
            if re.search(p, body or "")
        ]

    def _security_hardening(self, r):
        h = r.headers
        f = []
        checks = [
            ("permissions-policy", Severity.LOW, "Permissions-Policy is missing",
             "Set a restrictive Permissions-Policy for features the app does not need."),
            ("cross-origin-opener-policy", Severity.LOW, "Cross-Origin-Opener-Policy is missing",
             "Consider COOP where isolation is appropriate."),
            ("cross-origin-resource-policy", Severity.LOW, "Cross-Origin-Resource-Policy is missing",
             "Consider CORP for resources where cross-origin loading should be constrained."),
        ]
        for key, severity, title, fix in checks:
            if key not in h:
                f.append(Finding(
                    "headers", severity, title, f"No {key} header was observed.", fix,
                    confidence=Confidence.HIGH, status=Status.VERIFIED,
                ))
        server = h.get("server", "")
        if server:
            f.append(Finding(
                "headers", Severity.INFO, "Server header discloses implementation information",
                f"The Server header is present: {server[:120]}",
                "Minimize unnecessary version/product disclosure where practical.",
                evidence=server[:120],
                confidence=Confidence.HIGH, status=Status.DETECTED,
            ))
        cache = h.get("cache-control", "").lower()
        if any(x in r.url.lower() for x in ("/admin", "/account", "/dashboard", "/profile")) and "no-store" not in cache:
            f.append(Finding(
                "headers", Severity.MEDIUM, "Sensitive page lacks explicit no-store caching",
                "An admin/account-like URL was fetched without an observed Cache-Control: no-store directive.",
                "For sensitive authenticated pages, consider Cache-Control: no-store where appropriate.",
                evidence=cache,
                confidence=Confidence.MEDIUM, status=Status.HEURISTIC,
            ))
        hsts = h.get("strict-transport-security", "")
        if hsts and "includesubdomains" in hsts.lower() and "max-age=" not in hsts.lower():
            f.append(Finding(
                "headers", Severity.LOW, "HSTS value looks malformed",
                "Strict-Transport-Security was present but no max-age directive was detected.",
                "Set a valid HSTS policy with an appropriate max-age.",
                evidence=hsts,
                confidence=Confidence.HIGH, status=Status.DETECTED,
            ))
        return f

    def _tls(self):
        try:
            i = tls_info(self.url, self.timeout)
            return [Finding(
                "tls", Severity.PASS, "TLS handshake succeeded",
                f"Negotiated {i.get('version', 'unknown')} / {i.get('cipher', 'unknown')}.",
                confidence=Confidence.HIGH, status=Status.PASS,
            )]
        except Exception as e:
            return [Finding(
                "tls", Severity.HIGH, "TLS inspection failed", str(e),
                "Verify certificate chain, hostname and TLS configuration.",
                confidence=Confidence.HIGH, status=Status.VERIFIED,
            )]


def audit_website(url, admin_path="/admin", timeout=12):
    return UrlAuditor(url, admin_path, timeout).audit()
