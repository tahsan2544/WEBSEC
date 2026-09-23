from html.parser import HTMLParser
from urllib.parse import urlparse

from .http import request
from .models import Finding, Severity, Confidence, Status


class SEOParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.in_title = False
        self.lang = ""
        self.meta = []
        self.links = []
        self.images = []
        self.h1 = 0
        self.jsonld = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        t = tag.lower()
        if t == "html" and a.get("lang"):
            self.lang = a["lang"].strip()
        elif t == "title":
            self.in_title = True
        elif t == "meta":
            self.meta.append(a)
        elif t == "link":
            self.links.append(a)
        elif t == "img":
            self.images.append(a)
        elif t == "h1":
            self.h1 += 1
        elif t == "script" and a.get("type", "").lower() == "application/ld+json":
            self.jsonld += 1

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data.strip()


def _meta(p, name):
    n = name.lower()
    for m in p.meta:
        if m.get("name", "").lower() == n or m.get("property", "").lower() == n:
            return m.get("content", "").strip()
    return ""


def audit_seo(base_url, body, response, timeout=12, probe_aux=True):
    p = SEOParser()
    try:
        p.feed(body or "")
    except Exception:
        return [Finding(
            "seo", Severity.INFO, "HTML could not be fully parsed",
            "The page was not fully parseable as HTML.",
            "Review the document markup manually.",
            confidence=Confidence.MEDIUM, status=Status.INFO,
        )]
    f = []
    title = p.title.strip()
    desc = _meta(p, "description")
    robots = _meta(p, "robots")
    canonical = ""
    for l in p.links:
        if l.get("rel", "").lower() == "canonical":
            canonical = l.get("href", "").strip()
            break
    viewport = _meta(p, "viewport")
    og_title = _meta(p, "og:title")
    og_desc = _meta(p, "og:description")
    og_image = _meta(p, "og:image")
    twitter_card = _meta(p, "twitter:card")

    if not title:
        f.append(Finding(
            "seo", Severity.MEDIUM, "Missing title tag", "No HTML title was found.",
            "Add one unique, descriptive <title>.",
            confidence=Confidence.HIGH, status=Status.VERIFIED,
        ))
    elif len(title) > 60:
        f.append(Finding(
            "seo", Severity.LOW, "Title is long",
            "The title is longer than about 60 characters.",
            "Shorten it while preserving the main topic.",
            evidence=title[:120], confidence=Confidence.HIGH, status=Status.DETECTED,
        ))
    if not desc:
        f.append(Finding(
            "seo", Severity.MEDIUM, "Missing meta description", "No meta description was found.",
            "Add a concise, page-specific description.",
            confidence=Confidence.HIGH, status=Status.VERIFIED,
        ))
    elif len(desc) > 170:
        f.append(Finding(
            "seo", Severity.LOW, "Meta description is long",
            "The description is longer than about 170 characters.",
            "Trim it without losing the main value proposition.",
            evidence=desc[:200], confidence=Confidence.HIGH, status=Status.DETECTED,
        ))
    if not p.lang:
        f.append(Finding(
            "seo", Severity.LOW, "Missing HTML language",
            'The <html> element has no lang attribute.',
            'Set the primary language, e.g. lang="en".',
            confidence=Confidence.HIGH, status=Status.VERIFIED,
        ))
    if not viewport:
        f.append(Finding(
            "seo", Severity.LOW, "Missing mobile viewport",
            "No viewport meta tag was found.",
            "Add a responsive viewport meta tag.",
            confidence=Confidence.HIGH, status=Status.VERIFIED,
        ))
    if p.h1 == 0:
        f.append(Finding(
            "seo", Severity.MEDIUM, "No H1 heading found",
            "The page contains no H1 element.",
            "Add one clear primary heading when appropriate.",
            confidence=Confidence.HIGH, status=Status.VERIFIED,
        ))
    elif p.h1 > 1:
        f.append(Finding(
            "seo", Severity.LOW, "Multiple H1 headings",
            "More than one H1 was found.",
            "Use one primary H1 unless multiple H1s are intentional and semantically justified.",
            evidence=str(p.h1), confidence=Confidence.HIGH, status=Status.DETECTED,
        ))
    bad_alt = [i for i in p.images if i.get("src") and not i.get("alt", "").strip()]
    if bad_alt:
        f.append(Finding(
            "seo", Severity.LOW, "Images missing alt attributes",
            f"{len(bad_alt)} image(s) have empty/missing alt text.",
            "Add meaningful alt text to informative images; use empty alt only for decorative images.",
            evidence="; ".join(i.get("src", "")[:100] for i in bad_alt[:5]),
            confidence=Confidence.HIGH, status=Status.DETECTED,
        ))
    if not canonical:
        f.append(Finding(
            "seo", Severity.LOW, "Canonical URL is missing",
            "No rel=canonical link was observed.",
            "Add a canonical URL when duplicate/variant URLs can exist.",
            confidence=Confidence.HIGH, status=Status.VERIFIED,
        ))
    if not og_title or not og_desc:
        f.append(Finding(
            "seo", Severity.LOW, "Open Graph metadata is incomplete",
            "og:title and/or og:description is missing.",
            "Add page-specific Open Graph metadata for sharing.",
            confidence=Confidence.HIGH, status=Status.DETECTED,
        ))
    if not og_image:
        f.append(Finding(
            "seo", Severity.INFO, "Open Graph image is missing", "No og:image was observed.",
            "Add an appropriate social preview image.",
            confidence=Confidence.HIGH, status=Status.INFO,
        ))
    if not twitter_card:
        f.append(Finding(
            "seo", Severity.INFO, "Twitter/X card metadata is missing",
            "No twitter:card was observed.",
            "Add a card type if social previews on X matter.",
            confidence=Confidence.HIGH, status=Status.INFO,
        ))
    if not p.jsonld:
        f.append(Finding(
            "seo", Severity.LOW, "Structured data is not detected",
            "No JSON-LD structured data block was observed.",
            "Add valid Schema.org JSON-LD where it accurately describes the page.",
            confidence=Confidence.MEDIUM, status=Status.HEURISTIC,
        ))
    if "noindex" in robots.lower():
        f.append(Finding(
            "seo", Severity.MEDIUM, "Page requests noindex",
            "The robots meta tag contains noindex.",
            "Confirm this is intentional for the page.",
            evidence=robots, confidence=Confidence.HIGH, status=Status.DETECTED,
        ))
    if response.status != 200:
        f.append(Finding(
            "seo", Severity.MEDIUM, "Homepage does not return HTTP 200",
            f"The final response status is {response.status}.",
            "Ensure the canonical landing page returns the intended status.",
            evidence=str(response.status), confidence=Confidence.HIGH, status=Status.VERIFIED,
        ))
    if probe_aux:
        parsed = urlparse(base_url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        for path, label in [("/robots.txt", "robots.txt"), ("/sitemap.xml", "XML sitemap")]:
            rr = request(root + path, timeout=timeout, max_bytes=100_000)
            if rr.status == 200 and rr.body.strip():
                f.append(Finding(
                    "seo", Severity.PASS, f"{label} is reachable",
                    f"{path} returned HTTP 200.",
                    confidence=Confidence.HIGH, status=Status.PASS,
                ))
            elif path == "/robots.txt":
                f.append(Finding(
                    "seo", Severity.LOW, "robots.txt is not reachable",
                    "robots.txt did not return a usable HTTP 200 response.",
                    "Publish a valid robots.txt if crawler directives are needed.",
                    evidence=str(rr.status),
                    confidence=Confidence.HIGH, status=Status.VERIFIED,
                ))
            else:
                f.append(Finding(
                    "seo", Severity.LOW, "XML sitemap is not detected",
                    "sitemap.xml did not return a usable HTTP 200 response.",
                    "Publish and reference a sitemap when the site benefits from one.",
                    evidence=str(rr.status),
                    confidence=Confidence.MEDIUM, status=Status.INFO,
                ))
    return f
