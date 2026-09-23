from html.parser import HTMLParser

from .models import Finding, Severity, Confidence, Status


class ResourceParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts = []
        self.images = []
        self.styles = []
        self.preloads = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        t = tag.lower()
        if t == "script":
            self.scripts.append(a)
        elif t == "img":
            self.images.append(a)
        elif t == "link":
            rel = a.get("rel", "").lower()
            if rel == "stylesheet":
                self.styles.append(a)
            elif rel == "preload":
                self.preloads.append(a)


def audit_performance(response):
    body = response.body or ""
    p = ResourceParser()
    try:
        p.feed(body)
    except Exception:
        p = ResourceParser()
    f = []
    size = len(body.encode("utf-8"))
    if response.elapsed_ms >= 1800:
        f.append(Finding(
            "performance", Severity.HIGH, "Homepage response is slow",
            f"Initial HTTP request took about {response.elapsed_ms:.0f} ms.",
            "Investigate server response time, database/API calls, middleware, caching and edge delivery.",
            evidence=f"{response.elapsed_ms:.0f} ms",
            confidence=Confidence.MEDIUM, status=Status.DETECTED,
            metadata={"area": "Performance"},
        ))
    elif response.elapsed_ms >= 900:
        f.append(Finding(
            "performance", Severity.MEDIUM, "Homepage response time is elevated",
            f"Initial HTTP request took about {response.elapsed_ms:.0f} ms.",
            "Look for server/API latency and cache opportunities before optimizing client-side code.",
            evidence=f"{response.elapsed_ms:.0f} ms",
            confidence=Confidence.MEDIUM, status=Status.DETECTED,
            metadata={"area": "Performance"},
        ))
    if size > 500_000:
        f.append(Finding(
            "performance", Severity.MEDIUM, "HTML payload is large",
            f"The fetched HTML is about {size / 1024:.0f} KiB.",
            "Reduce initial HTML, server-render only required content, and avoid embedding large data blobs.",
            evidence=f"{size} bytes",
            confidence=Confidence.HIGH, status=Status.DETECTED,
            metadata={"area": "Performance"},
        ))
    elif size > 250_000:
        f.append(Finding(
            "performance", Severity.LOW, "HTML payload is moderately large",
            f"The fetched HTML is about {size / 1024:.0f} KiB.",
            "Review inline data and non-critical markup for opportunities to reduce initial payload.",
            evidence=f"{size} bytes",
            confidence=Confidence.HIGH, status=Status.DETECTED,
            metadata={"area": "Performance"},
        ))
    if len(p.scripts) > 15:
        f.append(Finding(
            "performance", Severity.MEDIUM, "Too many JavaScript files",
            f"{len(p.scripts)} script tags were detected in the initial HTML.",
            "Reduce script count, defer non-critical code, and consolidate only when your bundler benefits from it.",
            evidence=str(len(p.scripts)),
            confidence=Confidence.MEDIUM, status=Status.HEURISTIC,
            metadata={"area": "Performance"},
        ))
    elif len(p.scripts) > 8:
        f.append(Finding(
            "performance", Severity.LOW, "JavaScript file count is high",
            f"{len(p.scripts)} script tags were detected in the initial HTML.",
            "Review whether non-critical scripts can be deferred or removed.",
            evidence=str(len(p.scripts)),
            confidence=Confidence.MEDIUM, status=Status.HEURISTIC,
            metadata={"area": "Performance"},
        ))
    encoding = response.headers.get("content-encoding", "")
    if not encoding and size > 100_000:
        f.append(Finding(
            "performance", Severity.LOW, "Compression is not evident for a large HTML response",
            "The response did not expose a Content-Encoding header.",
            "Confirm Brotli or gzip compression is enabled at the edge/server.",
            evidence=encoding,
            confidence=Confidence.MEDIUM, status=Status.INFO,
            metadata={"area": "Performance"},
        ))
    cache = response.headers.get("cache-control", "").lower()
    if not cache and response.status == 200:
        f.append(Finding(
            "performance", Severity.INFO, "Cache policy is not evident on the homepage",
            "No Cache-Control header was observed on the initial response.",
            "Review caching policy for static assets and cacheable public HTML.",
            confidence=Confidence.MEDIUM, status=Status.INFO,
            metadata={"area": "Performance"},
        ))
    if not f:
        f.append(Finding(
            "performance", Severity.PASS, "Basic performance checks passed",
            "No high-signal performance issue was detected in the initial HTML/HTTP response.",
            confidence=Confidence.MEDIUM, status=Status.PASS,
            metadata={"area": "Performance"},
        ))
    return f
