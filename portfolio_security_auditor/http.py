from dataclasses import dataclass, field
import socket
import ssl
import time
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str]
    set_cookies: list[str] = field(default_factory=list)
    body: str = ""
    redirect_chain: list[dict] = field(default_factory=list)
    error: str = ""
    elapsed_ms: float = 0.0
    content_length: int = 0


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def request(url, method="GET", headers=None, timeout=12, max_bytes=500_000,
            follow_redirects=True, max_redirects=8):
    opener = build_opener(NoRedirect)
    current = url
    chain = []
    started = time.perf_counter()
    for _ in range(max_redirects + 1):
        try:
            with opener.open(Request(current, method=method, headers=headers or {}), timeout=timeout) as r:
                raw = r.read(max_bytes) if method.upper() != "HEAD" else b""
                elapsed = (time.perf_counter() - started) * 1000
                return HttpResponse(
                    r.geturl(),
                    r.status,
                    {k.lower(): v.strip() for k, v in r.headers.items()},
                    r.headers.get_all("Set-Cookie") or [],
                    raw.decode("utf-8", "replace"),
                    chain,
                    "",
                    elapsed,
                    len(raw),
                )
        except HTTPError as e:
            h = {k.lower(): v.strip() for k, v in e.headers.items()}
            cookies = e.headers.get_all("Set-Cookie") or []
            loc = h.get("location")
            if e.code in (301, 302, 303, 307, 308) and loc:
                if not follow_redirects:
                    elapsed = (time.perf_counter() - started) * 1000
                    return HttpResponse(current, e.code, h, cookies, "", chain, f"HTTP {e.code}", elapsed, 0)
                target = urljoin(current, loc)
                chain.append({"from": current, "status": e.code, "to": target})
                current = target
                continue
            elapsed = (time.perf_counter() - started) * 1000
            return HttpResponse(current, e.code, h, cookies, "", chain, f"HTTP {e.code}", elapsed, 0)
        except (URLError, TimeoutError, socket.timeout) as e:
            elapsed = (time.perf_counter() - started) * 1000
            return HttpResponse(current, 0, {}, [], "", chain, str(e), elapsed, 0)
        except Exception as e:
            elapsed = (time.perf_counter() - started) * 1000
            return HttpResponse(current, 0, {}, [], "", chain, repr(e), elapsed, 0)
    elapsed = (time.perf_counter() - started) * 1000
    return HttpResponse(current, 0, {}, [], "", chain, "Too many redirects", elapsed, 0)


def tls_info(url, timeout=8):
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname:
        return {"secure": False}
    with socket.create_connection((p.hostname, p.port or 443), timeout=timeout) as s:
        with ssl.create_default_context().wrap_socket(s, server_hostname=p.hostname) as ss:
            return {
                "secure": True,
                "version": ss.version(),
                "cipher": ss.cipher()[0] if ss.cipher() else "",
            }
