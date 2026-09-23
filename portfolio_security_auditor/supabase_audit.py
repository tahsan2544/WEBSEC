from pathlib import Path
import re

from .models import Finding, Severity, Confidence, Status
from .http import request, normalize_url


def audit_sql(path):
    p = Path(path)
    if not p.exists():
        return [Finding(
            "supabase-sql", Severity.HIGH, "SQL file not found", str(p),
            "Verify the path to the SQL file you want to review.",
            confidence=Confidence.HIGH, status=Status.VERIFIED,
        )]
    t = p.read_text(errors="ignore")
    f = []
    tables = re.findall(
        r"(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?([A-Za-z_][\w$]*)", t
    )
    enabled = {
        x.lower()
        for x in re.findall(
            r"(?is)alter\s+table\s+(?:only\s+)?(?:public\.)?([A-Za-z_][\w$]*)\s+enable\s+row\s+level\s+security",
            t,
        )
    }
    for table in tables:
        if table.lower() not in enabled:
            f.append(Finding(
                "rls", Severity.MEDIUM,
                f"RLS enablement not found for table {table}",
                "The SQL does not show RLS enabled.",
                "If exposed through Supabase API, explicitly decide whether RLS should protect it.",
                location=str(p),
                confidence=Confidence.HIGH, status=Status.DETECTED,
            ))
    for m in re.finditer(r"(?is)create\s+policy\s+.*?\s+on\s+(?:public\.)?([\w$]+).*?;", t):
        body = m.group(0)
        table = m.group(1)
        low = body.lower()
        if re.search(r"\bto\s+(?:public|anon)\b", low) and re.search(r"\busing\s*\(\s*true\s*\)", low):
            f.append(Finding(
                "rls-policy", Severity.HIGH, f"Broad public policy on {table}",
                "A public/anon policy appears to use USING (true).",
                "Confirm unrestricted access is intentional; otherwise add row/tenant predicates.",
                location=str(p), evidence=body[:700],
                confidence=Confidence.HIGH, status=Status.DETECTED,
            ))
        if re.search(r"\bto\s+authenticated\b", low) and re.search(r"\busing\s*\(\s*true\s*\)", low):
            f.append(Finding(
                "rls-policy", Severity.MEDIUM,
                f"Authenticated policy on {table} uses USING (true)",
                "Authenticated users appear able to pass the policy without a row predicate.",
                "Verify this broad access is intentional.",
                location=str(p), evidence=body[:700],
                confidence=Confidence.HIGH, status=Status.DETECTED,
            ))
    for m in re.finditer(r"(?is)create\s+(?:or\s+replace\s+)?function\s+.*?security\s+definer.*?(?:;)", t):
        if "search_path" not in m.group(0).lower():
            f.append(Finding(
                "functions", Severity.MEDIUM,
                "SECURITY DEFINER function lacks obvious search_path control",
                "A SECURITY DEFINER function lacks an obvious SET search_path.",
                "Review search_path safety and privilege boundaries.",
                location=str(p),
                confidence=Confidence.MEDIUM, status=Status.HEURISTIC,
            ))
    return f


class SupabaseLiveAuditor:
    def __init__(self, url, key, timeout=12):
        self.url = normalize_url(url)
        self.key = key.strip()
        self.timeout = timeout

    def audit_tables(self, tables):
        out = []
        for table in tables:
            r = request(
                f"{self.url}/rest/v1/{table}?select=*&limit=0",
                method="HEAD",
                headers={"apikey": self.key, "Authorization": f"Bearer {self.key}"},
                timeout=self.timeout,
            )
            if r.status == 200:
                out.append(Finding(
                    "supabase-live", Severity.INFO,
                    f"Supabase endpoint accepted read request for {table}",
                    "A read-only HEAD request succeeded. This confirms endpoint accessibility, not a vulnerability.",
                    "Review RLS and intended access.",
                    location=f"/rest/v1/{table}",
                    confidence=Confidence.HIGH, status=Status.VERIFIED,
                ))
            elif r.status in (401, 403):
                out.append(Finding(
                    "supabase-live", Severity.PASS,
                    f"Supabase endpoint rejected read request for {table}",
                    f"HTTP {r.status} was returned.",
                    confidence=Confidence.HIGH, status=Status.PASS,
                ))
            else:
                out.append(Finding(
                    "supabase-live", Severity.INFO,
                    f"Supabase endpoint returned HTTP {r.status} for {table}",
                    "The response is inconclusive for authorization.",
                    confidence=Confidence.HIGH, status=Status.INFO,
                ))
        return out
