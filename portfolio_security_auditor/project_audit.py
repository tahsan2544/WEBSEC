from pathlib import Path
import re

from .models import Finding, Severity, Confidence, Status


SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"(?i)\b(?:api[_-]?key|token|secret|private[_-]?key|password|db[_-]?password)\s*[:=]\s*['\"]([^'\s'\"]{16,})"), "secret-like assignment"),
    (re.compile(r"AIza[0-9A-Za-z_-]{30,}"), "Google API key"),
    (re.compile(r"sb_secret_[A-Za-z0-9._-]{20,}"), "Supabase secret key"),
]
PLACEHOLDER = re.compile(
    r"(?i)^(?:your[_-]?(?:key|token|secret|password)|example|changeme|replace[_-]?me|xxxxx+"
    r"|test[_-]?(?:key|token|secret)|<[^>]+>|dummy|placeholder)$"
)
TERM_ONLY = re.compile(r"(?i)^(?:service[_-]?role|sb_secret|supabase[_-]?(?:service|secret)[_-]?(?:role|key)?)$")


class ProjectAuditor:
    SKIP = {".git", "node_modules", ".next", "dist", "build", "coverage", ".venv", "venv",
            "__pycache__", ".idea", ".vscode"}
    EXTS = {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rs", ".java", ".kt", ".json",
            ".toml", ".yaml", ".yml", ".env", ".md", ".html", ".css", ".sql", ".sh", ".txt"}
    DOC_NAMES = {"README.md", "SECURITY.md", "CHANGELOG.md", "CONTRIBUTING.md"}
    SAMPLE_DIRS = {"examples", "example", "samples", "sample", "fixtures", "docs", "doc"}

    def __init__(self, path):
        self.root = Path(path).expanduser().resolve()

    def _files(self):
        if not self.root.exists():
            return
        for p in self.root.rglob("*"):
            if p.is_file() and not any(x in self.SKIP for x in p.parts) and (
                p.suffix.lower() in self.EXTS or p.name in {".env", ".gitignore"}
            ):
                yield p

    def _classification(self, p):
        rel = p.relative_to(self.root)
        parts = set(rel.parts[:-1])
        if p.name in self.DOC_NAMES:
            return "documentation"
        if parts & self.SAMPLE_DIRS:
            return "sample"
        if "tests" in parts or "test" in parts:
            return "test"
        return "source"

    def audit(self):
        if not self.root.exists():
            return [Finding(
                "project", Severity.HIGH, "Project path does not exist", str(self.root),
                "Verify the path you passed to the project audit.",
                confidence=Confidence.HIGH, status=Status.VERIFIED,
                metadata={"area": "Security", "target": "project"},
            )]
        findings = self._env() + self._ignore() + self._secrets() + self._browser() + self._supabase() + self._deps()
        for f in findings:
            f.metadata.setdefault("area", "Security")
            f.metadata.setdefault("target", "project")
        return findings

    def _env(self):
        out = []
        for p in self.root.glob(".env*"):
            if p.is_file() and p.name not in {".env.example", ".env.template"}:
                rel = str(p.relative_to(self.root))
                out.append(Finding(
                    "env", Severity.MEDIUM, "Local environment file exists",
                    f"A local environment file was found at {rel}.",
                    "Keep real .env files out of Git and use deployment secret storage.",
                    location=rel,
                    confidence=Confidence.HIGH, status=Status.DETECTED,
                ))
        return out

    def _ignore(self):
        p = self.root / ".gitignore"
        if not p.exists():
            return [Finding(
                "gitignore", Severity.MEDIUM, ".gitignore is missing",
                "No root .gitignore was found.",
                "Add rules for .env and local credentials.",
                confidence=Confidence.HIGH, status=Status.VERIFIED,
            )]
        t = p.read_text(errors="ignore")
        if re.search(r"(?m)^\.env(?:$|[*/])", t) or re.search(r"(?m)^\.env\*$", t):
            return []
        return [Finding(
            "gitignore", Severity.MEDIUM, ".env is not clearly ignored",
            "No obvious .env ignore rule was found.",
            "Add .env to .gitignore.",
            location=".gitignore",
            confidence=Confidence.MEDIUM, status=Status.HEURISTIC,
        )]

    def _secrets(self):
        out = []
        for p in self._files():
            try:
                text = p.read_text(errors="ignore")
            except OSError:
                continue
            if len(text) > 2_000_000:
                continue
            classification = self._classification(p)
            for rx, label in SECRET_PATTERNS:
                for m in rx.finditer(text):
                    token = m.group(1) if m.lastindex else m.group(0)
                    if PLACEHOLDER.search(token) or TERM_ONLY.match(token):
                        continue
                    if classification == "source":
                        severity = Severity.CRITICAL if label == "private key" else Severity.HIGH
                        confidence = Confidence.HIGH
                        status = Status.DETECTED
                    else:
                        severity = Severity.LOW
                        confidence = Confidence.MEDIUM
                        status = Status.HEURISTIC
                    detail = "A secret-like pattern was found; the value is redacted."
                    if classification != "source":
                        detail += (
                            f" The match is in {classification} content, so it may be"
                            " instructional rather than an exposed credential."
                        )
                    out.append(Finding(
                        "secrets", severity, f"Possible {label} in source", detail,
                        "Move server-only credentials to secret storage and rotate credentials if a real secret was exposed.",
                        evidence="<redacted>",
                        location=str(p.relative_to(self.root)),
                        confidence=confidence, status=status,
                        metadata={"classification": classification},
                    ))
                    break
                else:
                    continue
                break
        return out

    def _browser(self):
        rx = re.compile(r"(?i)(localStorage|sessionStorage)\s*\[[^\]]*(?:admin|role|isAdmin|permission)")
        out = []
        for p in self._files():
            try:
                text = p.read_text(errors="ignore")
            except OSError:
                continue
            if rx.search(text):
                out.append(Finding(
                    "browser-auth", Severity.MEDIUM,
                    "Authorization state appears client-controlled",
                    "Browser storage is used for admin/role/permission state. This alone does not prove a vulnerability.",
                    "Enforce authorization on the server/API.",
                    location=str(p.relative_to(self.root)),
                    confidence=Confidence.MEDIUM, status=Status.HEURISTIC,
                ))
        return out

    def _supabase(self):
        patterns = [
            re.compile(r"(?i)\bservice[_-]?role\b\s*[:=]\s*['\"]?([A-Za-z0-9._=-]{20,})"),
            re.compile(r"(?i)\bsb_secret_[A-Za-z0-9._-]{20,}"),
        ]
        out = []
        for p in self._files():
            try:
                text = p.read_text(errors="ignore")
            except OSError:
                continue
            classification = self._classification(p)
            for rx in patterns:
                m = rx.search(text)
                if not m:
                    continue
                token = m.group(1) if m.lastindex else m.group(0)
                if PLACEHOLDER.search(token):
                    continue
                sev = Severity.HIGH if classification == "source" else Severity.LOW
                conf = Confidence.HIGH if classification == "source" else Confidence.MEDIUM
                status = Status.DETECTED if classification == "source" else Status.HEURISTIC
                out.append(Finding(
                    "supabase", sev, "Supabase server credential reference found",
                    "A credential-shaped Supabase server secret appears in project content; the value is redacted.",
                    "Never expose server credentials to browser code; rotate an exposed secret.",
                    evidence="<redacted>",
                    location=str(p.relative_to(self.root)),
                    confidence=conf, status=status,
                    metadata={"classification": classification},
                ))
                break
        return out

    def _deps(self):
        if (self.root / "package.json").exists() and not any(
            (self.root / x).exists()
            for x in ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb"]
        ):
            return [Finding(
                "dependencies", Severity.LOW, "JavaScript lockfile not found",
                "package.json exists without a common lockfile.",
                "Commit a package-manager lockfile for reproducible builds.",
                confidence=Confidence.HIGH, status=Status.VERIFIED,
            )]
        return []


def audit_project(root):
    return ProjectAuditor(root).audit()
