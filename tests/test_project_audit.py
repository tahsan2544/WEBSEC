import tempfile
from pathlib import Path

from portfolio_security_auditor.models import Severity
from portfolio_security_auditor.project_audit import ProjectAuditor, audit_project


def test_missing_path_reports_high():
    findings = ProjectAuditor("/nonexistent/websec/path").audit()
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].status.value == "VERIFIED"


def test_placeholder_values_do_not_trigger_secret_findings():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "README.md").write_text("Use Supabase service_role only on a trusted server.")
        (root / "app.ts").write_text('const value = "service_role";')
        (root / ".env").write_text("API_KEY=YOUR_KEY")
        findings = ProjectAuditor(root).audit()
        assert not any(f.check == "secrets" for f in findings)
        assert not any(f.title == "Supabase server credential reference found" for f in findings)
        assert any(f.check == "env" for f in findings)


def test_real_secret_shape_is_detected_and_redacted():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "server.ts").write_text('const key = "sb_secret_abcdefghijklmnopqrstuvwxyz123456";')
        findings = ProjectAuditor(root).audit()
        supabase = [f for f in findings if f.title == "Supabase server credential reference found"]
        assert len(supabase) == 1
        assert supabase[0].severity is Severity.HIGH
        assert supabase[0].location == "server.ts"
        assert supabase[0].evidence == "<redacted>"
        assert "abcdefghijklmnopqrstuvwxyz123456" not in str(supabase[0].as_dict())


def test_private_key_in_source_is_critical():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "server.js").write_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA KEY-----")
        findings = ProjectAuditor(root).audit()
        keys = [f for f in findings if f.title == "Possible private key in source"]
        assert keys, "private key finding expected in a scanned source file"
        assert keys[0].severity is Severity.CRITICAL
        assert keys[0].evidence == "<redacted>"


def test_audit_project_wrapper():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / ".gitignore").write_text("node_modules\n")
        findings = audit_project(root)
        assert isinstance(findings, list)
        assert all(f.metadata.get("target") == "project" for f in findings)
