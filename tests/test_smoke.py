from portfolio_security_auditor import __version__
from portfolio_security_auditor.cli import threshold_exit
from portfolio_security_auditor.http import normalize_url
from portfolio_security_auditor.models import Finding, Severity
from portfolio_security_auditor.upgrade_engine import build_plan


def test_version_is_semver():
    assert len(__version__.split(".")) == 3


def test_plan_buckets():
    assert set(build_plan([])) == {"NOW", "NEXT", "POLISH", "OPTIONAL"}


def test_normalize_url_adds_scheme_and_strips_slash():
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url(" https://example.com/path/ ") == "https://example.com/path"
    assert normalize_url("http://example.com") == "http://example.com"


def test_threshold_exit_without_fail_on():
    findings = [Finding("x", Severity.CRITICAL, "t", "d")]
    assert threshold_exit(findings, None) == 0


def test_threshold_exit_at_and_below_threshold():
    findings = [Finding("x", Severity.HIGH, "t", "d")]
    assert threshold_exit(findings, "HIGH") == 1
    assert threshold_exit(findings, "CRITICAL") == 0
    assert threshold_exit([], "LOW") == 0
