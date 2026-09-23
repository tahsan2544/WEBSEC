import argparse
from pathlib import Path

from . import __version__
from .models import Severity, SEVERITY_ORDER
from .project_audit import audit_project
from .report import print_findings, print_scorecard, terminal_plan, to_html, to_json, to_sarif
from .supabase_audit import audit_sql, SupabaseLiveAuditor
from .url_audit import audit_website


def threshold_exit(findings, fail_on):
    if not fail_on:
        return 0
    limit = SEVERITY_ORDER[Severity(fail_on)]
    return 1 if any(SEVERITY_ORDER[f.severity] <= limit for f in findings) else 0


def _add_common(p):
    p.add_argument("--plan", action="store_true", help="Show the prioritized upgrade plan.")
    p.add_argument("--json", action="store_true", help="Write websec-report.json")
    p.add_argument("--html", action="store_true", help="Write websec-report.html")
    p.add_argument("--sarif", action="store_true", help="Write websec-report.sarif")
    p.add_argument("--output-dir", default=".", help="Directory for report files")
    p.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="Exit 1 when findings at or above this severity exist",
    )


def _write_reports(findings, args):
    out = Path(args.output_dir)
    wrote = []
    if args.json:
        out.mkdir(parents=True, exist_ok=True)
        path = out / "websec-report.json"
        path.write_text(to_json(findings), encoding="utf-8")
        wrote.append(path)
    if args.html:
        out.mkdir(parents=True, exist_ok=True)
        path = out / "websec-report.html"
        path.write_text(to_html(findings), encoding="utf-8")
        wrote.append(path)
    if args.sarif:
        out.mkdir(parents=True, exist_ok=True)
        path = out / "websec-report.sarif"
        path.write_text(to_sarif(findings), encoding="utf-8")
        wrote.append(path)
    for path in wrote:
        print(f"Wrote {path}")


def main():
    p = argparse.ArgumentParser(
        prog="websec",
        description="WEBSEC — Website Upgrade Intelligence System",
    )
    p.add_argument("--version", action="version", version=__version__)
    s = p.add_subparsers(dest="command")

    w = s.add_parser("website", help="Audit a website you own or are authorized to assess.")
    w.add_argument("url")
    w.add_argument("--admin-path", default="/admin")
    _add_common(w)

    u = s.add_parser("url", help="Alias for website.")
    u.add_argument("url")
    u.add_argument("--admin-path", default="/admin")
    _add_common(u)

    x = s.add_parser("project", help="Audit a local project for exposed secrets and risky configuration.")
    x.add_argument("path", nargs="?", default=".")
    _add_common(x)

    a = s.add_parser("all", help="Combine a project audit with an optional website audit.")
    a.add_argument("path", nargs="?", default=".")
    a.add_argument("--url")
    a.add_argument("--admin-path", default="/admin")
    _add_common(a)

    q = s.add_parser("supabase-sql", help="Static Supabase SQL review (RLS, policies, SECURITY DEFINER).")
    q.add_argument("file")
    _add_common(q)

    l = s.add_parser("supabase-live", help="Read-only Supabase endpoint reachability check.")
    l.add_argument("project_url")
    l.add_argument("--key", required=True)
    l.add_argument("--table", action="append", required=True)
    _add_common(l)

    args = p.parse_args()
    if not args.command:
        p.print_help()
        return

    if args.command in {"website", "url"}:
        findings = audit_website(args.url, args.admin_path)
    elif args.command == "project":
        findings = audit_project(args.path)
    elif args.command == "supabase-sql":
        findings = audit_sql(args.file)
    elif args.command == "supabase-live":
        findings = SupabaseLiveAuditor(args.project_url, args.key).audit_tables(args.table)
    else:
        findings = audit_project(args.path)
        if args.url:
            findings += audit_website(args.url, args.admin_path)

    print(f"WEBSEC {__version__} | Findings: {len(findings)}")
    print_scorecard(findings)
    print_findings(findings)
    if args.plan:
        print()
        terminal_plan(findings)
    _write_reports(findings, args)
    raise SystemExit(threshold_exit(findings, args.fail_on))


if __name__ == "__main__":
    main()
