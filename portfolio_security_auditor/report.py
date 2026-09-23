import json
from collections import Counter
from html import escape

from .models import Severity
from .upgrade_engine import build_scorecard, build_upgrade_summary
from .upgrade_plan import build_upgrade_plan
from . import __version__


def sort_findings(findings):
    from .models import SEVERITY_ORDER
    return sorted(findings, key=lambda x: (SEVERITY_ORDER[x.severity], x.check, x.title, x.location))


def summary(findings):
    return dict(Counter(x.severity.value for x in findings))


def finding_dict(f):
    return f.as_dict()


def to_json(findings):
    payload = {
        "tool": "WEBSEC",
        "version": __version__,
        "scorecard": build_scorecard(findings),
        "summary": summary(findings),
        "upgrade_summary": build_upgrade_summary(findings),
        "upgrade_plan": [x.__dict__ for x in build_upgrade_plan(findings)],
        "findings": [x.as_dict() for x in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2)


def to_sarif(findings):
    results = []
    for x in sort_findings(findings):
        if x.severity is Severity.PASS:
            continue
        if x.severity in {Severity.CRITICAL, Severity.HIGH}:
            level = "error"
        elif x.severity in {Severity.MEDIUM, Severity.LOW}:
            level = "warning"
        else:
            level = "note"
        results.append({
            "ruleId": f"{x.check}:{x.title}",
            "level": level,
            "message": {"text": x.detail},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": x.location or "site"},
                    "region": {},
                }
            }],
        })
    payload = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "WEBSEC", "version": __version__}},
            "results": results,
        }],
    }
    return json.dumps(payload, indent=2)


CSS = """
* { box-sizing: border-box; }
body { margin: 0; padding: 48px 24px; background: #ffffff; color: #15202b;
  font-family: Arial, Helvetica, sans-serif; font-size: 15px; line-height: 1.55; }
main { max-width: 960px; margin: 0 auto; }
header { border-bottom: 3px solid #15202b; padding-bottom: 16px; margin-bottom: 26px; }
h1 { font-family: Georgia, "Times New Roman", serif; font-size: 32px; margin: 0 0 6px; }
h2 { font-family: Georgia, "Times New Roman", serif; font-size: 20px; margin: 36px 0 14px; }
.meta { color: #5b6b7c; font-size: 13px; margin: 0; }
.scores { display: flex; flex-wrap: wrap; gap: 16px 40px; padding: 0; margin: 0; }
.scores > div { min-width: 130px; }
.scores dt { font-size: 12px; color: #5b6b7c; }
.scores dd { margin: 2px 0 0; font-family: Georgia, serif; font-size: 26px; font-weight: 700; }
.counts { display: flex; flex-wrap: wrap; gap: 8px; padding: 0; margin: 0; list-style: none; }
.counts li { border: 1px solid #d8dee6; border-radius: 4px; padding: 5px 10px; font-size: 13px; }
ol.plan { list-style: none; padding: 0; margin: 0; }
ol.plan li { border-top: 1px solid #d8dee6; padding: 13px 0; }
ol.plan li:last-child { border-bottom: 1px solid #d8dee6; }
.pri { display: inline-block; border-radius: 3px; padding: 2px 7px; font-size: 11px;
  font-weight: 700; color: #ffffff; margin-right: 8px; vertical-align: 1px; }
.now .pri { background: #b91c1c; }
.next .pri { background: #b45309; }
.polish .pri { background: #1d4ed8; }
.optional .pri { background: #475569; }
.plan .m { display: block; color: #5b6b7c; font-size: 13px; margin-top: 3px; }
.plan p { margin: 6px 0 0; }
.plan .verify { color: #5b6b7c; font-size: 13px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th { text-align: left; font-size: 12px; color: #5b6b7c; border-bottom: 2px solid #15202b;
  padding: 8px 10px; }
td { border-bottom: 1px solid #d8dee6; padding: 10px; vertical-align: top; }
.sev { display: inline-block; border-radius: 3px; padding: 2px 7px; font-size: 11px;
  font-weight: 700; color: #ffffff; }
.sev-critical { background: #7f1d1d; }
.sev-high { background: #b91c1c; }
.sev-medium { background: #a16207; }
.sev-low { background: #1d4ed8; }
.sev-info { background: #475569; }
.sev-pass { background: #15803d; }
td .detail { display: block; color: #334155; margin-top: 3px; }
td .fix { display: block; color: #5b6b7c; font-size: 13px; margin-top: 3px; }
code { font-family: Consolas, "Liberation Mono", monospace; font-size: 12px;
  word-break: break-all; color: #334155; }
footer { margin-top: 40px; border-top: 1px solid #d8dee6; padding-top: 14px;
  color: #5b6b7c; font-size: 13px; }
@media (max-width: 720px) {
  body { padding: 20px 14px; }
  table { display: block; overflow-x: auto; }
}
"""


def to_html(findings):
    items = sort_findings(findings)
    plan = build_upgrade_plan(findings)
    counts = summary(findings)
    scorecard = build_scorecard(findings)
    has_website = any(f.metadata.get("target") == "website" for f in findings)

    scores_html = ""
    if has_website:
        scores_html = "<dl class='scores'>" + "".join(
            f"<div><dt>{escape(area)}</dt><dd>{value}/100</dd></div>"
            for area, value in scorecard.items()
        ) + "</dl>"

    counts_html = "<ul class='counts'>" + "".join(
        f"<li>{escape(k)}: {v}</li>" for k, v in sorted(counts.items())
    ) + "</ul>"

    plan_html = "".join(
        f"<li class='{escape(x.priority.lower())}'>"
        f"<span class='pri'>{escape(x.priority)}</span>"
        f"<strong>{escape(x.area)}: {escape(x.issue)}</strong>"
        f"<span class='m'>impact {x.impact}/10, effort {escape(x.effort)}"
        f"{(' — ' + escape(x.location)) if x.location else ''}</span>"
        f"<p>{escape(x.action)}</p>"
        f"<p class='verify'>Verify: {escape(x.verify)}</p>"
        "</li>"
        for x in plan[:20]
    ) or "<li class='optional'><p class='meta'>No actionable upgrades were detected.</p></li>"

    rows = "".join(
        f"<tr>"
        f"<td><span class='sev sev-{x.severity.value.lower()}'>{escape(x.severity.value)}</span></td>"
        f"<td><strong>{escape(x.title)}</strong>"
        f"<span class='detail'>{escape(x.detail)}</span>"
        f"<span class='fix'>Fix: {escape(x.recommendation)}</span>"
        + (f"<div><code>{escape(x.evidence)}</code></div>" if x.evidence else "")
        + "</td>"
        f"<td>{escape(x.location) or '<span class=\'meta\'>—</span>'}</td>"
        f"</tr>"
        for x in items
    ) or "<tr><td colspan='3' class='meta'>No findings.</td></tr>"

    return (
        "<!doctype html><html lang='en'><head>"
        "<meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>WEBSEC Audit Report</title><style>{CSS}</style></head><body><main>"
        "<header><h1>WEBSEC Audit Report</h1>"
        f"<p class='meta'>websec {escape(__version__)} · {len(items)} findings · "
        "defensive, read-only audit</p></header>"
        + (f"<h2>Scorecard</h2>{scores_html}" if has_website else "")
        + f"<h2>Finding summary</h2>{counts_html}"
        + f"<h2>Upgrade plan</h2><ol class='plan'>{plan_html}</ol>"
        + "<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Location</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
        "<footer>Use these recommendations as an investigation plan, not proof of"
        " exploitability. Only audit systems you own or are authorized to assess.</footer>"
        "</main></body></html>"
    )


def print_scorecard(findings):
    if not any(f.metadata.get("target") == "website" for f in findings):
        return
    print("\nSCORECARD")
    for area, value in build_scorecard(findings).items():
        print(f"  {area}: {value}/100")


def print_findings(findings):
    items = sort_findings(findings)
    if not items:
        print("\nNo findings. Re-run after changes to confirm.")
        return
    print()
    for x in items:
        print(f"[{x.severity.value}] {x.title}")
        print(f"  {x.detail}")
        if x.recommendation:
            print(f"  Fix: {x.recommendation}")
        if x.location:
            print(f"  Where: {x.location}")
        if x.evidence:
            evidence = x.evidence if len(x.evidence) <= 200 else x.evidence[:197] + "..."
            print(f"  Evidence: {evidence}")
        print()


def terminal_plan(findings):
    plan = build_upgrade_plan(findings)
    groups = {"NOW": [], "NEXT": [], "POLISH": [], "OPTIONAL": []}
    for action in plan:
        groups[action.priority].append(action)
    print("UPGRADE PLAN")
    for name, items in groups.items():
        print(f"\n[{name}]")
        if not items:
            print("  Nothing flagged")
            continue
        for x in items:
            print(f"  • {x.area}: {x.issue} (impact {x.impact}/10, effort {x.effort})")
            print(f"    Do: {x.action}")
            print(f"    Verify: {x.verify}")
