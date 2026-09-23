from html.parser import HTMLParser

from .models import Finding, Severity, Confidence, Status


class AccessibilityParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inputs = []
        self.images = []
        self.buttons = []
        self.links = []
        self.heading_levels = []
        self.main_count = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        t = tag.lower()
        if t == "input" and a.get("type", "").lower() not in {"hidden", "submit", "button", "reset"}:
            self.inputs.append(a)
        elif t in {"textarea", "select"}:
            self.inputs.append(a)
        elif t == "img":
            self.images.append(a)
        elif t == "button":
            self.buttons.append(a)
        elif t == "a":
            self.links.append(a)
        elif t in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.heading_levels.append(int(t[1]))
        elif t == "main":
            self.main_count += 1


def _has_accessible_name(attrs):
    return bool(attrs.get("aria-label") or attrs.get("aria-labelledby") or attrs.get("title") or attrs.get("name"))


def audit_accessibility(body):
    p = AccessibilityParser()
    try:
        p.feed(body or "")
    except Exception as exc:
        return [Finding(
            "accessibility", Severity.INFO, "HTML could not be fully parsed for accessibility",
            str(exc), "Review the rendered DOM manually.",
            confidence=Confidence.MEDIUM, status=Status.INFO,
        )]
    f = []
    unlabeled = [x for x in p.inputs if not x.get("id") and not _has_accessible_name(x)]
    if unlabeled:
        f.append(Finding(
            "accessibility", Severity.MEDIUM, "Form controls may lack accessible names",
            f"{len(unlabeled)} form control(s) have no obvious id/name/ARIA label.",
            "Associate each user-editable control with a visible label or equivalent accessible name.",
            confidence=Confidence.MEDIUM, status=Status.HEURISTIC,
        ))
    unnamed_buttons = [x for x in p.buttons if not _has_accessible_name(x)]
    if unnamed_buttons:
        f.append(Finding(
            "accessibility", Severity.MEDIUM, "Buttons may lack accessible names",
            f"{len(unnamed_buttons)} button(s) have no obvious ARIA/name/title attribute. Visible button text may still provide a name.",
            "Give icon-only buttons an accessible name and verify visible text is exposed correctly.",
            confidence=Confidence.LOW, status=Status.HEURISTIC,
        ))
    unnamed_links = [x for x in p.links if not _has_accessible_name(x) and not x.get("href")]
    if unnamed_links:
        f.append(Finding(
            "accessibility", Severity.LOW, "Anchor elements without href were detected",
            f"{len(unnamed_links)} anchor(s) lack href and an obvious accessible name.",
            "Use semantic buttons for actions and real links for navigation.",
            confidence=Confidence.MEDIUM, status=Status.DETECTED,
        ))
    empty_alt = [x for x in p.images if not x.get("alt") and x.get("role") != "presentation"]
    if empty_alt:
        f.append(Finding(
            "accessibility", Severity.MEDIUM, "Images may be missing alt text",
            f"{len(empty_alt)} image(s) have no alt attribute. Some may be decorative.",
            'Add meaningful alt text to informative images; use alt="" for intentionally decorative images.',
            confidence=Confidence.HIGH, status=Status.DETECTED,
        ))
    if p.heading_levels:
        jumps = []
        previous = p.heading_levels[0]
        for level in p.heading_levels[1:]:
            if level - previous > 1:
                jumps.append((previous, level))
            previous = level
        if jumps:
            f.append(Finding(
                "accessibility", Severity.LOW, "Heading levels skip hierarchy levels",
                f"Found heading jumps such as {jumps[0][0]} to {jumps[0][1]}.",
                "Keep heading levels in a logical hierarchy where possible.",
                evidence=str(jumps[:5]),
                confidence=Confidence.MEDIUM, status=Status.HEURISTIC,
            ))
    if p.main_count == 0:
        f.append(Finding(
            "accessibility", Severity.LOW, "Main landmark is not detected",
            "No <main> landmark was detected in the HTML.",
            "Use a main landmark for the primary page content when appropriate.",
            confidence=Confidence.HIGH, status=Status.VERIFIED,
        ))
    elif p.main_count > 1:
        f.append(Finding(
            "accessibility", Severity.LOW, "Multiple main landmarks detected",
            f"{p.main_count} <main> elements were found.",
            "Keep a single primary main landmark for the document unless a justified pattern requires otherwise.",
            confidence=Confidence.HIGH, status=Status.DETECTED,
        ))
    if not f:
        f.append(Finding(
            "accessibility", Severity.PASS, "Basic accessibility structure checks passed",
            "No high-signal structural accessibility issues were detected in the fetched HTML.",
            confidence=Confidence.MEDIUM, status=Status.PASS,
        ))
    return f
