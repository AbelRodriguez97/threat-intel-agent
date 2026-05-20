"""
Markdown report generator for enriched vulnerabilities.
"""

from datetime import date, datetime, timezone
from typing import Iterable

from src.agents.models import Severity
from src.reports.models import EnrichedVulnerability


# Visual indicators for each severity level — used in the report header
SEVERITY_BADGES = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🟢 LOW",
}

# Priority order for sorting vulnerabilities in the report
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def generate_report(
    items: Iterable[EnrichedVulnerability],
    report_date: date | None = None,
) -> str:
    """
    Build a Markdown threat intelligence report from a list of enriched
    vulnerabilities.

    The report is sorted by severity (critical first) and includes:
    - An executive summary with severity counts
    - One section per vulnerability with the LLM analysis

    Args:
        items: Enriched vulnerabilities to include in the report.
        report_date: Date used in the report header. Defaults to today.

    Returns:
        A Markdown-formatted string ready to write to disk.
    """
    report_date = report_date or date.today()
    items_list = sorted(items, key=lambda i: SEVERITY_ORDER[i.analysis.severity])

    sections = [
        _build_header(report_date, items_list),
        _build_summary_table(items_list),
        _build_vulnerability_sections(items_list),
        _build_footer(),
    ]

    return "\n\n".join(sections)


def _build_header(report_date: date, items: list[EnrichedVulnerability]) -> str:
    """Top-level report metadata."""
    severity_counts = _count_by_severity(items)
    counts_line = " · ".join(
        f"{SEVERITY_BADGES[sev]}: {count}"
        for sev, count in severity_counts.items()
        if count > 0
    )

    return (
        f"# 🛡️ Threat Intelligence Report — {report_date.isoformat()}\n\n"
        f"> Generated automatically by `threat-intel-agent` "
        f"on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.\n\n"
        f"**Vulnerabilities analyzed:** {len(items)}  \n"
        f"**Severity breakdown:** {counts_line or 'No vulnerabilities'}"
    )


def _build_summary_table(items: list[EnrichedVulnerability]) -> str:
    """Quick-glance summary table at the top of the report."""
    if not items:
        return "## Summary\n\n*No vulnerabilities to report.*"

    rows = ["## 📊 Summary", "", "| CVE | Vendor / Product | Severity | Date added |",
            "|-----|------------------|----------|------------|"]
    for item in items:
        v = item.vulnerability
        rows.append(
            f"| `{v.cve_id}` "
            f"| {v.vendor_project} / {v.product} "
            f"| {SEVERITY_BADGES[item.analysis.severity]} "
            f"| {v.date_added.isoformat()} |"
        )
    return "\n".join(rows)


def _build_vulnerability_sections(items: list[EnrichedVulnerability]) -> str:
    """One detailed section per vulnerability."""
    if not items:
        return ""

    sections = ["## 🔍 Detailed analysis"]
    for item in items:
        sections.append(_build_single_section(item))
    return "\n\n".join(sections)


def _build_single_section(item: EnrichedVulnerability) -> str:
    """Render a single vulnerability with its LLM analysis."""
    v = item.vulnerability
    a = item.analysis

    actions = "\n".join(f"  {i}. {action}" for i, action in enumerate(a.recommended_actions, 1))
    technologies = ", ".join(a.affected_technologies) if a.affected_technologies else "_Not specified_"

    return (
        f"### {SEVERITY_BADGES[a.severity]} — `{v.cve_id}`\n\n"
        f"**{v.vulnerability_name}** — {v.vendor_project} / {v.product}\n\n"
        f"📅 Added to KEV: {v.date_added.isoformat()} · "
        f"⏳ CISA due date: {v.due_date.isoformat()} · "
        f"💀 Ransomware: {v.known_ransomware_campaign_use}\n\n"
        f"#### Executive summary\n\n{a.executive_summary}\n\n"
        f"#### Affected technologies\n\n{technologies}\n\n"
        f"#### Recommended actions\n\n{actions}\n\n"
        f"#### Rationale\n\n_{a.rationale}_"
    )


def _build_footer() -> str:
    """Footer with sources and disclaimers."""
    return (
        "---\n\n"
        "*Source: [CISA Known Exploited Vulnerabilities Catalog]"
        "(https://www.cisa.gov/known-exploited-vulnerabilities-catalog).*  \n"
        "*Analysis generated with Google Gemini. "
        "Always validate with a human analyst before taking action.*"
    )


def _count_by_severity(items: list[EnrichedVulnerability]) -> dict[Severity, int]:
    """Count how many items fall into each severity bucket."""
    counts = {sev: 0 for sev in Severity}
    for item in items:
        counts[item.analysis.severity] += 1
    return counts