"""
LangChain tools that wrap the existing pipeline components.

Each tool exposes a discrete capability to the LLM agent:
  - fetch_recent_vulnerabilities: ingest from CISA KEV (cached)
  - analyze_vulnerability:        enrich one CVE with Gemini
  - save_report_from_analyses:    write a Markdown report from existing analyses
                                  (does NOT re-invoke Gemini)

The agent decides which tools to call (and in what order) based on the
user's natural-language request.

Design note
-----------
The tool surface is intentionally split so that report generation does not
duplicate Gemini calls already performed by analyze_vulnerability. This keeps
the LLM cost (and rate-limit pressure) proportional to the number of distinct
CVEs being analyzed, not multiplied across tools.
"""

import logging
from datetime import date
from pathlib import Path
from typing import Optional

from langchain_core.tools import tool

from src.feeds.cisa import CISAClient
from src.feeds.models import Vulnerability
from src.agents.gemini_analyzer import GeminiAnalyzer
from src.agents.models import Severity, VulnerabilityAnalysis
from src.reports.models import EnrichedVulnerability
from src.reports.markdown import generate_report

logger = logging.getLogger(__name__)

# Module-level instances. We instantiate them once per process to avoid
# re-initializing API clients on every tool invocation.
_cisa_client = CISAClient()
_gemini_analyzer = GeminiAnalyzer()

# Simple per-process caches. They live for the duration of one agent run.
_feed_cache: Optional[list[Vulnerability]] = None
_analysis_cache: dict[str, VulnerabilityAnalysis] = {}


def _get_cached_feed() -> list[Vulnerability]:
    """Return the CISA feed, fetching it only on the first call."""
    global _feed_cache
    if _feed_cache is None:
        logger.info("Cache miss: fetching CISA KEV feed for the first time")
        _feed_cache = _cisa_client.fetch_vulnerabilities(limit=50)
    return _feed_cache


@tool
def fetch_recent_vulnerabilities(limit: int = 5) -> list[dict]:
    """
    Fetch the most recently added vulnerabilities from the CISA Known Exploited
    Vulnerabilities (KEV) catalog.

    Use this tool when the user asks about recent threats, latest CVEs,
    new exploited vulnerabilities, or anything that requires fresh data
    from CISA.

    Args:
        limit: Number of vulnerabilities to fetch (most recent first).
               Defaults to 5. Use higher values (10-20) only if the user
               explicitly asks for a comprehensive report.

    Returns:
        A list of dicts, each with: cve_id, vendor_project, product,
        vulnerability_name, date_added, short_description.
    """
    logger.info("Tool: fetch_recent_vulnerabilities(limit=%d)", limit)
    vulns = _get_cached_feed()[:limit]
    return [
        {
            "cve_id": v.cve_id,
            "vendor_project": v.vendor_project,
            "product": v.product,
            "vulnerability_name": v.vulnerability_name,
            "date_added": v.date_added.isoformat(),
            "short_description": v.short_description,
        }
        for v in vulns
    ]


@tool
def analyze_vulnerability(cve_id: str) -> dict:
    """
    Run a Gemini-based threat analysis on a single CVE.

    Use this tool to obtain a structured analysis of a specific vulnerability:
    executive summary, severity classification (critical/high/medium/low),
    affected technologies, recommended actions, and rationale.

    The result is cached per CVE for the duration of this agent run, so calling
    this tool again with the same CVE ID is free.

    Args:
        cve_id: The exact CVE identifier (e.g. "CVE-2024-12345").
                Must come from a previous fetch_recent_vulnerabilities call.

    Returns:
        A dict with the structured analysis fields.
    """
    logger.info("Tool: analyze_vulnerability(cve_id=%s)", cve_id)

    # Cache hit
    if cve_id in _analysis_cache:
        logger.info("Cache hit for analysis of %s", cve_id)
        cached = _analysis_cache[cve_id]
        return _analysis_to_dict(cve_id, cached)

    feed = _get_cached_feed()
    target = next((v for v in feed if v.cve_id == cve_id), None)
    if target is None:
        return {"error": f"CVE {cve_id} not found in the recent CISA KEV catalog."}

    analysis = _gemini_analyzer.analyze(target)
    _analysis_cache[cve_id] = analysis
    return _analysis_to_dict(cve_id, analysis)


@tool
def save_report_from_analyses(cve_ids: list[str], output_dir: str = "reports") -> str:
    """
    Write a Markdown threat intelligence report to disk using the CVE analyses
    already produced earlier in this conversation.

    IMPORTANT: this tool does NOT invoke the LLM. It assumes you have already
    called analyze_vulnerability for each CVE you want to include. If any CVE
    has not been analyzed yet, the tool returns an error listing which ones
    are missing — you should then call analyze_vulnerability for those, and
    retry this tool.

    Use this tool as the FINAL step when the user wants a written report.

    Args:
        cve_ids: List of CVE identifiers to include. Each must have been
                 analyzed earlier in this same agent run.
        output_dir: Directory to write the report into. Defaults to "reports".

    Returns:
        The path of the generated Markdown report, or an error message
        listing CVEs that need to be analyzed first.
    """
    logger.info("Tool: save_report_from_analyses(cve_ids=%s)", cve_ids)

    missing = [cve for cve in cve_ids if cve not in _analysis_cache]
    if missing:
        return (
            f"Cannot generate report yet — the following CVEs have not been "
            f"analyzed: {missing}. Call analyze_vulnerability for each of "
            f"them first, then retry save_report_from_analyses."
        )

    feed = _get_cached_feed()
    by_id = {v.cve_id: v for v in feed}

    enriched: list[EnrichedVulnerability] = []
    for cve_id in cve_ids:
        v = by_id.get(cve_id)
        if v is None:
            logger.warning("CVE %s not found in the feed, skipping", cve_id)
            continue
        analysis = _analysis_cache[cve_id]
        enriched.append(EnrichedVulnerability(vulnerability=v, analysis=analysis))

    today = date.today()
    report_md = generate_report(enriched, report_date=today)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    file_path = output_path / f"report-{today.isoformat()}.md"
    file_path.write_text(report_md, encoding="utf-8")

    return str(file_path)


def _analysis_to_dict(cve_id: str, analysis: VulnerabilityAnalysis) -> dict:
    """Serialize a VulnerabilityAnalysis to a plain dict for tool output."""
    return {
        "cve_id": cve_id,
        "executive_summary": analysis.executive_summary,
        "severity": analysis.severity.value,
        "affected_technologies": analysis.affected_technologies,
        "recommended_actions": analysis.recommended_actions,
        "rationale": analysis.rationale,
    }


# Public list of tools that the agent will use
AVAILABLE_TOOLS = [
    fetch_recent_vulnerabilities,
    analyze_vulnerability,
    save_report_from_analyses,
]