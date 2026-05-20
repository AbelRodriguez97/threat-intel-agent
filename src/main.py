"""
Entry point: orchestrates the end-to-end threat intelligence pipeline.

Flow:
  1. Fetch latest vulnerabilities from CISA KEV feed.
  2. For each one, generate an LLM-based analysis with Gemini.
  3. Render the results as a Markdown report and write it to disk.
"""

import argparse
import logging
from datetime import date
from pathlib import Path

from src.feeds.cisa import CISAClient
from src.agents.gemini_analyzer import GeminiAnalyzer
from src.reports.models import EnrichedVulnerability
from src.reports.markdown import generate_report

logger = logging.getLogger(__name__)


def run(limit: int, output_dir: Path) -> Path:
    """
    Execute the full pipeline and write a report to disk.

    Args:
        limit: Number of most-recent vulnerabilities to process.
        output_dir: Directory where the report file will be written.

    Returns:
        The path of the generated report file.
    """
    logger.info("Starting pipeline for the %d most recent vulnerabilities", limit)

    # 1. Ingest
    client = CISAClient()
    vulnerabilities = client.fetch_vulnerabilities(limit=limit)
    logger.info("Fetched %d vulnerabilities to analyze", len(vulnerabilities))

    # 2. Enrich each with LLM analysis
    analyzer = GeminiAnalyzer()
    enriched: list[EnrichedVulnerability] = []
    for i, vuln in enumerate(vulnerabilities, 1):
        logger.info("Analyzing %d/%d: %s", i, len(vulnerabilities), vuln.cve_id)
        try:
            analysis = analyzer.analyze(vuln)
            enriched.append(EnrichedVulnerability(vulnerability=vuln, analysis=analysis))
        except ValueError as e:
            logger.warning("Skipping %s due to analysis error: %s", vuln.cve_id, e)

    # 3. Render and write
    today = date.today()
    report_md = generate_report(enriched, report_date=today)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"report-{today.isoformat()}.md"
    output_path.write_text(report_md, encoding="utf-8")

    logger.info("Report written to %s", output_path)
    return output_path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a daily threat intelligence report.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Number of most-recent vulnerabilities to analyze (default: 5)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports"),
        help="Directory to write the report into (default: ./reports)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run(limit=args.limit, output_dir=args.output_dir)