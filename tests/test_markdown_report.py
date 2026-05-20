"""Tests for the Markdown report generator."""

from datetime import date

import pytest

from src.feeds.models import Vulnerability
from src.agents.models import Severity, VulnerabilityAnalysis
from src.reports.models import EnrichedVulnerability
from src.reports.markdown import generate_report


@pytest.fixture
def critical_item() -> EnrichedVulnerability:
    return EnrichedVulnerability(
        vulnerability=Vulnerability(
            cveID="CVE-2024-0001",
            vendorProject="VendorA",
            product="ProductA",
            vulnerabilityName="Critical RCE",
            dateAdded="2024-01-15",
            shortDescription="Critical vulnerability.",
            requiredAction="Patch now.",
            dueDate="2024-02-01",
            knownRansomwareCampaignUse="Known",
            notes="",
            cwes=["CWE-78"],
        ),
        analysis=VulnerabilityAnalysis(
            executive_summary="Critical RCE under active exploitation.",
            severity=Severity.CRITICAL,
            affected_technologies=["VendorA ProductA"],
            recommended_actions=["Patch immediately", "Isolate hosts"],
            rationale="Active exploitation plus RCE impact.",
        ),
    )


@pytest.fixture
def medium_item() -> EnrichedVulnerability:
    return EnrichedVulnerability(
        vulnerability=Vulnerability(
            cveID="CVE-2024-0002",
            vendorProject="VendorB",
            product="ProductB",
            vulnerabilityName="Information disclosure",
            dateAdded="2024-02-20",
            shortDescription="Info disclosure flaw.",
            requiredAction="Update software.",
            dueDate="2024-03-15",
            knownRansomwareCampaignUse="Unknown",
            notes="",
            cwes=[],
        ),
        analysis=VulnerabilityAnalysis(
            executive_summary="A medium-severity information disclosure.",
            severity=Severity.MEDIUM,
            affected_technologies=["VendorB ProductB"],
            recommended_actions=["Apply patch in next maintenance window"],
            rationale="Limited impact, no known exploitation.",
        ),
    )


def test_report_contains_header_with_date(critical_item):
    """Report header should include the date."""
    output = generate_report([critical_item], report_date=date(2024, 6, 1))
    assert "2024-06-01" in output
    assert "Threat Intelligence Report" in output


def test_report_includes_every_cve(critical_item, medium_item):
    """All vulnerabilities passed in should appear in the report."""
    output = generate_report([critical_item, medium_item])
    assert "CVE-2024-0001" in output
    assert "CVE-2024-0002" in output


def test_report_sorts_critical_before_medium(critical_item, medium_item):
    """Critical entries should appear before lower-severity ones."""
    output = generate_report([medium_item, critical_item])  # intentionally reversed
    pos_critical = output.find("CVE-2024-0001")
    pos_medium = output.find("CVE-2024-0002")
    assert pos_critical < pos_medium


def test_report_renders_recommended_actions_as_numbered_list(critical_item):
    """Recommended actions should appear as a numbered list."""
    output = generate_report([critical_item])
    assert "1. Patch immediately" in output
    assert "2. Isolate hosts" in output


def test_report_handles_empty_input():
    """An empty list should produce a valid (if minimal) report."""
    output = generate_report([])
    assert "Threat Intelligence Report" in output
    assert "No vulnerabilities" in output