"""Tests for the individual LangChain tools."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def reset_caches():
    """Clear module-level caches before each test to ensure isolation."""
    from src.agents import tools

    tools._feed_cache = None
    tools._analysis_cache = {}
    yield
    tools._feed_cache = None
    tools._analysis_cache = {}


@patch("src.agents.tools._cisa_client")
def test_fetch_recent_vulnerabilities_returns_serialized_dicts(mock_client):
    """The tool should return plain dicts ready for the LLM to read."""
    from src.feeds.models import Vulnerability
    from src.agents.tools import fetch_recent_vulnerabilities

    mock_client.fetch_vulnerabilities.return_value = [
        Vulnerability(
            cveID="CVE-2024-0001",
            vendorProject="VendorA",
            product="ProductA",
            vulnerabilityName="Test vuln",
            dateAdded="2024-01-01",
            shortDescription="Description.",
            requiredAction="Patch.",
            dueDate="2024-02-01",
            knownRansomwareCampaignUse="Unknown",
            notes="",
            cwes=[],
        )
    ]

    result = fetch_recent_vulnerabilities.invoke({"limit": 1})

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["cve_id"] == "CVE-2024-0001"
    assert result[0]["vendor_project"] == "VendorA"


@patch("src.agents.tools._cisa_client")
def test_fetch_uses_cache_on_second_call(mock_client):
    """The CISA feed should be fetched only once per agent run."""
    from src.feeds.models import Vulnerability
    from src.agents.tools import fetch_recent_vulnerabilities

    mock_client.fetch_vulnerabilities.return_value = [
        Vulnerability(
            cveID="CVE-2024-0001",
            vendorProject="V",
            product="P",
            vulnerabilityName="N",
            dateAdded="2024-01-01",
            shortDescription="D",
            requiredAction="A",
            dueDate="2024-02-01",
            knownRansomwareCampaignUse="Unknown",
            notes="",
            cwes=[],
        )
    ]

    fetch_recent_vulnerabilities.invoke({"limit": 1})
    fetch_recent_vulnerabilities.invoke({"limit": 1})

    # Despite two tool invocations, the underlying client was hit only once
    assert mock_client.fetch_vulnerabilities.call_count == 1


@patch("src.agents.tools._gemini_analyzer")
@patch("src.agents.tools._cisa_client")
def test_analyze_vulnerability_returns_error_when_cve_not_found(mock_client, mock_analyzer):
    """If the CVE isn't in the recent catalog, the tool should return an error dict."""
    from src.agents.tools import analyze_vulnerability

    mock_client.fetch_vulnerabilities.return_value = []  # empty catalog

    result = analyze_vulnerability.invoke({"cve_id": "CVE-9999-9999"})

    assert "error" in result
    assert "CVE-9999-9999" in result["error"]
    mock_analyzer.analyze.assert_not_called()


def test_save_report_returns_error_when_analyses_missing():
    """save_report_from_analyses should refuse if some CVEs haven't been analyzed."""
    from src.agents.tools import save_report_from_analyses

    result = save_report_from_analyses.invoke({
        "cve_ids": ["CVE-2024-9999"],
        "output_dir": "reports",
    })

    assert "not been analyzed" in result
    assert "CVE-2024-9999" in result


def test_available_tools_export_is_complete():
    """All three tools should be in AVAILABLE_TOOLS."""
    from src.agents.tools import (
        AVAILABLE_TOOLS,
        fetch_recent_vulnerabilities,
        analyze_vulnerability,
        save_report_from_analyses,
    )

    assert fetch_recent_vulnerabilities in AVAILABLE_TOOLS
    assert analyze_vulnerability in AVAILABLE_TOOLS
    assert save_report_from_analyses in AVAILABLE_TOOLS
    assert len(AVAILABLE_TOOLS) == 3