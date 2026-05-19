"""Tests for GeminiAnalyzer."""

from unittest.mock import MagicMock, patch

import pytest

from src.feeds.models import Vulnerability
from src.agents.models import Severity, VulnerabilityAnalysis


@pytest.fixture
def sample_vulnerability():
    """A realistic Vulnerability instance for tests."""
    return Vulnerability(
        cveID="CVE-2024-9999",
        vendorProject="TestVendor",
        product="TestProduct",
        vulnerabilityName="Remote Code Execution",
        dateAdded="2024-06-01",
        shortDescription="A critical RCE vulnerability.",
        requiredAction="Apply vendor patches immediately.",
        dueDate="2024-06-15",
        knownRansomwareCampaignUse="Known",
        notes="",
        cwes=["CWE-78"],
    )


@pytest.fixture
def sample_analysis():
    """A realistic VulnerabilityAnalysis that Gemini might produce."""
    return VulnerabilityAnalysis(
        executive_summary="A critical RCE vulnerability in TestProduct is being actively exploited.",
        severity=Severity.CRITICAL,
        affected_technologies=["TestVendor TestProduct"],
        recommended_actions=[
            "Apply patches immediately",
            "Isolate affected systems from the network",
        ],
        rationale="Active exploitation combined with RCE impact justifies critical severity.",
    )


@patch("src.agents.gemini_analyzer.genai")
def test_analyze_returns_parsed_analysis(mock_genai, sample_vulnerability, sample_analysis):
    """analyze() should return the parsed Pydantic object from response.parsed."""
    # Arrange: mock the Gemini client and response
    mock_response = MagicMock()
    mock_response.parsed = sample_analysis

    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response
    mock_genai.Client.return_value = mock_client

    from src.agents.gemini_analyzer import GeminiAnalyzer

    analyzer = GeminiAnalyzer()
    result = analyzer.analyze(sample_vulnerability)

    assert isinstance(result, VulnerabilityAnalysis)
    assert result.severity == Severity.CRITICAL
    assert "TestVendor TestProduct" in result.affected_technologies
    assert len(result.recommended_actions) == 2


@patch("src.agents.gemini_analyzer.genai")
def test_analyze_raises_when_parsed_is_none(mock_genai, sample_vulnerability):
    """analyze() should raise ValueError when Gemini returns no parseable output."""
    mock_response = MagicMock()
    mock_response.parsed = None
    mock_response.text = "garbled output that did not match the schema"

    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response
    mock_genai.Client.return_value = mock_client

    from src.agents.gemini_analyzer import GeminiAnalyzer

    analyzer = GeminiAnalyzer()

    with pytest.raises(ValueError, match="Could not parse Gemini response"):
        analyzer.analyze(sample_vulnerability)


@patch("src.agents.gemini_analyzer.genai")
def test_analyze_uses_structured_output_config(mock_genai, sample_vulnerability, sample_analysis):
    """analyze() should call Gemini with response_schema set to VulnerabilityAnalysis."""
    mock_response = MagicMock()
    mock_response.parsed = sample_analysis

    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response
    mock_genai.Client.return_value = mock_client

    from src.agents.gemini_analyzer import GeminiAnalyzer

    analyzer = GeminiAnalyzer()
    analyzer.analyze(sample_vulnerability)

    # Verify that the config passed to generate_content uses our schema
    call_kwargs = mock_client.models.generate_content.call_args.kwargs
    assert "config" in call_kwargs
    assert call_kwargs["config"].response_schema is VulnerabilityAnalysis
    assert call_kwargs["config"].response_mime_type == "application/json"