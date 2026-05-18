"""Tests for CISAClient."""

from datetime import date

import pytest

from src.feeds.cisa import CISAClient
from src.feeds.models import Vulnerability


@pytest.fixture
def sample_feed_response():
    """A minimal valid CISA feed response for testing."""
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.01.01",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-0001",
                "vendorProject": "TestVendor",
                "product": "TestProduct",
                "vulnerabilityName": "Test vulnerability",
                "dateAdded": "2024-01-15",
                "shortDescription": "A test vulnerability.",
                "requiredAction": "Apply patches.",
                "dueDate": "2024-02-01",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
                "cwes": ["CWE-79"],
            },
            {
                "cveID": "CVE-2024-0002",
                "vendorProject": "AnotherVendor",
                "product": "AnotherProduct",
                "vulnerabilityName": "Another vulnerability",
                "dateAdded": "2024-02-20",
                "shortDescription": "Another test vulnerability.",
                "requiredAction": "Update software.",
                "dueDate": "2024-03-01",
                "knownRansomwareCampaignUse": "Known",
                "notes": "",
                "cwes": [],
            },
        ],
    }


def test_vulnerability_model_parses_correctly(sample_feed_response):
    """Vulnerability model should map JSON aliases to Python attributes."""
    raw = sample_feed_response["vulnerabilities"][0]
    vuln = Vulnerability(**raw)

    assert vuln.cve_id == "CVE-2024-0001"
    assert vuln.vendor_project == "TestVendor"
    assert vuln.date_added == date(2024, 1, 15)
    assert vuln.cwes == ["CWE-79"]


def test_client_returns_sorted_descending(sample_feed_response, requests_mock):
    """fetch_vulnerabilities should sort by date_added, most recent first."""
    client = CISAClient()
    requests_mock.get(client.url, json=sample_feed_response)

    vulns = client.fetch_vulnerabilities()

    assert len(vulns) == 2
    assert vulns[0].cve_id == "CVE-2024-0002"  # más reciente
    assert vulns[1].cve_id == "CVE-2024-0001"


def test_client_respects_limit(sample_feed_response, requests_mock):
    """fetch_vulnerabilities should respect the limit argument."""
    client = CISAClient()
    requests_mock.get(client.url, json=sample_feed_response)

    vulns = client.fetch_vulnerabilities(limit=1)

    assert len(vulns) == 1
    assert vulns[0].cve_id == "CVE-2024-0002"