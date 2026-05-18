"""
Client for the CISA Known Exploited Vulnerabilities (KEV) feed.

See: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import logging
from typing import Optional

import requests

from src.feeds.models import Vulnerability

logger = logging.getLogger(__name__)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


class CISAClient:
    """Fetches and parses the CISA KEV feed."""

    def __init__(self, url: str = CISA_KEV_URL, timeout: int = 30) -> None:
        self.url = url
        self.timeout = timeout

    def fetch_vulnerabilities(self, limit: Optional[int] = None) -> list[Vulnerability]:
        """
        Download the CISA KEV feed and return a list of Vulnerability objects.

        Args:
            limit: If provided, return only the N most recently added vulnerabilities.

        Returns:
            A list of validated Vulnerability instances.

        Raises:
            requests.HTTPError: If the HTTP request fails.
            pydantic.ValidationError: If the feed structure is unexpected.
        """
        logger.info("Fetching CISA KEV feed from %s", self.url)

        response = requests.get(self.url, timeout=self.timeout)
        response.raise_for_status()

        data = response.json()
        raw_vulns = data.get("vulnerabilities", [])

        logger.info("Received %d vulnerabilities from the feed", len(raw_vulns))

        vulnerabilities = [Vulnerability(**raw) for raw in raw_vulns]

        # CISA returns them in chronological order. We want the most recent first.
        vulnerabilities.sort(key=lambda v: v.date_added, reverse=True)

        if limit is not None:
            vulnerabilities = vulnerabilities[:limit]

        return vulnerabilities