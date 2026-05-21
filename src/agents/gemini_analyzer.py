"""
Gemini-powered analyzer that enriches CISA vulnerabilities with
LLM-generated summaries, severity classification and recommended actions.
"""

import logging
import time

from google import genai
from google.genai import types

from src.config import GEMINI_API_KEY
from src.feeds.models import Vulnerability
from src.agents.models import VulnerabilityAnalysis

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gemini-2.5-flash"

# Free tier limit is 5 requests/minute. We throttle to ~4/minute (15s gap)
# to leave headroom for the agent's own reasoning calls.
MIN_SECONDS_BETWEEN_CALLS = 15.0

ANALYSIS_PROMPT = """\
You are a senior threat intelligence analyst working for a security operations team.

Your task is to analyze a single vulnerability from the CISA Known Exploited
Vulnerabilities (KEV) catalog and produce a structured assessment that the
team can use to prioritize their response.

Be precise, factual, and avoid speculation. If information is missing, do not
invent it — base your analysis only on the data provided.

# Vulnerability data

- CVE ID: {cve_id}
- Vendor / Product: {vendor_project} / {product}
- Vulnerability name: {vulnerability_name}
- Date added to KEV: {date_added}
- Short description: {short_description}
- Required action (per CISA): {required_action}
- Known ransomware campaign use: {ransomware_use}
- CWEs: {cwes}
"""


class GeminiAnalyzer:
    """Uses Gemini to enrich CISA vulnerabilities with structured analysis."""

    def __init__(self, model_name: str = DEFAULT_MODEL) -> None:
        self._client = genai.Client(api_key=GEMINI_API_KEY)
        self._model_name = model_name
        self._last_call_at: float = 0.0
        logger.info("Initialized GeminiAnalyzer with model %s", model_name)

    def analyze(self, vulnerability: Vulnerability) -> VulnerabilityAnalysis:
        """
        Produce a structured analysis of a single vulnerability.

        Applies client-side throttling between calls to stay within the
        Gemini free-tier rate limit (5 requests/minute).

        Args:
            vulnerability: A Vulnerability instance from the CISA feed.

        Returns:
            A validated VulnerabilityAnalysis.

        Raises:
            ValueError: If the LLM response cannot be parsed as the expected schema.
        """
        self._wait_for_rate_limit()

        prompt = self._build_prompt(vulnerability)
        logger.debug("Sending prompt for %s", vulnerability.cve_id)

        response = self._client.models.generate_content(
            model=self._model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=VulnerabilityAnalysis,
            ),
        )

        self._last_call_at = time.monotonic()

        parsed = response.parsed
        if parsed is None:
            logger.error("Gemini returned no parseable output: %s", response.text[:200])
            raise ValueError(
                f"Could not parse Gemini response for {vulnerability.cve_id}"
            )

        return parsed

    def _wait_for_rate_limit(self) -> None:
        """Sleep until enough time has passed since the previous call."""
        if self._last_call_at == 0.0:
            return  # first call, no wait needed

        elapsed = time.monotonic() - self._last_call_at
        remaining = MIN_SECONDS_BETWEEN_CALLS - elapsed
        if remaining > 0:
            logger.info("Rate-limit throttle: sleeping %.1fs", remaining)
            time.sleep(remaining)

    def _build_prompt(self, v: Vulnerability) -> str:
        return ANALYSIS_PROMPT.format(
            cve_id=v.cve_id,
            vendor_project=v.vendor_project,
            product=v.product,
            vulnerability_name=v.vulnerability_name,
            date_added=v.date_added.isoformat(),
            short_description=v.short_description,
            required_action=v.required_action,
            ransomware_use=v.known_ransomware_campaign_use,
            cwes=", ".join(v.cwes) if v.cwes else "None",
        )