"""
Composite models for report generation.
"""

from pydantic import BaseModel

from src.feeds.models import Vulnerability
from src.agents.models import VulnerabilityAnalysis


class EnrichedVulnerability(BaseModel):
    """A CISA vulnerability enriched with LLM-generated analysis."""

    vulnerability: Vulnerability
    analysis: VulnerabilityAnalysis