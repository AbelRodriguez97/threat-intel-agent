"""
Pydantic models for LLM analysis outputs.
"""

from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity classification produced by the LLM."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VulnerabilityAnalysis(BaseModel):
    """Structured analysis of a vulnerability produced by the LLM."""

    executive_summary: str = Field(
        description="Two-to-three sentence summary in plain English, "
                    "suitable for a non-technical stakeholder."
    )
    severity: Severity = Field(
        description="Overall severity classification."
    )
    affected_technologies: list[str] = Field(
        default_factory=list,
        description="Affected products, vendors or technology categories."
    )
    recommended_actions: list[str] = Field(
        description="Concrete, prioritized actions a security team should take."
    )
    rationale: str = Field(
        description="Brief justification for the severity classification."
    )