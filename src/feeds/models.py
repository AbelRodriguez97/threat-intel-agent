"""
Pydantic models for CISA KEV feed entries.
"""

from datetime import date
from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    """A single entry in the CISA Known Exploited Vulnerabilities catalog."""

    cve_id: str = Field(alias="cveID")
    vendor_project: str = Field(alias="vendorProject")
    product: str
    vulnerability_name: str = Field(alias="vulnerabilityName")
    date_added: date = Field(alias="dateAdded")
    short_description: str = Field(alias="shortDescription")
    required_action: str = Field(alias="requiredAction")
    due_date: date = Field(alias="dueDate")
    known_ransomware_campaign_use: str = Field(alias="knownRansomwareCampaignUse")
    notes: str = ""
    cwes: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}