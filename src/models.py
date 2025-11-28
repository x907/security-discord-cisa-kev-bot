"""Data models for KEV and NVD CVE data."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class KEVEntry(BaseModel):
    """Model for a single KEV catalog entry."""

    cve_id: str = Field(..., alias="cveID")
    vendor_project: str = Field(..., alias="vendorProject")
    product: str
    vulnerability_name: str = Field(..., alias="vulnerabilityName")
    date_added: datetime = Field(..., alias="dateAdded")
    short_description: str = Field(..., alias="shortDescription")
    required_action: str = Field(..., alias="requiredAction")
    due_date: datetime = Field(..., alias="dueDate")
    known_ransomware_campaign_use: str = Field(..., alias="knownRansomwareCampaignUse")
    notes: str = ""

    @field_validator("date_added", "due_date", mode="before")
    @classmethod
    def parse_date(cls, v: Any) -> datetime:
        """Parse date string to datetime object."""
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            try:
                return datetime.strptime(v, "%Y-%m-%d")
            except ValueError:
                # Try ISO format
                return datetime.fromisoformat(v.replace("Z", "+00:00"))
        raise ValueError(f"Invalid date format: {v}")

    @field_validator("known_ransomware_campaign_use", mode="before")
    @classmethod
    def normalize_ransomware_field(cls, v: Any) -> str:
        """Normalize ransomware campaign field."""
        if isinstance(v, str):
            return v.strip()
        return str(v)


class KEVCatalog(BaseModel):
    """Model for the complete KEV catalog."""

    title: str
    catalog_version: str = Field(..., alias="catalogVersion")
    date_released: datetime = Field(..., alias="dateReleased")
    count: int
    vulnerabilities: list[KEVEntry]

    @field_validator("date_released", mode="before")
    @classmethod
    def parse_date_released(cls, v: Any) -> datetime:
        """Parse date released string to datetime object."""
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            try:
                return datetime.strptime(v, "%Y-%m-%d")
            except ValueError:
                return datetime.fromisoformat(v.replace("Z", "+00:00"))
        raise ValueError(f"Invalid date format: {v}")


class CVSSMetric(BaseModel):
    """CVSS metric data from NVD."""

    base_score: float | None = None
    base_severity: str | None = None
    vector_string: str | None = None


class CVEDescription(BaseModel):
    """CVE description from NVD."""

    value: str


class NVDCVEData(BaseModel):
    """Enriched CVE data from NVD API."""

    cve_id: str
    published_date: datetime | None = None
    last_modified_date: datetime | None = None
    descriptions: list[str] = Field(default_factory=list)
    cvss_v3: CVSSMetric | None = None
    cvss_v2: CVSSMetric | None = None
    references: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)

    @property
    def primary_description(self) -> str:
        """Get the primary English description."""
        return self.descriptions[0] if self.descriptions else ""

    @property
    def severity_score(self) -> str:
        """Get a formatted severity score string."""
        if self.cvss_v3 and self.cvss_v3.base_score:
            return f"{self.cvss_v3.base_severity} ({self.cvss_v3.base_score})"
        if self.cvss_v2 and self.cvss_v2.base_score:
            return f"{self.cvss_v2.base_severity} ({self.cvss_v2.base_score})"
        return "Not Available"


class EnrichedKEV(BaseModel):
    """KEV entry enriched with NVD data."""

    kev_entry: KEVEntry
    nvd_data: NVDCVEData | None = None
