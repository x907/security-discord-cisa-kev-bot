"""Tests for data models."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.models import KEVEntry, NVDCVEData


def test_kev_entry_valid() -> None:
    """Test valid KEV entry creation."""
    data = {
        "cveID": "CVE-2024-1234",
        "vendorProject": "TestVendor",
        "product": "TestProduct",
        "vulnerabilityName": "Test Vulnerability",
        "dateAdded": "2024-01-15",
        "shortDescription": "A test vulnerability",
        "requiredAction": "Apply updates",
        "dueDate": "2024-02-15",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
    }

    entry = KEVEntry.model_validate(data)
    assert entry.cve_id == "CVE-2024-1234"
    assert entry.vendor_project == "TestVendor"
    assert isinstance(entry.date_added, datetime)


def test_kev_entry_ransomware_normalization() -> None:
    """Test ransomware field normalization."""
    data = {
        "cveID": "CVE-2024-1234",
        "vendorProject": "TestVendor",
        "product": "TestProduct",
        "vulnerabilityName": "Test Vulnerability",
        "dateAdded": "2024-01-15",
        "shortDescription": "A test vulnerability",
        "requiredAction": "Apply updates",
        "dueDate": "2024-02-15",
        "knownRansomwareCampaignUse": " Known ",
        "notes": "",
    }

    entry = KEVEntry.model_validate(data)
    assert entry.known_ransomware_campaign_use == "Known"


def test_nvd_cve_data_severity_score() -> None:
    """Test NVD CVE severity score property."""
    from src.models import CVSSMetric

    cve = NVDCVEData(
        cve_id="CVE-2024-1234",
        cvss_v3=CVSSMetric(
            base_score=9.8,
            base_severity="CRITICAL",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
    )

    assert cve.severity_score == "CRITICAL (9.8)"


def test_nvd_cve_data_no_cvss() -> None:
    """Test NVD CVE with no CVSS data."""
    cve = NVDCVEData(cve_id="CVE-2024-1234")
    assert cve.severity_score == "Not Available"


def test_nvd_cve_data_primary_description() -> None:
    """Test primary description extraction."""
    cve = NVDCVEData(
        cve_id="CVE-2024-1234",
        descriptions=["First description", "Second description"],
    )

    assert cve.primary_description == "First description"


def test_nvd_cve_data_no_description() -> None:
    """Test CVE with no descriptions."""
    cve = NVDCVEData(cve_id="CVE-2024-1234")
    assert cve.primary_description == ""
