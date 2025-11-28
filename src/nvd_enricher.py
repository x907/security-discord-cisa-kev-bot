"""NVD API integration for CVE enrichment with rate limiting."""

import logging
import time
from typing import Any

import requests
from pydantic import ValidationError

from .config import Settings
from .models import CVSSMetric, NVDCVEData

logger = logging.getLogger(__name__)


class NVDEnricherError(Exception):
    """Base exception for NVD enricher errors."""


class NVDAPIError(NVDEnricherError):
    """Error calling NVD API."""


class NVDParseError(NVDEnricherError):
    """Error parsing NVD response."""


class NVDEnricher:
    """Enrich CVE data using the NVD API with rate limiting."""

    def __init__(self, settings: Settings) -> None:
        """Initialize NVD enricher with settings.

        Args:
            settings: Application settings
        """
        self.settings = settings
        self.session = requests.Session()

        # Setup headers
        headers = {
            "User-Agent": "CISA-KEV-Discord-Bot/1.0",
            "Accept": "application/json",
        }

        # Add API key if available
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key
            logger.info("NVD API key configured - using enhanced rate limits (50 req/30s)")
        else:
            logger.warning(
                "NVD API key not configured - using public rate limits (5 req/30s). "
                "Get a free API key at https://nvd.nist.gov/developers/request-an-api-key"
            )

        self.session.headers.update(headers)
        self.last_request_time: float | None = None

    def _rate_limit(self) -> None:
        """Enforce rate limiting between API requests."""
        if self.last_request_time is not None:
            elapsed = time.time() - self.last_request_time
            delay_needed = self.settings.nvd_request_delay_seconds - elapsed

            if delay_needed > 0:
                logger.debug(f"Rate limiting: sleeping {delay_needed:.2f}s")
                time.sleep(delay_needed)

        self.last_request_time = time.time()

    def _parse_cvss_metric(self, metric_data: dict[str, Any]) -> CVSSMetric:
        """Parse CVSS metric data from NVD response.

        Args:
            metric_data: CVSS metric data from API

        Returns:
            Parsed CVSS metric
        """
        cvss_data = metric_data.get("cvssData", {})
        return CVSSMetric(
            base_score=cvss_data.get("baseScore"),
            base_severity=cvss_data.get("baseSeverity"),
            vector_string=cvss_data.get("vectorString"),
        )

    def enrich_cve(self, cve_id: str, max_retries: int = 3) -> NVDCVEData | None:
        """Enrich CVE data from NVD API with exponential backoff retry logic.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')
            max_retries: Maximum number of retry attempts for transient failures

        Returns:
            Enriched CVE data or None if not found/error

        Raises:
            NVDAPIError: If API request fails critically
        """
        url = f"{self.settings.nvd_base_url}"
        params = {"cveId": cve_id}

        for attempt in range(max_retries + 1):
            # Rate limit before making request
            self._rate_limit()

            try:
                logger.info(f"Fetching NVD data for {cve_id} (attempt {attempt + 1}/{max_retries + 1})")
                response = self.session.get(
                    url,
                    params=params,
                    timeout=self.settings.request_timeout_seconds,
                )

                # Handle different status codes
                if response.status_code == 404:
                    logger.warning(f"CVE {cve_id} not found in NVD")
                    return None

                if response.status_code == 403:
                    logger.error(f"NVD API access forbidden for {cve_id} - check API key")
                    return None

                # Handle rate limiting with exponential backoff
                if response.status_code == 429:
                    if attempt < max_retries:
                        backoff_time = (2 ** attempt) * self.settings.nvd_request_delay_seconds
                        logger.warning(
                            f"Rate limited by NVD for {cve_id}. "
                            f"Backing off for {backoff_time:.1f}s before retry {attempt + 2}/{max_retries + 1}"
                        )
                        time.sleep(backoff_time)
                        continue
                    else:
                        logger.error(f"Rate limit exceeded for {cve_id} after {max_retries} retries")
                        return None

                # Handle transient server errors with exponential backoff
                if response.status_code in (500, 502, 503, 504):
                    if attempt < max_retries:
                        backoff_time = (2 ** attempt) * 2  # 2s, 4s, 8s
                        logger.warning(
                            f"Server error {response.status_code} for {cve_id}. "
                            f"Retrying in {backoff_time}s (attempt {attempt + 2}/{max_retries + 1})"
                        )
                        time.sleep(backoff_time)
                        continue
                    else:
                        logger.error(f"Server error for {cve_id} after {max_retries} retries")
                        return None

                response.raise_for_status()
                break  # Success - exit retry loop

            except requests.Timeout:
                if attempt < max_retries:
                    backoff_time = (2 ** attempt) * 2
                    logger.warning(
                        f"Timeout for {cve_id}. Retrying in {backoff_time}s "
                        f"(attempt {attempt + 2}/{max_retries + 1})"
                    )
                    time.sleep(backoff_time)
                    continue
                else:
                    logger.error(f"Timeout for {cve_id} after {max_retries} retries")
                    return None

            except requests.RequestException as e:
                logger.error(f"Request failed for {cve_id}: {e}")
                return None

        # Parse the successful response
        try:

            data: dict[str, Any] = response.json()

            # Parse response
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                logger.warning(f"No vulnerability data found for {cve_id}")
                return None

            cve_item = vulnerabilities[0].get("cve", {})

            # Extract descriptions
            descriptions: list[str] = []
            for desc in cve_item.get("descriptions", []):
                if desc.get("lang") == "en":
                    descriptions.append(desc.get("value", ""))

            # Extract CVSS metrics
            metrics = cve_item.get("metrics", {})
            cvss_v3 = None
            cvss_v2 = None

            # Try CVSSv3.1 first, then CVSSv3.0
            for version in ["cvssMetricV31", "cvssMetricV30"]:
                if version in metrics and metrics[version]:
                    cvss_v3 = self._parse_cvss_metric(metrics[version][0])
                    break

            if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_v2 = self._parse_cvss_metric(metrics["cvssMetricV2"][0])

            # Extract references
            references: list[str] = []
            for ref in cve_item.get("references", []):
                url = ref.get("url")
                if url:
                    references.append(url)

            # Extract CWE IDs
            cwe_ids: list[str] = []
            for weakness in cve_item.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    value = desc.get("value", "")
                    if value.startswith("CWE-"):
                        cwe_ids.append(value)

            # Parse dates
            published = cve_item.get("published")
            modified = cve_item.get("lastModified")

            nvd_data = NVDCVEData(
                cve_id=cve_id,
                published_date=published,
                last_modified_date=modified,
                descriptions=descriptions,
                cvss_v3=cvss_v3,
                cvss_v2=cvss_v2,
                references=references[:5],  # Limit references to top 5
                cwe_ids=cwe_ids,
            )

            logger.info(f"Successfully enriched {cve_id}")
            return nvd_data

        except (ValueError, KeyError, ValidationError) as e:
            logger.error(f"Failed to parse NVD data for {cve_id}: {e}")
            return None

    def __enter__(self) -> "NVDEnricher":
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit - cleanup resources."""
        self.session.close()
