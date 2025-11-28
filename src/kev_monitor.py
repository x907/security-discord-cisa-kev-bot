"""KEV catalog fetching and filtering logic."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from pydantic import ValidationError

from .config import Settings
from .models import KEVCatalog, KEVEntry

logger = logging.getLogger(__name__)


class KEVMonitorError(Exception):
    """Base exception for KEV monitor errors."""


class KEVFetchError(KEVMonitorError):
    """Error fetching KEV data."""


class KEVParseError(KEVMonitorError):
    """Error parsing KEV data."""


class KEVMonitor:
    """Monitor for CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self, settings: Settings) -> None:
        """Initialize KEV monitor with settings.

        Args:
            settings: Application settings
        """
        self.settings = settings
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "CISA-KEV-Discord-Bot/1.0",
                "Accept": "application/json",
            }
        )

    def fetch_kev_catalog(self) -> KEVCatalog:
        """Fetch the current KEV catalog from CISA.

        Returns:
            Parsed KEV catalog

        Raises:
            KEVFetchError: If fetching fails
            KEVParseError: If parsing fails
        """
        try:
            logger.info(f"Fetching KEV catalog from {self.settings.kev_url}")
            response = self.session.get(
                self.settings.kev_url,
                timeout=self.settings.request_timeout_seconds,
            )
            response.raise_for_status()

            raw_data: dict[str, Any] = response.json()
            logger.info(f"Fetched KEV catalog version {raw_data.get('catalogVersion')}")

            return KEVCatalog.model_validate(raw_data)

        except requests.RequestException as e:
            logger.error(f"Failed to fetch KEV catalog: {e}")
            raise KEVFetchError(f"Failed to fetch KEV catalog: {e}") from e
        except (ValueError, KeyError) as e:
            logger.error(f"Invalid JSON response: {e}")
            raise KEVParseError(f"Invalid JSON response: {e}") from e
        except ValidationError as e:
            logger.error(f"Failed to parse KEV catalog: {e}")
            raise KEVParseError(f"Failed to parse KEV catalog: {e}") from e

    def filter_recent_entries(
        self, catalog: KEVCatalog, hours: int | None = None
    ) -> list[KEVEntry]:
        """Filter KEV entries added within the specified time window.

        Args:
            catalog: KEV catalog to filter
            hours: Number of hours to look back (defaults to settings)

        Returns:
            List of KEV entries added within the time window
        """
        if hours is None:
            hours = self.settings.kev_check_hours

        # Calculate cutoff time (UTC)
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        logger.info(f"Filtering entries added after {cutoff_time.isoformat()}")

        recent_entries: list[KEVEntry] = []
        for entry in catalog.vulnerabilities:
            # Ensure date_added is timezone-aware
            entry_date = entry.date_added
            if entry_date.tzinfo is None:
                entry_date = entry_date.replace(tzinfo=timezone.utc)

            if entry_date >= cutoff_time:
                recent_entries.append(entry)
                logger.debug(f"Found recent entry: {entry.cve_id} (added {entry_date})")

        logger.info(f"Found {len(recent_entries)} recent KEV entries")
        return recent_entries

    def get_recent_vulnerabilities(self) -> list[KEVEntry]:
        """Get vulnerabilities added within the configured time window.

        Returns:
            List of recent KEV entries

        Raises:
            KEVMonitorError: If fetching or parsing fails
        """
        catalog = self.fetch_kev_catalog()
        return self.filter_recent_entries(catalog)

    def __enter__(self) -> "KEVMonitor":
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit - cleanup resources."""
        self.session.close()
