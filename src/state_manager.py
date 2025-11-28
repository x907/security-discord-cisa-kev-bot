"""State management for tracking posted CVEs to prevent duplicates."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class PostedCVE(BaseModel):
    """Record of a posted CVE."""

    cve_id: str
    posted_at: datetime
    date_added_to_kev: datetime


class StateManager:
    """Manage state for tracking posted CVEs."""

    def __init__(self, state_file: Path | str = "state/posted_cves.json") -> None:
        """Initialize state manager.

        Args:
            state_file: Path to state file for storing posted CVEs
        """
        self.state_file = Path(state_file)
        self.posted_cves: dict[str, PostedCVE] = {}
        self._ensure_state_dir()
        self._load_state()

    def _ensure_state_dir(self) -> None:
        """Ensure the state directory exists."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

    def _load_state(self) -> None:
        """Load state from file."""
        if not self.state_file.exists():
            logger.info("No existing state file found - starting fresh")
            return

        try:
            with open(self.state_file, "r") as f:
                data: dict[str, Any] = json.load(f)

            for cve_id, cve_data in data.items():
                self.posted_cves[cve_id] = PostedCVE(
                    cve_id=cve_data["cve_id"],
                    posted_at=datetime.fromisoformat(cve_data["posted_at"]),
                    date_added_to_kev=datetime.fromisoformat(cve_data["date_added_to_kev"]),
                )

            logger.info(f"Loaded {len(self.posted_cves)} previously posted CVEs from state")

        except Exception as e:
            logger.error(f"Failed to load state file: {e}")
            logger.warning("Starting with empty state")
            self.posted_cves = {}

    def _save_state(self) -> None:
        """Save state to file."""
        try:
            data = {
                cve_id: {
                    "cve_id": cve.cve_id,
                    "posted_at": cve.posted_at.isoformat(),
                    "date_added_to_kev": cve.date_added_to_kev.isoformat(),
                }
                for cve_id, cve in self.posted_cves.items()
            }

            # Write to temp file first, then rename (atomic operation)
            temp_file = self.state_file.with_suffix(".json.tmp")
            with open(temp_file, "w") as f:
                json.dump(data, f, indent=2)

            temp_file.replace(self.state_file)
            logger.debug(f"Saved state with {len(self.posted_cves)} CVEs")

        except Exception as e:
            logger.error(f"Failed to save state file: {e}")

    def is_posted(self, cve_id: str) -> bool:
        """Check if a CVE has already been posted.

        Args:
            cve_id: CVE identifier to check

        Returns:
            True if already posted, False otherwise
        """
        return cve_id in self.posted_cves

    def mark_as_posted(self, cve_id: str, date_added_to_kev: datetime) -> None:
        """Mark a CVE as posted.

        Args:
            cve_id: CVE identifier
            date_added_to_kev: Date the CVE was added to KEV catalog
        """
        self.posted_cves[cve_id] = PostedCVE(
            cve_id=cve_id,
            posted_at=datetime.now(timezone.utc),
            date_added_to_kev=date_added_to_kev,
        )
        self._save_state()
        logger.info(f"Marked {cve_id} as posted")

    def mark_batch_as_posted(self, cve_entries: list[Any]) -> None:
        """Mark a batch of CVE entries as posted.

        Args:
            cve_entries: List of KEVEntry objects
        """
        for entry in cve_entries:
            # Ensure date is timezone-aware
            date_added = entry.date_added
            if date_added.tzinfo is None:
                date_added = date_added.replace(tzinfo=timezone.utc)

            self.posted_cves[entry.cve_id] = PostedCVE(
                cve_id=entry.cve_id,
                posted_at=datetime.now(timezone.utc),
                date_added_to_kev=date_added,
            )

        self._save_state()
        logger.info(f"Marked {len(cve_entries)} CVEs as posted in batch")

    def get_posted_count(self) -> int:
        """Get count of posted CVEs.

        Returns:
            Number of CVEs in state
        """
        return len(self.posted_cves)

    def cleanup_old_entries(self, days: int = 90) -> None:
        """Remove old entries from state to prevent unbounded growth.

        Args:
            days: Remove entries older than this many days
        """
        cutoff = datetime.now(timezone.utc).timestamp() - (days * 86400)
        initial_count = len(self.posted_cves)

        self.posted_cves = {
            cve_id: cve
            for cve_id, cve in self.posted_cves.items()
            if cve.posted_at.timestamp() > cutoff
        }

        removed = initial_count - len(self.posted_cves)
        if removed > 0:
            self._save_state()
            logger.info(f"Cleaned up {removed} old entries from state")
