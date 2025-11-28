"""Discord webhook integration with rich embed formatting."""

import logging
from typing import Any

import requests

from .config import Settings
from .models import EnrichedKEV

logger = logging.getLogger(__name__)


class DiscordNotifierError(Exception):
    """Base exception for Discord notifier errors."""


class DiscordWebhookError(DiscordNotifierError):
    """Error sending Discord webhook."""


class DiscordNotifier:
    """Send formatted KEV notifications to Discord via webhooks."""

    # Discord color codes (decimal)
    COLOR_CRITICAL = 0xDC143C  # Crimson
    COLOR_HIGH = 0xFF4500  # OrangeRed
    COLOR_MEDIUM = 0xFFA500  # Orange
    COLOR_LOW = 0xFFD700  # Gold
    COLOR_INFO = 0x1E90FF  # DodgerBlue
    COLOR_RANSOMWARE = 0x8B0000  # DarkRed

    def __init__(self, settings: Settings) -> None:
        """Initialize Discord notifier.

        Args:
            settings: Application settings
        """
        self.settings = settings
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "CISA-KEV-Discord-Bot/1.0",
                "Content-Type": "application/json",
            }
        )

    def _get_severity_color(self, enriched: EnrichedKEV) -> int:
        """Determine embed color based on severity.

        Args:
            enriched: Enriched KEV entry

        Returns:
            Discord color code (decimal)
        """
        # Ransomware gets special treatment
        if enriched.kev_entry.known_ransomware_campaign_use.lower() == "known":
            return self.COLOR_RANSOMWARE

        # Use NVD CVSS score if available
        if enriched.nvd_data and enriched.nvd_data.cvss_v3:
            score = enriched.nvd_data.cvss_v3.base_score
            if score is not None:
                if score >= 9.0:
                    return self.COLOR_CRITICAL
                if score >= 7.0:
                    return self.COLOR_HIGH
                if score >= 4.0:
                    return self.COLOR_MEDIUM
                return self.COLOR_LOW

        # Default to high severity for KEV entries
        return self.COLOR_HIGH

    def _create_embed(self, enriched: EnrichedKEV) -> dict[str, Any]:
        """Create a Discord embed for a KEV entry.

        Args:
            enriched: Enriched KEV entry

        Returns:
            Discord embed dictionary
        """
        kev = enriched.kev_entry
        nvd = enriched.nvd_data

        # Build title with CVE ID and vulnerability name
        title = f"🚨 {kev.cve_id}: {kev.vulnerability_name}"
        if len(title) > 256:
            title = title[:253] + "..."

        # Use NVD description if available, otherwise KEV description
        description = kev.short_description
        if nvd and nvd.primary_description:
            description = nvd.primary_description

        # Truncate description to Discord's 4096 character limit
        if len(description) > 2000:
            description = description[:1997] + "..."

        # Build fields
        fields: list[dict[str, Any]] = [
            {
                "name": "📦 Product",
                "value": f"{kev.vendor_project} - {kev.product}",
                "inline": True,
            },
            {
                "name": "📅 Date Added to KEV",
                "value": kev.date_added.strftime("%Y-%m-%d"),
                "inline": True,
            },
        ]

        # Add CVSS score if available
        if nvd and nvd.severity_score:
            fields.append(
                {
                    "name": "⚠️ CVSS Score",
                    "value": nvd.severity_score,
                    "inline": True,
                }
            )

        # Add ransomware indicator if known
        if kev.known_ransomware_campaign_use.lower() == "known":
            fields.append(
                {
                    "name": "🦠 Ransomware Campaign",
                    "value": "⚠️ **Known to be used in ransomware campaigns**",
                    "inline": False,
                }
            )

        # Add required action
        fields.append(
            {
                "name": "✅ Required Action",
                "value": kev.required_action,
                "inline": False,
            }
        )

        # Add due date
        fields.append(
            {
                "name": "⏰ Due Date",
                "value": kev.due_date.strftime("%Y-%m-%d"),
                "inline": True,
            }
        )

        # Add CWE if available
        if nvd and nvd.cwe_ids:
            cwe_str = ", ".join(nvd.cwe_ids[:3])  # Limit to 3 CWEs
            fields.append(
                {
                    "name": "🔍 Weakness Type",
                    "value": cwe_str,
                    "inline": True,
                }
            )

        # Add references
        reference_links = [f"[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)"]
        reference_links.append(f"[NVD](https://nvd.nist.gov/vuln/detail/{kev.cve_id})")

        if nvd and nvd.references:
            for i, ref in enumerate(nvd.references[:2], 1):  # Add top 2 references
                reference_links.append(f"[Reference {i}]({ref})")

        fields.append(
            {
                "name": "🔗 References",
                "value": " • ".join(reference_links),
                "inline": False,
            }
        )

        # Build embed
        embed = {
            "title": title,
            "description": description,
            "color": self._get_severity_color(enriched),
            "fields": fields,
            "footer": {
                "text": "CISA Known Exploited Vulnerabilities Catalog",
            },
            "timestamp": kev.date_added.isoformat(),
        }

        return embed

    def send_notifications(self, enriched_kevs: list[EnrichedKEV]) -> None:
        """Send KEV notifications to Discord.

        Args:
            enriched_kevs: List of enriched KEV entries to notify

        Raises:
            DiscordWebhookError: If sending fails critically
        """
        if not enriched_kevs:
            logger.info("No KEV entries to send")
            return

        logger.info(f"Preparing to send {len(enriched_kevs)} KEV notifications to Discord")

        # Discord allows max 10 embeds per message
        max_embeds = self.settings.max_discord_embeds_per_message

        # Split into batches
        for i in range(0, len(enriched_kevs), max_embeds):
            batch = enriched_kevs[i : i + max_embeds]
            embeds = [self._create_embed(kev) for kev in batch]

            # Create message payload
            payload: dict[str, Any] = {
                "embeds": embeds,
            }

            # Add summary content if this is the first batch
            if i == 0:
                total = len(enriched_kevs)
                plural = "vulnerability" if total == 1 else "vulnerabilities"
                payload["content"] = (
                    f"**🚨 CISA KEV Alert: {total} new {plural} added to the "
                    f"Known Exploited Vulnerabilities catalog**"
                )

            try:
                response = self.session.post(
                    str(self.settings.discord_webhook_url),
                    json=payload,
                    timeout=self.settings.request_timeout_seconds,
                )
                response.raise_for_status()
                logger.info(
                    f"Successfully sent batch {i // max_embeds + 1} "
                    f"({len(batch)} entries) to Discord"
                )

            except requests.RequestException as e:
                logger.error(f"Failed to send Discord notification: {e}")
                # For the first batch, raise error
                if i == 0:
                    raise DiscordWebhookError(f"Failed to send Discord notification: {e}") from e
                # For subsequent batches, log but continue
                logger.warning("Continuing with remaining batches...")

    def send_test_message(self) -> None:
        """Send a test message to verify webhook configuration.

        Raises:
            DiscordWebhookError: If sending fails
        """
        payload = {
            "content": "✅ CISA KEV Discord Bot test message - webhook is configured correctly!",
            "embeds": [
                {
                    "title": "Test Notification",
                    "description": "This is a test message from the CISA KEV monitoring bot.",
                    "color": self.COLOR_INFO,
                    "fields": [
                        {
                            "name": "Status",
                            "value": "✅ Operational",
                            "inline": True,
                        }
                    ],
                }
            ],
        }

        try:
            response = self.session.post(
                str(self.settings.discord_webhook_url),
                json=payload,
                timeout=self.settings.request_timeout_seconds,
            )
            response.raise_for_status()
            logger.info("Test message sent successfully")
        except requests.RequestException as e:
            raise DiscordWebhookError(f"Failed to send test message: {e}") from e

    def __enter__(self) -> "DiscordNotifier":
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit - cleanup resources."""
        self.session.close()
