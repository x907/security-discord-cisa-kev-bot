"""Main orchestration logic for CISA KEV Discord bot."""

import argparse
import logging
import sys
from typing import NoReturn

from .config import Settings, get_settings
from .discord_notifier import DiscordNotifier, DiscordNotifierError
from .kev_monitor import KEVMonitor, KEVMonitorError
from .models import EnrichedKEV
from .nvd_enricher import NVDEnricher

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger(__name__)


class KEVBotError(Exception):
    """Base exception for KEV bot errors."""


def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration.

    Args:
        verbose: Enable debug logging
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger().setLevel(level)

    # Reduce noise from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def enrich_kev_entries(
    kev_entries: list,
    enricher: NVDEnricher,
) -> list[EnrichedKEV]:
    """Enrich KEV entries with NVD data.

    Args:
        kev_entries: List of KEV entries to enrich
        enricher: NVD enricher instance

    Returns:
        List of enriched KEV entries
    """
    enriched: list[EnrichedKEV] = []

    logger.info(f"Enriching {len(kev_entries)} KEV entries with NVD data")

    for kev_entry in kev_entries:
        logger.debug(f"Enriching {kev_entry.cve_id}")

        # Fetch NVD data (returns None on error, doesn't raise)
        nvd_data = enricher.enrich_cve(kev_entry.cve_id)

        enriched_kev = EnrichedKEV(
            kev_entry=kev_entry,
            nvd_data=nvd_data,
        )
        enriched.append(enriched_kev)

    success_count = sum(1 for e in enriched if e.nvd_data is not None)
    logger.info(f"Successfully enriched {success_count}/{len(kev_entries)} entries")

    return enriched


def run_monitor(settings: Settings) -> int:
    """Run the KEV monitoring and notification workflow.

    Args:
        settings: Application settings

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Initialize components
        with (
            KEVMonitor(settings) as kev_monitor,
            NVDEnricher(settings) as nvd_enricher,
            DiscordNotifier(settings) as discord_notifier,
        ):
            # Fetch recent KEV entries
            logger.info("Starting CISA KEV monitoring workflow")
            recent_kevs = kev_monitor.get_recent_vulnerabilities()

            if not recent_kevs:
                logger.info("No new vulnerabilities found in the specified time window")
                return 0

            logger.info(f"Found {len(recent_kevs)} new vulnerabilities")

            # Enrich with NVD data
            enriched_kevs = enrich_kev_entries(recent_kevs, nvd_enricher)

            # Send notifications
            discord_notifier.send_notifications(enriched_kevs)

            logger.info("Successfully completed KEV monitoring workflow")
            return 0

    except KEVMonitorError as e:
        logger.error(f"KEV monitoring error: {e}")
        return 1
    except DiscordNotifierError as e:
        logger.error(f"Discord notification error: {e}")
        return 1
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 1


def run_test(settings: Settings) -> int:
    """Run a test of the Discord webhook.

    Args:
        settings: Application settings

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        logger.info("Testing Discord webhook configuration")
        with DiscordNotifier(settings) as discord_notifier:
            discord_notifier.send_test_message()
        logger.info("Test message sent successfully!")
        return 0
    except DiscordNotifierError as e:
        logger.error(f"Discord test failed: {e}")
        return 1
    except Exception as e:
        logger.exception(f"Unexpected error during test: {e}")
        return 1


def main() -> NoReturn:
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(
        description="CISA KEV Discord Bot - Monitor and report Known Exploited Vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run the monitor (check last 24 hours)
  python -m src.main

  # Test Discord webhook
  python -m src.main --test

  # Enable debug logging
  python -m src.main --verbose

  # Check custom time window (set KEV_CHECK_HOURS env var)
  KEV_CHECK_HOURS=48 python -m src.main
        """,
    )

    parser.add_argument(
        "--test",
        action="store_true",
        help="Send a test message to Discord webhook",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    # Load settings
    try:
        settings = get_settings()
        logger.info("Configuration loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        logger.error("Please ensure DISCORD_WEBHOOK_URL is set in .env file")
        sys.exit(1)

    # Run appropriate workflow
    if args.test:
        exit_code = run_test(settings)
    else:
        exit_code = run_monitor(settings)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
