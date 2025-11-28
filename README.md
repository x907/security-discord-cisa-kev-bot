# CISA KEV Discord Bot

A professional Python bot that monitors the [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and posts notifications to Discord when new vulnerabilities are added. The bot enriches KEV data with detailed information from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/) API.

## Features

- **Automated Monitoring**: Runs on GitHub Actions hourly to check for new KEV entries
- **Rich Notifications**: Beautifully formatted Discord embeds with comprehensive vulnerability information
- **NVD Enrichment**: Enhances KEV data with CVSS scores, CWE classifications, and detailed descriptions
- **Security-First Design**: Built with input validation, proper error handling, and secure configuration management
- **Smart Rate Limiting**: Respects NVD API rate limits with exponential backoff retry logic
- **Resilient**: Automatic retry with exponential backoff for transient failures (429, 500, 502, 503, 504)
- **Ransomware Alerts**: Special highlighting for vulnerabilities used in ransomware campaigns

## Quick Start

### Prerequisites

- Python 3.11+
- Discord webhook URL
- **Strongly Recommended:** Free NVD API key for 10x faster rate limits

### Installation

1. Clone the repository:
```bash
git clone https://github.com/x907/security-discord-cisa-kev-bot.git
cd security-discord-cisa-kev-bot
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env and add your Discord webhook URL
```

4. Test the configuration:
```bash
python -m src.main --test
```

5. Run the monitor:
```bash
python -m src.main
```

## Configuration

### Required Environment Variables

- `DISCORD_WEBHOOK_URL`: Your Discord webhook URL (required)

### Strongly Recommended Environment Variables

- `NVD_API_KEY`: **Free** NVD API key for 10x faster rate limits (5 req/30s → 50 req/30s)
  - **Get your free API key at:** https://nvd.nist.gov/developers/request-an-api-key
  - Without a key, the bot will be significantly slower and may timeout on large batches
  - Registration is free and instant
- `KEV_CHECK_HOURS`: Hours to look back for new vulnerabilities (default: 24)
- `NVD_REQUEST_DELAY_SECONDS`: Delay between NVD requests (default: 6.0 without key, 0.6 with key)
- `MAX_DISCORD_EMBEDS_PER_MESSAGE`: Maximum embeds per message (default: 10)

### Discord Webhook Setup

1. Go to your Discord server settings
2. Navigate to Integrations → Webhooks
3. Click "New Webhook"
4. Configure the webhook name and channel
5. Copy the webhook URL
6. Add it to your `.env` file

## GitHub Actions Setup

### Required Secrets

Configure these in your repository settings (Settings → Secrets and variables → Actions):

- `DISCORD_WEBHOOK_URL`: Your Discord webhook URL (required)
- `NVD_API_KEY`: Your free NVD API key (strongly recommended - 10x faster)

### Workflow Configuration

The bot runs automatically on GitHub Actions:
- **Schedule**: Every hour (configurable in `.github/workflows/kev-monitor.yml`)
- **Manual**: Can be triggered manually with custom time windows
- **On Push**: Runs on code changes for testing

To modify the schedule, edit the cron expression in `.github/workflows/kev-monitor.yml`:
```yaml
schedule:
  - cron: '0 * * * *'  # Every hour
```

## Development

### Project Structure

```
security-discord-cisa-kev-bot/
├── src/
│   ├── __init__.py
│   ├── main.py              # Entry point and orchestration
│   ├── config.py            # Configuration management
│   ├── models.py            # Data models (Pydantic)
│   ├── kev_monitor.py       # KEV catalog fetching
│   ├── nvd_enricher.py      # NVD API integration
│   └── discord_notifier.py  # Discord webhook posting
├── tests/
│   ├── test_config.py
│   └── test_models.py
├── .github/workflows/
│   ├── kev-monitor.yml      # Main monitoring workflow
│   └── test.yml             # CI/CD tests
├── requirements.txt
├── pyproject.toml
└── .env.example
```

### Running Tests

```bash
# Run all tests with coverage
pytest --cov=src

# Run linting
ruff check src/

# Run type checking
mypy src/

# Format code
black src/
```

### Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt

# Run with debug logging
python -m src.main --verbose

# Test Discord webhook
python -m src.main --test

# Check custom time window
KEV_CHECK_HOURS=48 python -m src.main
```

## Security Considerations

- **No Hardcoded Secrets**: All sensitive data is loaded from environment variables
- **Input Validation**: Pydantic models validate all external data
- **Rate Limiting**: Respects NVD API rate limits to avoid blocking
- **Error Handling**: Graceful degradation if NVD enrichment fails
- **Secure Defaults**: Conservative timeout and rate limit settings
- **Type Safety**: Full type hints with mypy strict checking

## Discord Message Format

Each vulnerability is displayed as a rich embed containing:

- **CVE ID and Name**: Clear identification
- **Description**: Detailed explanation from NVD (or KEV if unavailable)
- **Product**: Affected vendor and product
- **CVSS Score**: Severity rating with color coding
- **Ransomware Alert**: Special indicator if used in ransomware campaigns
- **Required Action**: CISA's recommended remediation
- **Due Date**: CISA's remediation deadline
- **CWE Classification**: Weakness types
- **References**: Links to CISA KEV, NVD, and additional resources

### Color Coding

- 🔴 Dark Red: Ransomware-related vulnerabilities
- 🔴 Crimson: Critical (CVSS 9.0+)
- 🟠 Orange Red: High (CVSS 7.0-8.9)
- 🟡 Orange: Medium (CVSS 4.0-6.9)
- 🟢 Gold: Low (CVSS < 4.0)
- 🔵 Blue: Informational/Testing

## Rate Limits and Retry Logic

### NVD API
- **Without API Key**: 5 requests per 30 seconds (bot uses 6-second delay)
- **With Free API Key**: 50 requests per 30 seconds (bot uses 0.6-second delay) - **10x faster!**

### Exponential Backoff Retry
The bot automatically retries failed requests with exponential backoff:
- **Rate Limiting (429)**: Backs off exponentially (6s, 12s, 24s) up to 3 retries
- **Server Errors (500-504)**: Retries with 2s, 4s, 8s delays
- **Timeouts**: Retries with progressive delays
- Graceful degradation: Continues with remaining CVEs if one fails

### Discord Webhooks
- Rate limits vary but are generally permissive
- Bot batches up to 10 embeds per message to optimize

## Troubleshooting

### "Failed to load configuration"
- Ensure `.env` file exists with `DISCORD_WEBHOOK_URL`
- Verify the webhook URL format is correct

### "NVD API access forbidden"
- Check if your `NVD_API_KEY` is valid
- Ensure rate limiting delay is appropriate

### "Failed to send Discord notification"
- Verify webhook URL is still valid
- Check Discord server permissions
- Ensure webhook channel still exists

### No vulnerabilities found
- This is normal if no new KEV entries in the last 24 hours
- Try increasing `KEV_CHECK_HOURS` for testing

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass (`pytest`)
5. Run linting (`ruff check src/`)
6. Submit a pull request

## Acknowledgments

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [Discord Webhooks](https://discord.com/developers/docs/resources/webhook)
