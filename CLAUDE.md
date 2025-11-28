# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a professional Python security monitoring bot that tracks the CISA Known Exploited Vulnerabilities (KEV) catalog and posts notifications to Discord. The bot enriches KEV data with information from the National Vulnerability Database (NVD) API.

## Development Commands

### Running the Application

```bash
# Standard run (checks last 24 hours)
python -m src.main

# Check last 7 days (useful for initial run or testing)
python -m src.main --days 7

# Force posting all found CVEs (bypass deduplication)
python -m src.main --days 7 --force

# Test Discord webhook
python -m src.main --test

# Debug mode with verbose logging
python -m src.main --verbose

# Custom time window via environment variable
KEV_CHECK_HOURS=48 python -m src.main
```

### Testing

```bash
# Run all tests with coverage
pytest --cov=src --cov-report=term-missing

# Run specific test file
pytest tests/test_models.py

# Run with verbose output
pytest -v
```

### Code Quality

```bash
# Linting (includes security checks via bandit)
ruff check src/

# Auto-fix linting issues
ruff check --fix src/

# Type checking
mypy src/

# Code formatting
black src/

# Check formatting without modifying
black --check src/
```

### Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install all dependencies including dev tools
pip install -r requirements.txt
```

## Architecture

### Core Components

The application follows a modular, security-first architecture with clear separation of concerns:

1. **src/config.py**: Configuration management using Pydantic Settings
   - All settings loaded from environment variables
   - Validation ensures security constraints (e.g., rate limits)
   - No hardcoded secrets or credentials

2. **src/models.py**: Type-safe data models using Pydantic
   - `KEVEntry`: CISA KEV catalog entry with date parsing and validation
   - `NVDCVEData`: NVD API response with CVSS metrics and descriptions
   - `EnrichedKEV`: Combined KEV + NVD data for notifications

3. **src/kev_monitor.py**: KEV catalog fetching and filtering
   - Fetches raw JSON from GitHub (CISA's official source)
   - Filters entries by date (default: last 24 hours)
   - Handles timezone-aware datetime comparisons

4. **src/nvd_enricher.py**: NVD API integration with rate limiting and retry logic
   - Respects NVD rate limits: 5 req/30s (public) or 50 req/30s (with free API key)
   - **Exponential backoff retry**: Automatically retries on 429, 500-504, and timeouts
   - Retry strategy: Up to 3 attempts with exponential backoff (2s, 4s, 8s for errors)
   - Parses CVSS v3.1, v3.0, and v2.0 metrics
   - Extracts CWE classifications and references
   - Graceful degradation: returns None on errors, doesn't crash

5. **src/discord_notifier.py**: Discord webhook posting with rich embeds
   - Creates formatted embeds with color coding by severity
   - Batches up to 10 embeds per message (Discord limit)
   - Special highlighting for ransomware-related CVEs

6. **src/state_manager.py**: State management for deduplication
   - Tracks posted CVEs in `state/posted_cves.json`
   - Prevents duplicate notifications
   - Automatic cleanup of old entries (90 days)
   - Atomic file writes for data integrity

7. **src/main.py**: Orchestration and entry point
   - Context managers ensure proper resource cleanup
   - Structured logging with configurable verbosity
   - CLI argument parsing for --test, --days, --force, --verbose
   - Deduplication logic to filter already-posted CVEs

### Data Flow

```
KEVMonitor → fetch KEV JSON → filter by date → KEV entries
    ↓
StateManager → check for duplicates → filter new CVEs
    ↓
NVDEnricher → enrich each CVE → rate-limited API calls → Enriched KEVs
    ↓
DiscordNotifier → format embeds → batch messages → post to Discord
    ↓
StateManager → mark as posted → update state file
```

### Security Architecture

The codebase is designed with "left-to-right thinking" security principles:

1. **Input Validation**: All external data validated via Pydantic models before processing
2. **Type Safety**: Full type hints with mypy strict mode enforcement
3. **Rate Limiting**: Built-in protection against API abuse
4. **Error Handling**: Try-except blocks with specific exception types
5. **Resource Management**: Context managers for HTTP sessions
6. **No Secret Leakage**: Secrets only in environment variables, never logged
7. **Minimal Permissions**: GitHub Actions uses `permissions: contents: read`
8. **Deduplication**: State tracking prevents duplicate posts
9. **Atomic Writes**: State file updates use temp file + rename for atomicity

### Configuration Validation

The `Settings` class in `src/config.py` enforces security constraints:

- Discord webhook URL must be valid HTTPS URL
- NVD rate limiting validated based on API key presence:
  - Without key: minimum 6.0 seconds between requests
  - With key: minimum 0.6 seconds between requests
- Numeric bounds on check hours (1-720) and embeds (1-10)

## GitHub Actions

### Workflows

1. **kev-monitor.yml**: Main monitoring workflow
   - Runs hourly via cron: `0 * * * *`
   - Can be manually triggered with custom time windows
   - Uses repository secrets for sensitive data
   - 15-minute timeout to prevent runaway jobs

2. **test.yml**: CI/CD testing
   - Runs on PRs and pushes to main
   - Linting (ruff), formatting (black), and type checking (mypy)
   - Unit tests with coverage reporting

### Required Repository Secrets

Set in: Settings → Secrets and variables → Actions

- `DISCORD_WEBHOOK_URL` (required): Discord webhook URL
- `NVD_API_KEY` (strongly recommended): Free NVD API key for 10x faster rate limits
  - Get free API key at: https://nvd.nist.gov/developers/request-an-api-key
  - Without key: 5 requests/30s (slow, may timeout on large batches)
  - With key: 50 requests/30s (10x faster)

## Important Notes for Development

### When Adding New Features

1. **Always add type hints**: This project uses strict mypy checking
2. **Validate external data**: Use Pydantic models for all external inputs
3. **Handle errors gracefully**: Don't let one failure crash the entire workflow
4. **Add tests**: Maintain test coverage for new functionality
5. **Update documentation**: Keep README.md and this file in sync

### Security Considerations

- **Never log secrets**: Be careful not to log webhook URLs, API keys, or sensitive data
- **Validate URLs**: Ensure URLs are properly validated before making requests
- **Rate limit external APIs**: Always respect third-party rate limits
- **Input sanitization**: Validate all user-controllable inputs (even from config)
- **Dependency updates**: Keep dependencies updated for security patches

### Common Patterns

#### Adding a new API integration

1. Create a new module in `src/` (e.g., `src/new_api.py`)
2. Define Pydantic models for responses in `src/models.py`
3. Add configuration in `src/config.py` with validation
4. Implement rate limiting using `time.sleep()` and tracking `last_request_time`
5. Use `requests.Session()` with context manager for connection pooling
6. Return `None` on non-critical errors, raise exceptions for critical failures

#### Adding new Discord embed fields

1. Modify `_create_embed()` in `src/discord_notifier.py`
2. Keep field names concise (with emoji prefixes for visual appeal)
3. Use `inline: True` for short values, `False` for long ones
4. Test with different data scenarios (missing data, long strings, etc.)

#### Adding new configuration options

1. Add field to `Settings` class in `src/config.py`
2. Include `Field()` with description and validation constraints
3. Add to `.env.example` with helpful comments
4. Document in README.md under Configuration section
5. Add test in `tests/test_config.py`

## Testing Notes

### Test Data Location

Test fixtures use minimal realistic data inline. For larger test data:
- Mock HTTP responses using `pytest` fixtures
- Don't commit real API keys or webhook URLs to tests

### Running Specific Tests

```bash
# Test configuration validation
pytest tests/test_config.py -v

# Test data models
pytest tests/test_models.py -v

# Test with coverage for specific module
pytest --cov=src.kev_monitor tests/
```

## Debugging

### Enable Debug Logging

Set logging to DEBUG in `src/main.py` or run with `--verbose`:

```bash
python -m src.main --verbose
```

### Common Issues

1. **Rate limiting errors**: NVD returns 403
   - Check if `NVD_REQUEST_DELAY_SECONDS` is appropriate for your API key status
   - Verify API key is set correctly if you have one

2. **Discord webhook fails**:
   - Test webhook with `--test` flag first
   - Verify webhook URL is still valid (Discord webhooks can be deleted)
   - Check webhook channel permissions

3. **No vulnerabilities found**:
   - This is normal if no new KEV entries in the time window
   - Try increasing `KEV_CHECK_HOURS` for testing purposes

4. **Timezone issues**:
   - All dates are normalized to UTC in `src/models.py`
   - KEV dates are parsed as midnight UTC

## Dependencies

### Core Dependencies

- **requests**: HTTP client for API calls
- **pydantic**: Data validation and settings management
- **python-dotenv**: Load environment variables from `.env`

### Dev Dependencies

- **pytest**: Testing framework
- **pytest-cov**: Coverage reporting
- **ruff**: Fast Python linter (includes security checks)
- **black**: Code formatter
- **mypy**: Static type checker

### Updating Dependencies

```bash
# Update all dependencies
pip install --upgrade -r requirements.txt

# Test after updates
pytest
ruff check src/
mypy src/
```

## Python Version

This project requires **Python 3.11+** for:
- Modern type hints (`str | None` instead of `Optional[str]`)
- Performance improvements
- Security updates

Do not downgrade to Python 3.10 or earlier without refactoring type hints.
