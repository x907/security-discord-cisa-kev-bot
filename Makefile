.PHONY: help install test lint format type-check run test-webhook clean

help:
	@echo "CISA KEV Discord Bot - Development Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  install       Install dependencies"
	@echo "  test          Run tests with coverage"
	@echo "  lint          Run linting checks"
	@echo "  format        Format code with black"
	@echo "  type-check    Run type checking with mypy"
	@echo "  run           Run the KEV monitor"
	@echo "  test-webhook  Test Discord webhook configuration"
	@echo "  clean         Clean cache and temp files"
	@echo "  all           Run format, lint, type-check, and test"

install:
	pip install -r requirements.txt

test:
	pytest --cov=src --cov-report=term-missing --cov-report=html

lint:
	ruff check src/ tests/

format:
	black src/ tests/

type-check:
	mypy src/

run:
	python -m src.main

test-webhook:
	python -m src.main --test

clean:
	rm -rf __pycache__ .pytest_cache .mypy_cache .coverage htmlcov
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

all: format lint type-check test
	@echo "✅ All checks passed!"
