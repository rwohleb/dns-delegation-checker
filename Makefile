.PHONY: help install test test-unit test-integration test-coverage clean lint format

help: ## Show this help message
	@echo "DNS Delegation Checker - Available commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	pip3 install -r requirements.txt

test: ## Run all tests
	python3 -m pytest

test-unit: ## Run unit tests only
	python3 -m pytest -m "not integration"

test-integration: ## Run integration tests only
	python3 -m pytest -m integration

test-coverage: ## Run tests with coverage report
	python3 -m pytest --cov=dns_delegation_checker --cov-report=html --cov-report=term-missing

test-fast: ## Run tests quickly (no coverage, no integration)
	python3 -m pytest -m "not integration" --tb=short -q

clean: ## Clean up generated files
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf __pycache__/
	rm -rf tests/__pycache__/
	rm -rf *.pyc
	rm -rf tests/*.pyc
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

lint: ## Run linting checks
	flake8 dns_delegation_checker.py tests/
	pylint dns_delegation_checker.py tests/ || true

format: ## Format code with black
	black dns_delegation_checker.py tests/

check: ## Run all checks (lint, test, coverage)
	$(MAKE) lint
	$(MAKE) test-coverage

demo: ## Run a demo with example domains
	python3 dns_delegation_checker.py google.com
	python3 dns_delegation_checker.py example.com
	python3 dns_delegation_checker.py mail.google.com --explain

install-dev: ## Install development dependencies
	pip3 install -r requirements.txt
	pip3 install flake8 black pylint

setup: install-dev ## Set up development environment
	$(MAKE) clean
	$(MAKE) test 