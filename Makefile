.PHONY: help test lint syntax replay dashboard visualize run-safe run-rollout build-all clean-cache

ENV ?= env-api-gateway-auth
MODEL ?= openai/gpt-6.1-sol

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

test: ## Run AgentTripwire unit tests
	pytest -v

lint: ## Run Ruff linter across src, tests, environments, and scripts
	ruff check src/ tests/ environments/ scripts/

syntax: ## Verify Python syntax across all modules
	find src tests environments scripts -name "*.py" -exec python -m py_compile {} +

replay: ## Replay recorded frontier rollout trajectory for ENV
	python -m tripwire replay $(ENV)

dashboard: ## Generate standalone interactive HTML security dashboard
	python -m tripwire dashboard --output docs/dashboard.html

visualize: ## Generate CLI scorecard table from results/
	python scripts/visualize_results.py

run-safe: ## Verify safe reference oracle for ENV
	python -m tripwire run $(ENV) --mode safe

run-rollout: ## Run autonomous model evaluation for ENV using MODEL
	python -m tripwire run $(ENV) --mode agent --model $(MODEL)

build-all: ## Build Docker images for all five sandbox environments
	@for dir in environments/env-*; do \
		name=$$(basename $$dir); \
		echo "Building agent-tripwire/$$name..."; \
		docker build -t agent-tripwire/$$name $$dir/environment; \
	done

clean-cache: ## Remove __pycache__ and .pyc artifacts
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
