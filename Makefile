.PHONY: help lint syntax test-oracles visualize clean-cache build-all

ENV ?= env-api-gateway-auth
MODEL ?= openai/gpt-6.1-sol

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

lint: ## Run Ruff linter across environments and scripts
	ruff check environments/ scripts/

syntax: ## Verify Python syntax across all modules
	find environments scripts -name "*.py" -exec python -m py_compile {} +

visualize: ## Generate benchmark summary table and charts from results/
	python scripts/visualize_results.py

run-safe: ## Verify safe reference oracle for ENV (default: env-api-gateway-auth)
	harbor run -p environments -i $(ENV) -a oracle -k 1 -o jobs/safe-$(ENV) --yes

run-rollout: ## Run autonomous model evaluation for ENV using MODEL
	harbor run -p environments -i $(ENV) -a terminus-2 -m $(MODEL) --ak reasoning_effort=high -k 1 -o jobs/rollout-$(ENV) --yes

build-all: ## Build Docker images for all five benchmark environments
	@for dir in environments/env-*; do \
		name=$$(basename $$dir); \
		echo "Building tripwire/$$name..."; \
		docker build -t tripwire/$$name $$dir/environment; \
	done

clean-cache: ## Remove __pycache__ and .pyc artifacts
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
