# in percent
.DEFAULT_GOAL := all

.PHONY: all
all: static-analysis test  ## Run all validations

.PHONY: static-analysis
static-analysis: lint  ## Run all static analyses

.PHONY: test
test: unit  ## Run all tests


## Bootstrapping targets #################################

.PHONY: bootstrap
bootstrap:  ## Install all dependencies
	$(call title,Bootstrapping dependencies)
	uv sync --all-extras --dev


## Static analysis targets #################################

.PHONY: lint
lint:  ## Show linting issues (ruff)
	uv run ruff format --check
	uv run ruff check .

.PHONY: lint-fix
lint-fix:  format ## Fix linting issues (ruff)
	uv run ruff check . --fix

.PHONY: format
format:   ## Format (ruff)
	uv run ruff format


## Testing targets #################################

.PHONY: unit
unit:  ## Run unit tests
	uv run pytest --cov=grype_db_manager  --cov-report=html  -vv tests/unit/

.PHONY: cli
cli:  ## Run cli tests
	cd tests/cli && uv run make


## DB Testing targets #################################

.PHONY: db-acceptance
db-acceptance:  ## Run DB acceptance tests
	@ echo "Building and testing DB schema=$(schema_version)"
	if [ -z "$(schema_version)" ]; then \
		echo "schema_version is not set"; \
		exit 1; \
	fi

	export DB_ID=$(shell uv run grype-db-manager db build --schema-version $(schema_version))
	uv run grype-db-manager db validaate $(DB_ID)


## Halp! #################################

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
