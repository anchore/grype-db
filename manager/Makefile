# in percent
COVERAGE_THRESHOLD := 60

.DEFAULT_GOAL := all

.PHONY: all
all: static-analysis test  ## Run all validations

.PHONY: static-analysis
static-analysis: format lint  ## Run all static analyses

.PHONY: test
test: unit  ## Run all tests

virtual-env-check:
	@ if [ "${VIRTUAL_ENV}" = "" ]; then \
		echo "$(ERROR)Not in a virtual environment. Try running with 'poetry run' or enter a 'poetry shell' session.$(RESET)"; \
		exit 1; \
	fi


## Bootstrapping targets #################################

.PHONY: bootstrap
bootstrap:  ## Install all dependencies
	$(call title,Bootstrapping dependencies)
	poetry install


## Static analysis targets #################################

.PHONY: lint
lint: virtual-env-check  ## Show linting issues (ruff)
	ruff check .

.PHONY: lint-fix
lint-fix: virtual-env-check  ## Fix linting issues (ruff)
	ruff check . --fix

.PHONY: format
format: virtual-env-check  ## Format all code (black)
	black src tests


## Testing targets #################################

.PHONY: unit
unit: virtual-env-check  ## Run unit tests
	pytest --cov-fail-under=$(COVERAGE_THRESHOLD) --config-file ../pyproject.toml --cov-report html --cov grype_db_manager -vv tests/unit/

.PHONY: cli
cli: virtual-env-check  ## Run cli tests
	cd tests/cli && make


## DB Testing targets #################################

.PHONY: db-acceptance
db-acceptance: virtual-env-check  ## Run DB acceptance tests
	@ echo "Building and testing DB schema=$(schema_version)"
	if [ -z "$(schema_version)" ]; then \
		echo "schema_version is not set"; \
		exit 1; \
	fi

	export DB_ID=$(shell grype-db-manager db build --schema-version $(schema_version))
	grype-db-manager db validaate $(DB_ID)


## Halp! #################################

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
