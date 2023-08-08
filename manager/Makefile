# in percent
COVERAGE_THRESHOLD := 40

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
	pytest --cov-fail-under=$(COVERAGE_THRESHOLD) --config-file ../pyproject.toml --cov-report html --cov grype_db_manager -v tests/unit/

