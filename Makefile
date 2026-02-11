BIN = grype-db
OWNER = anchore

SOURCE_REPO_URL = https://github.com/anchore/grype-db
TEMP_DIR = ./.tmp
TOOL_DIR = .tool
RESULTS_DIR = $(TEMP_DIR)/results

DB_ARCHIVE = ./grype-db-cache.tar.gz
GRYPE_DB = go run ./cmd/$(BIN)/main.go -c config/grype-db/publish-nightly-r2.yaml
GRYPE_DB_DATA_IMAGE_NAME = ghcr.io/anchore/$(BIN)/data
date = $(shell date -u +"%y-%m-%d")

# Command templates #################################
BINNY = $(TOOL_DIR)/binny
LINT_CMD = $(TOOL_DIR)/golangci-lint run --config .golangci.yaml
GOIMPORTS_CMD := $(TOOL_DIR)/gosimports -local github.com/anchore
RELEASE_CMD = $(TOOL_DIR)/goreleaser release --clean
SNAPSHOT_CMD = $(RELEASE_CMD) --skip=publish --snapshot
CHRONICLE_CMD = $(TOOL_DIR)/chronicle
GLOW_CMD = $(TOOL_DIR)/glow
ORAS = $(TOOL_DIR)/oras
ORAS_FLAGS = $(if $(filter true,$(CI)),--no-tty,)
BOUNCER = $(TOOL_DIR)/bouncer
CRANE = $(TOOL_DIR)/crane

# Formatting variables #################################
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

# Test variables #################################
DIST_DIR=./dist
CHANGELOG := CHANGELOG.md
SNAPSHOT_DIR=./snapshot
OS := $(shell uname | tr '[:upper:]' '[:lower:]')
SNAPSHOT_BIN := $(abspath $(shell pwd)/$(SNAPSHOT_DIR)/$(OS)-build_$(OS)_amd64_v1/$(BIN))


define safe_rm_rf
	bash -c 'test -z "$(1)" && false || rm -rf $(1)'
endef

define safe_rm_rf_children
	bash -c 'test -z "$(1)" && false || rm -rf $(1)/*'
endef

ifeq "$(strip $(VERSION))" ""
 override VERSION = $(shell git describe --always --tags --dirty)
endif

## Variable assertions

ifndef TEMP_DIR
	$(error TEMP_DIR is not set)
endif

ifndef RESULTS_DIR
	$(error RESULTS_DIR is not set)
endif

ifndef DIST_DIR
	$(error DIST_DIR is not set)
endif

ifndef SNAPSHOT_DIR
	$(error SNAPSHOT_DIR is not set)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

.DEFAULT_GOAL := all

.PHONY: all
all: static-analysis test ## Run all checks (linting, license checks, unit, and acceptance tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: static-analysis  ## Run all static analysis checks (linting and license checks)
static-analysis: check-go-mod-tidy lint check-licenses
	cd manager && uv run make static-analysis

.PHONY: test
test: unit cli ## Run all tests
	cd manager && uv run make test


## Bootstrapping targets #################################

.PHONY: bootstrap
bootstrap: $(TEMP_DIR) bootstrap-go bootstrap-tools bootstrap-python  ## Download and install all tooling dependencies (+ prep tooling in the ./tmp dir)

.PHONY: bootstrap-python
bootstrap-python:
	cd manager && make bootstrap

# note: we need to assume that binny and task have not already been installed
$(BINNY):
	@mkdir -p $(TOOL_DIR)
	@curl -sSfL https://raw.githubusercontent.com/$(OWNER)/binny/main/install.sh | sh -s -- -b $(TOOL_DIR)

.PHONY: bootstrap-tools
bootstrap-tools: $(BINNY)
	$(BINNY) install

.PHONY: bootstrap-go
bootstrap-go:
	go mod download

$(TEMP_DIR):
	mkdir -p $(TEMP_DIR)

.PHONY: update-tools
update-tools: $(BINNY)  ## Update all tools
	$(BINNY) update -v

.PHONY: list-tools
list-tools: $(BINNY)  ## List all tools used
	$(BINNY) list

.PHONY: list-tool-updates
list-tool-updates: $(BINNY)  ## List all tools with available updates
	$(BINNY) list --updates

## Static analysis targets #################################

.PHONY: lint
lint:  ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINT_CMD)
	@[ -z "$(shell $(GOIMPORTS_CMD) -d .)" ] || (echo "goimports needs to be fixed" && false)

.PHONY: format
format: ## Auto-format all source code
	$(call title,Running formatters)
	gofmt -w -s .
	$(GOIMPORTS_CMD) -w .
	go mod tidy

.PHONY: lint-fix
lint-fix: format  ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	$(LINT_CMD) --fix

check-go-mod-tidy:
	@ .github/scripts/go-mod-tidy-check.sh && echo "go.mod and go.sum are tidy!"

.PHONY: check-licenses
check-licenses:
	$(BOUNCER) check ./cmd/$(BIN)


## Testing targets #################################

.PHONY: unit
unit: $(TEMP_DIR) ## Run Go unit tests
	$(call title,Running Go unit tests)
	go test $(shell go list ./... | grep -v anchore/grype-db/test)

.PHONY: unit-python
unit-python: ## Run Python unit tests
	$(call title,Running Python unit tests)
	cd manager && make unit

.PHONY: db-acceptance
db-acceptance: ## Run acceptance tests
	$(call title,"Running DB acceptance tests (schema=$(schema))")
	uv run ./test/db/acceptance.sh $(schema)

.PHONY: cli
cli: cli-go cli-python ## Run all CLI tests

.PHONY: cli-python
cli-python:  ## Run python CLI tests
	cd manager && uv run make cli

.PHONY: cli-go
cli-go: $(SNAPSHOT_DIR)  ## Run go CLI tests
	chmod 755 "$(SNAPSHOT_BIN)"
	$(SNAPSHOT_BIN) version
	GRYPE_DB_BINARY_LOCATION='$(SNAPSHOT_BIN)' \
		go test -count=1 -timeout=15m -v ./test/cli


## Data management targets #################################

.PHONY: show-providers
show-providers:
	@# this is used in CI to generate a job matrix, pulling data for each provider concurrently
	@$(GRYPE_DB) list-providers -q -o json

.PHONY: ci-oras-ghcr-login
ci-oras-ghcr-login:
	@[ -n "$(GITHUB_USERNAME)" ] || (echo "Error: GITHUB_USERNAME environment variable is not set" && exit 1)
	@[ -n "$(GITHUB_TOKEN)" ] || (echo "Error: GITHUB_TOKEN environment variable is not set" && exit 1)
	echo $(GITHUB_TOKEN) | $(ORAS) login ghcr.io --username $(GITHUB_USERNAME) --password-stdin

.PHONY: download-provider-cache
download-provider-cache:
	$(call title,Downloading and restoring "$(provider)" provider data cache ($(date)))
	@bash -c "$(ORAS) pull $(ORAS_FLAGS) $(GRYPE_DB_DATA_IMAGE_NAME)/$(provider):$(date) || (echo 'no data cache found for $(date)' && exit 1)"
	$(GRYPE_DB) cache restore --path .cache/vunnel/$(provider)/grype-db-cache.tar.gz
	@rm -rf .cache/vunnel/$(provider)

.PHONY: refresh-provider-cache
refresh-provider-cache:
	$(call title,Refreshing "$(provider)" provider data cache)
	$(GRYPE_DB) pull -v -p $(provider)

.PHONY: upload-provider-cache
upload-provider-cache: ci-check
	$(call title,Uploading "$(provider)" existing provider data cache)

	@mkdir -p .cache/vunnel/$(provider)
	@rm -f .cache/vunnel/$(provider)/grype-db-cache.tar.gz
	$(GRYPE_DB) cache status -p $(provider)
	$(GRYPE_DB) cache backup -v --path .cache/vunnel/$(provider)/grype-db-cache.tar.gz -p $(provider)
	$(ORAS) push $(ORAS_FLAGS) -v $(GRYPE_DB_DATA_IMAGE_NAME)/$(provider):$(date) .cache/vunnel/$(provider)/grype-db-cache.tar.gz --annotation org.opencontainers.image.source=$(SOURCE_REPO_URL)
	$(CRANE) tag $(GRYPE_DB_DATA_IMAGE_NAME)/$(provider):$(date) latest
	@rm -rf .cache/vunnel/$(provider)

.PHONY: download-all-provider-cache
download-all-provider-cache:
	$(call title,Downloading and restoring all provider data caches)
	.github/scripts/aggregate-all-provider-cache.py


## Code and data generation targets #################################

.PHONY: generate-processor-code
generate-processor-code:
	go generate ./pkg/process
	make format

## Build-related targets #################################

.PHONY: build
build: $(SNAPSHOT_DIR) ## Build release snapshot binaries and packages

$(SNAPSHOT_DIR): $(TEMP_DIR)  ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOT_DIR)" > $(TEMP_DIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMP_DIR)/goreleaser.yaml

	# build release snapshots
	$(SNAPSHOT_CMD) --config $(TEMP_DIR)/goreleaser.yaml

.PHONY: changelog
changelog: clean-changelog  ## Generate and show the changelog for the current unreleased version
	$(CHRONICLE_CMD) -vvv -n --version-file VERSION > $(CHANGELOG)
	@$(GLOW_CMD) $(CHANGELOG)

$(CHANGELOG):
	$(CHRONICLE_CMD) -vvv > $(CHANGELOG)

.PHONY: release
release:
	@.github/scripts/trigger-release.sh

.PHONY: release
ci-release: ci-check $(TEMP_DIR) clean-dist $(CHANGELOG) ## Build and publish final binaries and packages. Intended to be run only on macOS.
	$(call title,Publishing release artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(DIST_DIR)" > $(TEMP_DIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMP_DIR)/goreleaser.yaml

	bash -c "$(RELEASE_CMD) --config $(TEMP_DIR)/goreleaser.yaml --release-notes <(cat $(CHANGELOG))"

.PHONY: ci-check
ci-check:
	@.github/scripts/ci-check.sh


## Cleanup targets #################################

.PHONY: clean
clean: clean-dist clean-snapshot clean-changelog  ## Remove previous builds and result reports
	$(call safe_rm_rf_children,$(RESULTS_DIR))

.PHONY: clean-changelog
clean-changelog:
	rm -f $(CHANGELOG) VERSION

.PHONY: clear-test-cache
clear-test-cache:
	find . -type f -wholename "**/test-fixtures/tar-cache/*.tar" -delete

.PHONY: clean-db
clean-db:
	rm -rf build/
	rm -f metadata.json listing.json vulnerability-db*.tar.gz vulnerability.db

.PHONY: clean-dist
clean-dist: clean-changelog
	$(call safe_rm_rf,$(DIST_DIR))
	rm -f $(TEMP_DIR)/goreleaser.yaml

.PHONY: clean-snapshot
clean-snapshot:
	$(call safe_rm_rf,$(SNAPSHOT_DIR))
	rm -f $(TEMP_DIR)/goreleaser.yaml


## Halp! #################################

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
