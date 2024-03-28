BIN = grype-db

SOURCE_REPO_URL = https://github.com/anchore/grype-db
TEMP_DIR = ./.tmp
RESULTS_DIR = $(TEMP_DIR)/results

DB_ARCHIVE = ./grype-db-cache.tar.gz
GRYPE_DB = go run ./cmd/$(BIN)/main.go -c config/grype-db/publish-nightly.yaml
GRYPE_DB_DATA_IMAGE_NAME = ghcr.io/anchore/$(BIN)/data
date = $(shell date -u +"%y-%m-%d")

# Command templates #################################
LINT_CMD = $(TEMP_DIR)/golangci-lint run --config .golangci.yaml
GOIMPORTS_CMD := $(TEMP_DIR)/gosimports -local github.com/anchore
RELEASE_CMD := $(TEMP_DIR)/goreleaser release --rm-dist
SNAPSHOT_CMD := $(RELEASE_CMD) --skip-publish --skip-sign --snapshot
CHRONICLE_CMD = $(TEMP_DIR)/chronicle
GLOW_CMD = $(TEMP_DIR)/glow

# Tool versions #################################
GOLANGCILINT_VERSION = v1.57.1
GOSIMPORTS_VERSION := v0.3.8
BOUNCER_VERSION = v0.4.0
CHRONICLE_VERSION = v0.8.0
GORELEASER_VERSION = v1.24.0
CRANE_VERSION=v0.16.1
GLOW_VERSION := v1.5.0

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
# the quality gate lower threshold for unit test total % coverage (by function statements)
COVERAGE_THRESHOLD := 55
RELEASE_CMD=$(TEMP_DIR)/goreleaser release --rm-dist
SNAPSHOT_CMD=$(RELEASE_CMD) --skip-publish --snapshot
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
	cd manager && poetry run make static-analysis

.PHONY: test
test: unit cli ## Run all tests
	cd manager && poetry run make test


## Bootstrapping targets #################################

.PHONY: bootstrap
bootstrap: $(TEMP_DIR) bootstrap-go bootstrap-tools bootstrap-python  ## Download and install all tooling dependencies (+ prep tooling in the ./tmp dir)

.PHONY: bootstrap-python
bootstrap-python:
	cd manager && make bootstrap

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMP_DIR)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMP_DIR)/ $(GOLANGCILINT_VERSION)
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMP_DIR)/ $(BOUNCER_VERSION)
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMP_DIR)/ $(CHRONICLE_VERSION)
	.github/scripts/goreleaser-install.sh -b $(TEMP_DIR)/ $(GORELEASER_VERSION)
	GOBIN="$(abspath $(TEMP_DIR))" go install github.com/google/go-containerregistry/cmd/crane@$(CRANE_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/charmbracelet/glow@$(GLOW_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/rinchsan/gosimports/cmd/gosimports@$(GOSIMPORTS_VERSION)

.PHONY: bootstrap-go
bootstrap-go:
	go mod download

$(TEMP_DIR):
	mkdir -p $(TEMP_DIR)


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
	$(TEMP_DIR)/bouncer check ./cmd/$(BIN)


## Testing targets #################################

.PHONY: unit
unit: ## Run Go unit tests (with coverage)
	$(call title,Running Go unit tests)
	go test -coverprofile $(TEMP_DIR)/unit-coverage-details.txt $(shell go list ./... | grep -v anchore/grype-db/test)
	@.github/scripts/coverage.py $(COVERAGE_THRESHOLD) $(TEMP_DIR)/unit-coverage-details.txt

.PHONY: unit-python
unit-python: ## Run Python unit tests (with coverage)
	$(call title,Running Python unit tests)
	cd manager && poetry run make unit

.PHONY: db-acceptance
db-acceptance: ## Run acceptance tests
	$(call title,"Running DB acceptance tests (schema=$(schema))")
	poetry run ./test/db/acceptance.sh $(schema)

.PHONY: cli
cli: cli-go cli-python ## Run all CLI tests

.PHONY: cli-python
cli-python:  ## Run python CLI tests
	cd manager && poetry run make cli

.PHONY: cli-go
cli-go: $(SNAPSHOT_DIR)  ## Run go CLI tests
	chmod 755 "$(SNAPSHOT_BIN)"
	$(SNAPSHOT_BIN) version
	GRYPE_DB_BINARY_LOCATION='$(SNAPSHOT_BIN)' \
		go test -count=1 -timeout=15m -v ./test/cli


## Test-fixture-related targets #################################

.PHONY: update-test-fixtures
update-test-fixtures:
	docker run \
		--pull always \
		--rm \
		-it \
		anchore/grype:latest \
			-q \
		 	-o json \
		 		centos:8.2.2004 > publish/test-fixtures/centos-8.2.2004.json
	dos2unix publish/test-fixtures/centos-8.2.2004.json
	cd test/acceptance && poetry install && poetry run python grype-ingest.py capture-test-fixtures


## Data management targets #################################

.PHONY: show-providers
show-providers:
	@# this is used in CI to generate a job matrix, pulling data for each provider concurrently
	@$(GRYPE_DB) list-providers -q -o json

.PHONY: download-provider-cache
download-provider-cache:
	$(call title,Downloading and restoring todays "$(provider)" provider data cache)
	@bash -c "oras pull $(GRYPE_DB_DATA_IMAGE_NAME)/$(provider):$(date) && $(GRYPE_DB) cache restore --path $(DB_ARCHIVE) || (echo 'no data cache found for today' && exit 1)"

.PHONY: refresh-provider-cache
refresh-provider-cache:
	$(call title,Refreshing "$(provider)" provider data cache)
	$(GRYPE_DB) pull -v -p $(provider)

.PHONY: upload-provider-cache
upload-provider-cache: ci-check
	$(call title,Uploading "$(provider)" existing provider data cache)

	@rm -f $(DB_ARCHIVE)
	$(GRYPE_DB) cache status -p $(provider)
	$(GRYPE_DB) cache backup -v --path $(DB_ARCHIVE) -p $(provider)
	oras push -v $(GRYPE_DB_DATA_IMAGE_NAME)/$(provider):$(date) $(DB_ARCHIVE) --annotation org.opencontainers.image.source=$(SOURCE_REPO_URL)
	$(TEMP_DIR)/crane tag $(GRYPE_DB_DATA_IMAGE_NAME)/$(provider):$(date) latest

.PHONY: aggregate-all-provider-cache
aggregate-all-provider-cache:
	$(call title,Aggregating all of todays provider data cache)
	.github/scripts/aggregate-all-provider-cache.py

.PHONY: upload-all-provider-cache
upload-all-provider-cache: ci-check
	$(call title,Uploading existing provider data cache)

	@rm -f $(DB_ARCHIVE)
	$(GRYPE_DB) cache status
	$(GRYPE_DB) cache backup -v --path $(DB_ARCHIVE)
	oras push -v $(GRYPE_DB_DATA_IMAGE_NAME):$(date) $(DB_ARCHIVE) --annotation org.opencontainers.image.source=$(SOURCE_REPO_URL)
	$(TEMP_DIR)/crane tag $(GRYPE_DB_DATA_IMAGE_NAME):$(date) latest


.PHONY: download-all-provider-cache
download-all-provider-cache:
	$(call title,Downloading and restoring all of todays provider data cache)
	@rm -f $(DB_ARCHIVE)
	@bash -c "oras pull $(GRYPE_DB_DATA_IMAGE_NAME):$(date) && $(GRYPE_DB) cache restore --path $(DB_ARCHIVE) || (echo 'no data cache found for today' && exit 1)"


## Build-related targets #################################

.PHONY: build
build: $(SNAPSHOT_DIR) ## Build release snapshot binaries and packages

$(SNAPSHOT_DIR): ## Build snapshot release binaries and packages
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
ci-release: ci-check clean-dist $(CHANGELOG) ## Build and publish final binaries and packages. Intended to be run only on macOS.
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
