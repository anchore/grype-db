BIN = grype-db
SOURCE_REPO_URL = https://github.com/anchore/grype-db

TEMP_DIR = ./.tmp
RESULTS_DIR = $(TEMP_DIR)/results
COVER_REPORT = $(RESULTS_DIR)/cover.report
COVER_TOTAL = $(RESULTS_DIR)/cover.total
LICENSES_REPORT = $(RESULTS_DIR)/licenses.json

LINT_CMD = $(TEMP_DIR)/golangci-lint run --config .golangci.yaml

DB_ARCHIVE = ./grype-db-cache.tar.gz
GRYPE_DB = go run ./cmd/$(BIN)/main.go
GRYPE_DB_DATA_IMAGE_NAME = ghcr.io/anchore/$(BIN)/data
date = $(shell date +"%y-%m-%d")

BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

# the quality gate lower threshold for unit test total % coverage (by function statements)
COVERAGE_THRESHOLD := 55
RELEASE_CMD=$(TEMP_DIR)/goreleaser release --rm-dist
SNAPSHOT_CMD=$(RELEASE_CMD) --skip-publish --snapshot
DISTDIR=./dist
SNAPSHOTDIR=./snapshot

GOLANGCILINT_VERSION = v1.51.1
BOUNCER_VERSION = v0.4.0
CHRONICLE_VERSION = v0.6.0
GORELEASER_VERSION = v1.13.0
CRANE_VERSION=v0.12.1

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

ifndef DISTDIR
	$(error DISTDIR is not set)
endif

ifndef SNAPSHOTDIR
	$(error SNAPSHOTDIR is not set)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

.PHONY: all
all: static-analysis test ## Run all checks (linting, license checks, unit, and acceptance tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: test
test: unit ## Run all tests (unit & acceptance tests)

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

.PHONY: ci-bootstrap
ci-bootstrap: bootstrap ci-build-libs
	sudo apt install -y bc

.PHONY: ci-build-libs
ci-build-libs:
	sudo DEBIAN_FRONTEND=noninteractive apt-get update
	sudo DEBIAN_FRONTEND=noninteractive apt-get -yq install -y sqlite3 libsqlite3-dev

.PHONY: bootstrap
bootstrap: ## Download and install all project dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Downloading dependencies)
	# prep temp dirs
	mkdir -p $(TEMP_DIR)
	mkdir -p $(RESULTS_DIR)
	# install go dependencies
	go mod download
	# install utilities
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMP_DIR)/ $(GOLANGCILINT_VERSION)
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMP_DIR)/ $(BOUNCER_VERSION)
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMP_DIR)/ $(CHRONICLE_VERSION)
	.github/scripts/goreleaser-install.sh -b $(TEMP_DIR)/ $(GORELEASER_VERSION)
	GOBIN="$(abspath $(TEMP_DIR))" go install github.com/google/go-containerregistry/cmd/crane@$(CRANE_VERSION)


.PHONY: static-analysis
static-analysis: lint check-licenses

.PHONY: lint
lint: ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINT_CMD)

.PHONY: lint-fix
lint-fix: ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(LINT_CMD) --fix
	go mod tidy

.PHONY: check-licenses
check-licenses:
	$(TEMP_DIR)/bouncer check ./cmd/$(BIN)

.PHONY: unit
unit: unit-go unit-python ## Run go and python unit tests

.PHONY: unit-python
unit-python: ## Run python unit tests
	$(call title,Running Python unit tests)
	cd publish && poetry install && poetry run pytest -v tests

.PHONY: unit-go
unit-go: ## Run GO unit tests (with coverage)
	$(call title,Running Go unit tests)
	go test -coverprofile $(COVER_REPORT) ./...
	@go tool cover -func $(COVER_REPORT) | grep total |  awk '{print substr($$3, 1, length($$3)-1)}' > $(COVER_TOTAL)
	@echo "Coverage: $$(cat $(COVER_TOTAL))"
	@if [ $$(echo "$$(cat $(COVER_TOTAL)) >= $(COVERAGE_THRESHOLD)" | bc -l) -ne 1 ]; then echo "$(RED)$(BOLD)Failed coverage quality gate (> $(COVERAGE_THRESHOLD)%)$(RESET)" && false; fi

.PHONY: acceptance
acceptance: ## Run acceptance tests (for local use, not CI)
	$(call title,"Running local acceptance tests (this takes a while... 45 minutes or so)")
	cd test/acceptance && poetry run python ./grype-ingest.py test-all

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

CHANGELOG.md:
	$(TEMP_DIR)/chronicle -vv > CHANGELOG.md

.PHONY: build
build: $(SNAPSHOTDIR) ## Build release snapshot binaries and packages

$(SNAPSHOTDIR): ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOTDIR)" > $(TEMP_DIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMP_DIR)/goreleaser.yaml

	# build release snapshots
	$(SNAPSHOT_CMD) --config $(TEMP_DIR)/goreleaser.yaml

.PHONY: show-providers
show-providers:
	@# this is used in CI to generate a job matrix, pulling data for each provider concurrently
	@cat .grype-db.yaml | python -c 'import yaml; import json; import sys; print(json.dumps([x["name"] for x in yaml.safe_load(sys.stdin).get("provider",{}).get("configs",[])]));'

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
	$(GRYPE_DB) cache backup -v --path $(DB_ARCHIVE) -p $(provider)
	oras push -v $(GRYPE_DB_DATA_IMAGE_NAME)/$(provider):$(date) $(DB_ARCHIVE) --annotation org.opencontainers.image.source=$(SOURCE_REPO_URL)
	$(TEMP_DIR)/crane tag $(GRYPE_DB_DATA_IMAGE_NAME)/$(provider):$(date) latest

.PHONY: aggregate-all-provider-cache
aggregate-all-provider-cache:
	$(call title,Aggregating all of todays provider data cache)
	.github/scripts/aggregate-all-provider-cache.py

.PHONY: ci-check
ci-check:
	@.github/scripts/ci-check.sh

.PHONY: upload-all-provider-cache
upload-all-provider-cache: ci-check
	$(call title,Uploading existing provider data cache)

	@rm -f $(DB_ARCHIVE)
	$(GRYPE_DB) cache backup -v --path $(DB_ARCHIVE)
	oras push -v $(GRYPE_DB_DATA_IMAGE_NAME):$(date) $(DB_ARCHIVE) --annotation org.opencontainers.image.source=$(SOURCE_REPO_URL)
	$(TEMP_DIR)/crane tag $(GRYPE_DB_DATA_IMAGE_NAME):$(date) latest


.PHONY: download-all-provider-cache
download-all-provider-cache:
	$(call title,Downloading and restoring all of todays provider data cache)
	@rm -f $(DB_ARCHIVE)
	@bash -c "oras pull $(GRYPE_DB_DATA_IMAGE_NAME):$(date) && $(GRYPE_DB) cache restore --path $(DB_ARCHIVE) || (echo 'no data cache found for today' && exit 1)"


.PHONY: changelog
changelog: clean-changelog CHANGELOG.md
	@docker run -it --rm \
		-v $(shell pwd)/CHANGELOG.md:/CHANGELOG.md \
		rawkode/mdv \
			-t 748.5989 \
			/CHANGELOG.md

# TODO uncomment changelog capabilities after chronicle supports annotated tags: https://github.com/anchore/chronicle/issues/35
.PHONY: release
release: clean-dist # CHANGELOG.md  ## Build and publish final binaries and packages. Intended to be run only on macOS.
	$(call title,Publishing release artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(DISTDIR)" > $(TEMP_DIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMP_DIR)/goreleaser.yaml

	bash -c "$(RELEASE_CMD) \
		--config $(TEMP_DIR)/goreleaser.yaml"
#		--release-notes <(cat CHANGELOG.md)"

.PHONY: clear-test-cache
clear-test-cache: ## Delete all test cache (built docker image tars)
	find . -type f -wholename "**/test-fixtures/tar-cache/*.tar" -delete

.PHONY: clean-db
clean-db:
	rm -rf build/
	rm -f metadata.json listing.json vulnerability-db*.tar.gz vulnerability.db

.PHONY: clean-changelog
clean-changelog:
	rm -f CHANGELOG.md

.PHONY: clean-dist
clean-dist: clean-changelog
	$(call safe_rm_rf,$(DISTDIR))
	rm -f $(TEMP_DIR)/goreleaser.yaml

.PHONY: clean
clean: clean-dist clean-snapshot  ## Remove previous builds and result reports
	$(call safe_rm_rf_children,$(RESULTS_DIR))

.PHONY: clean-snapshot
clean-snapshot:
	$(call safe_rm_rf,$(SNAPSHOTDIR))
	rm -f $(TEMP_DIR)/goreleaser.yaml

