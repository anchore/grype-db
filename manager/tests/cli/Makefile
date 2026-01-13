ACTIVATE_VENV = . venv/bin/activate &&

# formatting variables
BOLD := $(shell tput -T linux bold))
CYAN := $(shell tput -T linux setaf 6)
RESET := $(shell tput -T linux sgr0)

test:  ## Run CLI tests
	uv run pytest . -vv -o log_cli=true

.PHONY: vunnel-oracle-data
vunnel-oracle-data: cli-test-data/vunnel/oracle

cli-test-data/vunnel/oracle: ## Prepare oracle data for CLI tests
	mkdir -p cli-test-data/vunnel
	../../../.tool/oras pull ghcr.io/anchore/grype-db/data/oracle:latest
	go build -C ../../../cmd/grype-db -o $(shell pwd)/grype-db
	./grype-db cache restore --path .cache/vunnel/oracle/grype-db-cache.tar.gz

.PHONY: install-oracle-labels
install-oracle-labels:
	mkdir -p cli-test-data/yardstick/labels
	cp -a ../../../data/vulnerability-match-labels/labels/docker.io+oraclelinux* ./cli-test-data/yardstick/labels/

.PHONY: clean
clean: clean-data ## Clear all existing yardstick results and delete python environment

.PHONY: clean-data
clean-data: clean-vunnel clean-yardstick clean-manager

.PHONY: clean-vunnel
clean-vunnel:
	rm -rf cli-test-data/vunnel

.PHONY: clean-yardstick
clean-yardstick:
	rm -rf cli-test-data/yardstick

.PHONY: clean-yardstick-labels
clean-yardstick-labels:
	rm -rf cli-test-data/yardstick/labels
	mkdir -p cli-test-data/yardstick/labels

.PHONY: clean-manager
clean-manager:
	rm -rf cli-test-data/manager

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
