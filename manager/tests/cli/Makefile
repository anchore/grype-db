ACTIVATE_VENV = . venv/bin/activate &&

# formatting variables
BOLD := $(shell tput -T linux bold))
CYAN := $(shell tput -T linux setaf 6)
RESET := $(shell tput -T linux sgr0)

test: venv ## Run CLI tests
	$(ACTIVATE_VENV) ./case-*.sh

venv: venv/touchfile ## Create a python virtual environment

venv/touchfile: ../../../pyproject.toml
	test -d venv || python3 -m venv venv
	$(ACTIVATE_VENV) pip install -e ../../../
	touch venv/touchfile

prep-data: clean-data ## Prepare data for CLI tests
	mkdir -p cli-test-data/vunnel
	oras pull ghcr.io/anchore/grype-db/data/oracle:latest && go run ../../../cmd/grype-db cache restore --path ./grype-db-cache.tar.gz

prep-labels: ## Copy the label fixtures into the yardstick directory
	rm -rf ./cli-test-data/yardstick/labels
	mkdir -p ./cli-test-data/yardstick/labels
	cp -a ./fixtures/yardstick/labels ./cli-test-data/yardstick/labels

.PHONY: clean
clean: clean-data clean-env ## Clear all existing yardstick results and delete python environment

clean-data:
	rm -rf cli-test-data

clean-env:
	rm -rf venv

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'