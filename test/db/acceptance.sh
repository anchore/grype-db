#!/usr/bin/env bash
set -eu

BOLD=$(tput -T linux bold)
RESET=$(tput -T linux sgr0)

function title() {
  echo "${BOLD}$1${RESET}"
}

SCHEMA_VERSION=${1:-}

if [ -z "$SCHEMA_VERSION" ]; then
  echo "Usage: $0 <schema_version>"
  exit 1
else
  title "Building DB"
fi

DB_ID=$(grype-db-manager -v -c ./config/grype-db-manager/acceptance-pr.yaml db build --schema-version $SCHEMA_VERSION)

if [ -z "$DB_ID" ]; then
  echo "Failed to create DB instance"
  exit 1
fi

title "Validating DB"

grype-db-manager -vv -c ./config/grype-db-manager/acceptance-pr.yaml db validate $DB_ID
