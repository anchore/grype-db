#!/usr/bin/env bash

. utils.sh

title "Starting workflow 4: full publish workflow"
# this test exercises the full publish workflow, by building and validating a new DB from raw vunnel data,
# uploading the DB to an S3 mock, updating and upload the listing file, and then using the updated listing file
# in a grype scan.

# note: these credentials / configurations must match the ones used in s3-mock/setup.py and .grype-db-manager.yaml
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_REGION="us-west-2"

GRYPE_VERSION="v0.65.0"
SCHEMA_VERSION="5"

# there are what are used in the staging pipeline for a single DB build
export GRYPE_DB_MANAGER_VALIDATE_LISTING_OVERRIDE_GRYPE_VERSION=$GRYPE_VERSION
export GRYPE_DB_MANAGER_VALIDATE_LISTING_OVERRIDE_DB_SCHEMA_VERSION=$SCHEMA_VERSION

set -e

BIN_DIR="./bin"

rm -rf $BIN_DIR

curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b $BIN_DIR $GRYPE_VERSION

make clean-manager
make cli-test-data/vunnel/oracle

pushd s3-mock
docker-compose up -d
python setup-workflow-4.py
popd

set +e

### Start of testing ########################
header "Case 1: create and publish a DB"

# note: this test is exercising the following commands:
# grype-db-manager db build
# grype-db-manager db validate <uuid> --skip-namespace-check
# grype-db-manager db upload <uuid>

run grype-db-manager db build-and-upload --schema-version $SCHEMA_VERSION --skip-namespace-check
assert_contains $(last_stdout_file) "Validation passed"
assert_contains $(last_stdout_file) "' uploaded to s3://testbucket/grype/databases"


header "Case 2: update the listing file based on the DB uploaded"

# note: this test is exercising the following commands:
# grype-db-manager listing create
# grype-db-manager listing validate <listing-file-path>

run grype-db-manager listing update
assert_contains $(last_stdout_file) "Validation passed"
assert_contains $(last_stdout_file) "listing.json uploaded to s3://testbucket/grype/databases"

# check if grype works with this updated listing file
export GRYPE_DB_UPDATE_URL="http://localhost:4566/testbucket/grype/databases/listing.json"
export GRYPE_DB_CACHE_DIR="./bin"

run bin/grype db list

assert_contains $(last_stdout_file) "http://localhost:4566"

run bin/grype db update

run bin/grype docker.io/oraclelinux:6@sha256:a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495

assert_contains $(last_stdout_file) "ELSA-2021-9591"


### End of testing ########################

pushd s3-mock
docker-compose down -t 1 -v
popd

end_testing
