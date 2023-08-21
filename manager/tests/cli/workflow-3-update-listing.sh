#!/usr/bin/env bash

. utils.sh

title "Starting workflow 3: update the listing file"
# this uses real, already-built DBs (from the production workflow) to exercise the listing file update logic.
# an S3 mock is used to upload a set of DBs and to generate a new listing file from. The uploaded listing file
# is then used by grype to download the correct DB and run a scan.

# note: these credentials / configurations must match the ones used in s3-mock/setup.py and .grype-db-manager.yaml
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_REGION="us-west-2"

GRYPE_VERSION="v0.65.0"

set -e

BIN_DIR="./bin"

rm -rf $BIN_DIR

curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b $BIN_DIR $GRYPE_VERSION

pushd s3-mock
docker-compose up -d
python setup-workflow-3.py
popd

set +e

### Start of testing ########################
header "Case 1: update a listing file based on S3 state"

# note: this test is exercising the following commands:
# grype-db-manager listing create
# grype-db-manager listing validate <listing-file-path>

run grype-db-manager listing update
assert_contains $(last_stdout_file) "Validation passed"
assert_contains $(last_stdout_file) "listing.json uploaded to s3://testbucket/grype/databases"

# check if grype works with this updated listing file
export GRYPE_DB_UPDATE_URL="http://localhost:4566/testbucket/grype/databases/listing.json"
export GRYPE_DB_CACHE_DIR=$BIN_DIR

run bin/grype db list

assert_contains $(last_stdout_file) "http://localhost:4566"

run bin/grype db update

run bin/grype alpine:3.2

assert_contains $(last_stdout_file) "CVE-2016-2148"


### End of testing ########################

pushd s3-mock
docker-compose down -t 1 -v
popd

end_testing
