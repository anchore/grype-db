#!/usr/bin/env bash

. utils.sh

title "Starting workflow 3: update the listing file (dry-run)"

# note: these credentials / configurations must match the ones used in s3-mock/setup.py and .grype-db-manager.yaml
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_REGION="us-west-2"

set -e

pushd s3-mock
docker-compose up -d
python setup.py
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


### End of testing ########################

pushd s3-mock
docker-compose down -t 1
popd

end_testing
