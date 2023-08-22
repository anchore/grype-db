#!/usr/bin/env bash

. utils.sh

title "Starting workflow 2: validate DB"
# this test uses raw vunnel data to create a DB from scratch and see if it passes validation. There are different sets
# of labels to trigger a failing validation as well as passing validations under other non-ideal conditions.
# ultimately it is up to unit tests to fully exercise the validation logic, but this test is a good sanity check
# that the data needed for validations is wired up correctly.

header "Setup: create the DB"
make clean-manager
make cli-test-data/vunnel/oracle
run grype-db-manager -v db build -s 5
assert_not_empty $(last_stdout_file)
DB_ID="$(last_stdout)"

### Start of testing ########################
header "Case 1: fail DB validation (too many unknowns)"

make clean-yardstick-labels

run_expect_fail grype-db-manager db validate $DB_ID -vvv
assert_contains $(last_stderr_file) "current indeterminate matches % is greater than 10.0%"


#############################################
header "Case 2: pass DB validation"

make clean-yardstick-labels
echo "installing labels"
# use the real labels
cp -a ../../../data/yardstick/labels/docker.io+oraclelinux* ./cli-test-data/yardstick/labels/
tree ./cli-test-data/yardstick/labels/

run grype-db-manager db validate $DB_ID -vvv
assert_contains $(last_stdout_file) "Validation passed"


### End of testing ########################
end_testing
