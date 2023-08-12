#!/usr/bin/env bash

. utils.sh

title "Starting workflow 2: fail DB validation due to missing labels"

header "Setup: create the DB"
make clean-manager
make cli-test-data/vunnel/oracle
run grype-db-manager -v db build -s 5
assert_not_empty $(last_stdout_file)
DB_ID="$(last_stdout)"

### Start of testing ########################
header "Case 1: fail DB validation (too many unknowns)"

make clean-yardstick-labels

run_expect_fail grype-db-manager db validate $DB_ID
assert_contains $(last_stderr_file) "current indeterminate matches % is greater than 10%"


#############################################
header "Case 2: pass DB validation (half tp/fp)"

make clean-yardstick-labels
echo "installing half-tp-half-fp-labels"
cp -a ./fixtures/half-tp-half-fp-labels/* ./cli-test-data/yardstick/labels/

run grype-db-manager db validate $DB_ID
assert_contains $(last_stdout_file) "Validation passed"


#############################################
header "Case 2: pass DB validation (all tp)"

make clean-yardstick-labels
echo "installing all-tp-labels"
cp -a ./fixtures/all-tp-labels/* ./cli-test-data/yardstick/labels/

run grype-db-manager db validate $DB_ID
assert_contains $(last_stdout_file) "Validation passed"


### End of testing ########################
end_testing
