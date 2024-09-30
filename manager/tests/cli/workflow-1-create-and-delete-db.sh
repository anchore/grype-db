#!/usr/bin/env bash

. utils.sh

title "Starting workflow 1: create and delete DB"

header "Setup: clear previous data"

make clean-manager
make cli-test-data/vunnel/oracle


### Start of testing ########################
header "Case 1: create the DB"

run grype-db-manager -v db build -s 5
assert_not_empty $(last_stdout_file)
DB_ID="$(last_stdout)"
run grype-db-manager db list

assert_contains "$(last_stdout_file)" $DB_ID


#############################################
header "Case 2: delete the DB"

run grype-db-manager db clear
run grype-db-manager db list
assert_does_not_contain "$(last_stdout_file)" $DB_ID


### End of testing ########################
end_testing
