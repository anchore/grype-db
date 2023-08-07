#!/usr/bin/env bash

. utils.sh

title "Starting case 1: create and delete DB"
make prep-data

### Start of testing...

# create the DB

run grype-db-manager -v db build -s 5

assert_last_output_not_empty

DB_ID=$(last_output)

run grype-db-manager db list

assert_last_output_contains $DB_ID


# delete the DB

run grype-db-manager db clear

run grype-db-manager db list

assert_last_output_does_not_contain $DB_ID


### End of testing...

end_testing
