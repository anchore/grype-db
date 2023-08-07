#!/usr/bin/env bash

. utils.sh

make prep-data

### Start of testing...

# create the DB

run grype-db-manager -v db build -s 5

assert_last_output_not_empty

DB_ID=$(last_output)

run grype-db-manager db list

assert_last_output_contains $DB_ID


# validate the DB (should fail)

run_expect_fail grype-db-manager db validate $DB_ID

### End of testing...

end_testing()
