# grype-db-manager

A small python tool for publishing validated grype databases to S3 for distribution.


This is a rough outline of the DB release process using this tool
```
# build a new DB, validate it, and upload it to S3
grype-db-manager -v db build-and-upload --schema-version #

# recreate the DB listing file from the current S3 state and upload it
grype-db-manager listing update
```
