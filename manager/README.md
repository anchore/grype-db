# grype-db-manager

A small python tool for publishing validated grype databases to S3 for distribution.

This is a rough outline of the DB release process using this tool:

```
# build a new DB, validate it, and upload it to S3
grype-db-manager -v db build-and-upload --schema-version #

# recreate the DB listing file from the current S3 state and upload it
# note: this requires having your AWS credentials configured
grype-db-manager listing update
```

The configuration for grype-db-manager is stored at .grype-db-manager.yaml, and in the context of this repo,
we have multiple configurations for different environments within the `config/grype-db-manager` directory.
