# CLI tests

The CLI tests here attempt to cover the most important user flows via the CLI, asserting correct return code, 
output to the terminal, and limited side effects (e.g. files created locally or uploaded to S3).

Some tests rely on uploading files to S3, which has been mocked with a localstack instance via a docker compose stack.
This means that no special AWS credentials or external S3 bucket / services are required for testing.

If you want to run all CLI test:
```shell
# from the manager/tests/cli directory

make
```

If you'd like to run a single test:
```shell
# from the manager/tests/cli directory

./run.sh <test-file-name>

# e.g.
# ./run.sh workflow-3-update-listing.sh
# ./run.sh workflow-*db.sh
```
