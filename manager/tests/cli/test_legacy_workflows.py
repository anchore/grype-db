import pytest

from grype_db_manager.db import schema


@pytest.mark.usefixtures("cli_env")
def test_workflow_1(cli_env, command, logger):
    """
    workflow 1: create and delete a DB
    """

    logger.step("setup: clear previous data")
    command.run("make clean-manager", env=cli_env)
    command.run("make vunnel-oracle-data", env=cli_env)

    logger.step("case 1: create the DB")
    stdout, _ = command.run("grype-db-manager -c .grype-db-manager.yaml -v db build -s 5", env=cli_env)
    assert stdout.strip(), "Expected non-empty output"
    db_id = stdout.splitlines()[-1]  # assume DB ID is the last line of output

    stdout, _ = command.run("grype-db-manager -c .grype-db-manager.yaml db list", env=cli_env)
    assert db_id in stdout, f"Expected DB ID {db_id} in output"

    logger.step("case 2: delete the DB")
    command.run("grype-db-manager -c .grype-db-manager.yaml db clear", env=cli_env)
    stdout, _ = command.run("grype-db-manager -c .grype-db-manager.yaml db list", env=cli_env)
    assert db_id not in stdout, f"Did not expect DB ID {db_id} in output"


@pytest.mark.usefixtures("cli_env")
def test_workflow_2(cli_env, command, logger):
    """
    workflow 2: validate DB
    This test creates a database from raw vunnel data and performs validations under different conditions.
    """

    logger.step("setup: create the DB")
    command.run("make clean-manager", env=cli_env)
    command.run("make vunnel-oracle-data", env=cli_env)

    # create the database
    stdout, _ = command.run("grype-db-manager -c .grype-db-manager.yaml -v db build -s 5", env=cli_env)
    assert stdout.strip(), "Expected non-empty output"
    db_id = stdout.splitlines()[-1]  # Get the last line as the DB ID

    ### case 1: fail DB validation (too many unknowns) ###
    logger.step("case 1: fail DB validation (too many unknowns)")
    command.run("make clean-yardstick-labels", env=cli_env)

    # workaround for Go 1.23+ parent directory module lookup
    cli_env["GOWORK"] = "off"

    stdout, _ = command.run(
        f"grype-db-manager -c .grype-db-manager.yaml -vv db validate {db_id} --skip-namespace-check --recapture",
        env=cli_env,
        expect_fail=True,
    )
    assert "current indeterminate matches % is greater than 10%" in stdout

    ### case 2: fail DB validation (missing namespaces) ###
    logger.step("case 2: fail DB validation (missing namespaces)")
    command.run("make clean-yardstick-labels", env=cli_env)

    logger.info("installing labels")
    command.run("make install-oracle-labels", env=cli_env)

    _, stderr = command.run(
        f"grype-db-manager -c .grype-db-manager.yaml -vv db validate {db_id}",
        env=cli_env,
        expect_fail=True,
    )
    assert "missing namespaces in DB" in stderr

    ### case 3: pass DB validation ###
    logger.step("case 3: pass DB validation")
    command.run("make clean-yardstick-labels", env=cli_env)

    logger.info("installing labels")
    command.run("make install-oracle-labels", env=cli_env)

    stdout, _ = command.run(
        f"grype-db-manager -c .grype-db-manager.yaml -vv db validate {db_id} --skip-namespace-check",
        env=cli_env,
    )
    assert "Quality gate passed!" in stdout


@pytest.mark.usefixtures("cli_env")
def test_workflow_3(cli_env, command, logger, tmp_path, grype):
    """
    workflow 3: update an existing listing file
    This test uses a mock S3 setup to upload databases, generate a new listing file, and validate that the updated
    listing file works with grype for scanning.
    """

    logger.step("setup: prepare environment variables and directories")

    # set environment variables for aws and grype
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    # deep copy cli_env to avoid modifying the original
    cli_env = cli_env.copy()
    cli_env.update(
        {
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_REGION": "us-west-2",
            "PATH": f"{bin_dir}:{cli_env['PATH']}",  # ensure `bin` directory is in PATH
        }
    )

    grype = grype.install("v0.65.0", bin_dir)

    logger.step("setup: start mock S3 and upload databases")
    with command.pushd("s3-mock", logger):
        command.run("docker compose up -d", env=cli_env)
        command.run("python setup-legacy-workflow-3.py", env=cli_env)

    ### start of testing ###
    logger.step("case 1: update a listing file based on S3 state")

    # generate a new listing file
    stdout, _ = command.run("grype-db-manager -c .grype-db-manager.yaml listing update", env=cli_env)
    assert "Validation passed" in stdout
    assert "listing.json uploaded to s3://testbucket/grype/databases" in stdout

    # setup grype for DB updates and scans
    cli_env.update(
        {
            "GRYPE_DB_UPDATE_URL": "http://localhost:4566/testbucket/grype/databases/listing.json",
            "GRYPE_DB_CACHE_DIR": str(bin_dir),
        }
    )

    # validate grype DB listing and scanning
    stdout, _ = grype.run(f"db list", env=cli_env)
    assert "http://localhost:4566" in stdout

    stdout, _ = grype.run(f"db update", env=cli_env)

    stdout, _ = grype.run(f"--platform linux/amd64 --by-cve alpine:3.2", env=cli_env)
    assert "CVE-2016-2148" in stdout

    ### end of testing ###

    logger.step("teardown: stop mock S3 and clean up")
    with command.pushd("s3-mock", logger):
        command.run("docker compose down -t 1 -v", env=cli_env)


@pytest.mark.usefixtures("cli_env")
def test_workflow_4(cli_env, command, logger, tmp_path, grype):
    """
    workflow 4: full publish workflow
    This test builds and validates a new DB from raw vunnel data, uploads the DB to a mock S3, updates the listing file,
    and uses the updated listing file in a grype scan.
    """

    logger.step("setup: prepare environment variables and directories")

    # set environment variables for aws, grype, and schema versions
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    schema_version = "5"
    # deep copy cli_env to avoid modifying the original
    cli_env = cli_env.copy()
    cli_env.update(
        {
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_REGION": "us-west-2",
            "SCHEMA_VERSION": schema_version,
            "GRYPE_DB_MANAGER_VALIDATE_LISTING_OVERRIDE_GRYPE_VERSION": "v0.65.0",
            "GRYPE_DB_MANAGER_VALIDATE_LISTING_OVERRIDE_DB_SCHEMA_VERSION": "5",
            "PATH": f"{bin_dir}:{cli_env['PATH']}",  # ensure `bin` directory is in PATH
        }
    )

    grype = grype.install(schema.grype_version(schema_version), bin_dir)

    logger.step("setup: clean manager and prepare data")
    command.run("make clean-manager", env=cli_env)
    command.run("make vunnel-oracle-data", env=cli_env)
    command.run("make install-oracle-labels", env=cli_env)

    logger.step("setup: start mock S3 and upload initial data")
    with command.pushd("s3-mock", logger):
        command.run("docker compose up -d", env=cli_env)
        command.run("python setup-legacy-workflow-4.py", env=cli_env)

    ### start of testing ###
    logger.step("case 1: create and publish a DB")

    # build, validate, and upload the database
    stdout, _ = command.run(
        f"grype-db-manager -c .grype-db-manager.yaml db build-and-upload --schema-version {schema_version} --skip-namespace-check",
        env=cli_env,
    )
    assert "Quality gate passed!" in stdout
    assert "' uploaded to s3://testbucket/grype/databases" in stdout

    logger.step("case 2: update the listing file based on the DB uploaded")

    # update the listing file and validate
    stdout, _ = command.run("grype-db-manager -c .grype-db-manager.yaml -v listing update", env=cli_env)
    assert "Validation passed" in stdout
    assert "listing.json uploaded to s3://testbucket/grype/databases" in stdout

    # set grype environment variables
    cli_env.update(
        {
            "GRYPE_DB_UPDATE_URL": "http://localhost:4566/testbucket/grype/databases/listing.json",
            "GRYPE_DB_CACHE_DIR": str(bin_dir),
        }
    )

    # validate grype DB listing and scanning
    stdout, _ = grype.run("db list", env=cli_env)
    assert "http://localhost:4566" in stdout

    stdout, _ = grype.run("db update", env=cli_env)
    assert "Vulnerability database updated" in stdout

    stdout, _ = grype.run(
        "docker.io/oraclelinux:6@sha256:a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495 --by-cve",
        env=cli_env,
    )
    assert "ELSA-2021-9591" in stdout

    ### end of testing ###

    logger.step("teardown: stop mock S3 and clean up")
    with command.pushd("s3-mock", logger):
        command.run("docker compose down -t 1 -v", env=cli_env)
