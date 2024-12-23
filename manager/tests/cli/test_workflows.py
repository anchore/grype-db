import pytest

from grype_db_manager.db import schema


@pytest.mark.usefixtures("cli_env")
def test_workflow_1(cli_env, command, logger, tmp_path, grype):
    """
    workflow 1: create, upload, and delete a DB
    """
    logger.step("setup: prepare environment variables and directories")

    # set environment variables for aws and grype
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    schema_version = "6"
    cli_env.update(
        {
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_REGION": "us-west-2",
            "GRYPE_EXP_DBV6": "true",  # while we are in development, we need to enable the experimental dbv6 feature flag
            "GRYPE_DB_AUTO_UPDATE": "false", # disable auto-updating the database to avoid unexpected behavior
            "GOWORK": "off",  # workaround for Go 1.23+ parent directory module lookup
            "PATH": f"{bin_dir}:{cli_env['PATH']}",  # ensure `bin` directory is in PATH
            "GOBIN": bin_dir,
            "GRYPE_DB_UPDATE_URL": f"http://localhost:4566/testbucket/grype/databases/v{schema_version}/latest.json",
            "GRYPE_DB_CACHE_DIR": str(bin_dir),
        }
    )

    grype = grype.install(schema.grype_version(schema_version), bin_dir)

    logger.step("setup: clear previous data")
    command.run("make clean-manager", env=cli_env)
    command.run("make vunnel-oracle-data", env=cli_env)

    logger.step("setup: start mock S3")
    with command.pushd("s3-mock", logger):
        command.run("docker compose up -d", env=cli_env)
        command.run("python setup-workflow-1.py", env=cli_env)

    logger.step("case 1: create the DB")
    stdout, _ = command.run(f"grype-db-manager -v db build -s {schema_version}", env=cli_env)
    assert stdout.strip(), "Expected non-empty output"
    db_id = stdout.splitlines()[-1]  # assume DB ID is the last line of output

    stdout, _ = command.run("grype-db-manager db list", env=cli_env)
    assert db_id in stdout, f"Expected DB ID {db_id} in output"

    logger.step("case 2: upload the DB")
    stdout, _ = command.run(f"grype-db-manager db upload {db_id}", env=cli_env)
    assert f"DB archive '{db_id}' uploaded to s3://testbucket/grype/databases/v{schema_version}" in stdout
    assert f"latest.json '{db_id}' uploaded to s3://testbucket/grype/databases/v{schema_version}" in stdout

    logger.step("case 3: use the DB with grype")
    stdout, _ = grype.run("db update -v", env=cli_env)
    assert "Vulnerability database updated" in stdout

    stdout, _ = grype.run("--platform linux/amd64 --by-cve alpine:3.2", env=cli_env)
    assert "CVE-2016-2148" in stdout

    logger.step("case 4: delete the DB")
    command.run("grype-db-manager db clear", env=cli_env)
    stdout, _ = command.run("grype-db-manager db list", env=cli_env)
    assert db_id not in stdout, f"Did not expect DB ID {db_id} in output"

    ### end of testing ###

    logger.step("teardown: stop mock S3 and clean up")
    with command.pushd("s3-mock", logger):
        command.run("docker compose down -t 1 -v", env=cli_env)


@pytest.mark.usefixtures("cli_env")
def test_workflow_2(cli_env, command, logger):
    """
    workflow 2: validate DB
    This test creates a database from raw vunnel data and performs validations via the quality gate.
    """

    logger.step("setup: create the DB")
    command.run("make clean-manager", env=cli_env)
    command.run("make vunnel-oracle-data", env=cli_env)

    # create the database
    stdout, _ = command.run("grype-db-manager -v db build -s 6", env=cli_env)
    assert stdout.strip(), "Expected non-empty output"
    db_id = stdout.splitlines()[-1]  # Get the last line as the DB ID

    ### case 1: fail DB validation (too many unknowns) ###
    logger.step("case 1: fail DB validation (too many unknowns)")
    command.run("make clean-yardstick-labels", env=cli_env)

    # workaround for Go 1.23+ parent directory module lookup
    cli_env["GOWORK"] = "off"

    stdout, _ = command.run(
        f"grype-db-manager db validate {db_id} -vvv --recapture",
        env=cli_env,
        expect_fail=True,
    )
    assert "current indeterminate matches % is greater than 10%" in stdout

    ### case 2: fail DB validation (missing providers) ###
    logger.step("case 2: fail DB validation (missing providers)")
    command.run("make clean-yardstick-labels", env=cli_env)

    logger.info("installing labels")
    command.run("make install-oracle-labels", env=cli_env)

    _, stderr = command.run(
        f"grype-db-manager db validate {db_id} -vvv",
        env=cli_env,
        expect_fail=True,
    )
    assert "missing providers in DB" in stderr

    ### case 3: pass DB validation ###
    logger.step("case 3: pass DB validation")
    command.run("make clean-yardstick-labels", env=cli_env)

    logger.info("installing labels")
    command.run("make install-oracle-labels", env=cli_env)

    stdout, _ = command.run(
        f"grype-db-manager db validate {db_id} -vvv",
        env=cli_env,
    )
    assert "Quality gate passed!" in stdout
