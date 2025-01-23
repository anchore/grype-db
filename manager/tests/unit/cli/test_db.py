import datetime

from click.testing import CliRunner

from grype_db_manager import cli, grypedb


def test_upload_db(mocker, test_dir_path, redact_aws_credentials):
    config_path = test_dir_path("fixtures/db/upload-test-config.yaml")

    # mock db.DBManager to return a mock object
    # the mock object should respond to get_db_info and return a grypedb.DBInfo object
    db_mock = mocker.patch("grype_db_manager.cli.db.DBManager")
    db_mock.return_value.get_db_info.return_value = grypedb.DBInfo(
        uuid="some-db-uuid",
        schema_version=5,
        db_checksum="checksum",
        db_created=datetime.datetime.now(),
        data_created=datetime.datetime.now(),
        archive_path="some/path/to/archive.tar.gz",
    )

    s3_mock = mocker.patch("grype_db_manager.cli.db.s3utils")
    s3_mock.upload_file.return_value = None

    runner = CliRunner()
    result = runner.invoke(cli.cli, f"-c {config_path} db upload some-db-uuid".split())

    assert result.exit_code == 0

    # ensure the s3 mock was called with the right arguments
    s3_mock.upload_file.assert_called_once_with(
        path="some/path/to/archive.tar.gz",
        bucket="testbucket",
        key="grype/databases/archive.tar.gz",
        CacheControl="public,max-age=31536000",
    )
