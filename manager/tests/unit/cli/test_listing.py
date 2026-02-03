import os
import io
import tarfile
import boto3
import pytest
from click.testing import CliRunner
from moto import mock_s3
from unittest.mock import patch

from grype_db_manager import cli, utils
from grype_db_manager import db
from grype_db_manager.cli import config


# USEFUL DEV FUNCTION: used to create the initial small input-listing.json file from a rather large listing.json file
#
# def create_sample_listing(test_dir_path):
#     path = test_dir_path("fixtures/listing/create/input-listing.json")
#     with open(path) as f:
#         listing_json = f.read()
#
#     lst = db.Listing.from_json(listing_json)
#     lst.prune(3, 3)
#
#     content = lst.to_json(indent=2)
#     with open(path, "w") as f:
#         f.write(content)


@pytest.fixture
def listing_s3_mock(redact_aws_credentials):
    def run(dir_with_config: str, skip_db_in_s3: list[str] = None, extra_dbs: list[str] = None):
        if not skip_db_in_s3:
            skip_db_in_s3 = []

        if not extra_dbs:
            extra_dbs = []

        listing_file_name = "listing.json"

        with utils.set_directory(dir_with_config):
            cfg = config.load(".grype-db-manager.yaml")
            if os.path.exists(listing_file_name):
                os.remove(listing_file_name)

        bucket = cfg.distribution.s3_bucket
        path = cfg.distribution.s3_path

        listing_path = os.path.join(path, listing_file_name)

        # add the input listing file to the bucket
        input_listing_path = os.path.join(dir_with_config, "input-listing.json")

        with open(input_listing_path) as f:
            contents = f.read()

        s3 = boto3.client("s3", region_name="us-east-1")

        s3.create_bucket(Bucket=bucket)
        s3.put_object(Bucket=bucket, Key=listing_path, Body=contents)

        # parse the listing file
        lst = db.Listing.from_json(contents)

        # create a DB entry for each artifact
        url_prefix = "http://localhost:4566/"
        for entries in lst.available.values():
            for entry in entries:
                db_bucket_path = entry.url.removeprefix(url_prefix)
                if db_bucket_path in skip_db_in_s3:
                    continue
                s3.put_object(Bucket=bucket, Key=db_bucket_path, Body="db-archive-contents...")

        # add any extra DBs
        for db_path in extra_dbs:
            # parse built and version from
            # grype/databases/vulnerability-db_v1_2023-08-08T01:33:25Z_45f59b141d7256bf2c4d.tar.gz
            # e.g. 2023-08-08T01:33:25Z and 1
            fields = db_path.split("_")
            built, version = fields[2], int(fields[1].removeprefix("v"))
            s3.put_object(Bucket=bucket, Key=db_path, Body=create_tar_gz(built, version))

        return s3

    return run


def create_tar_gz(built: str, version: int):
    tar_fileobj = io.BytesIO()
    with tarfile.open(fileobj=tar_fileobj, mode="w|") as tar:
        content = db.Metadata(built=built, version=version).to_json().encode("utf-8")
        tf = tarfile.TarInfo("metadata.json")
        tf.size = len(content)
        tar.addfile(tf, io.BytesIO(content))
    tar_fileobj.seek(0)
    return tar_fileobj.read()


@pytest.mark.parametrize(
    "case_dir, expected_exit_code, extra_dbs, contains",
    [
        pytest.param(
            "create-all-exists",
            0,
            [],
            ["discovered 0 new database candidates to add to the listing", "wrote 15 total database entries to the listing"],
            id="create-all-exists",
        ),
        pytest.param(
            "create-new-db",
            0,
            [
                "databases/vulnerability-db_v1_2024-08-22T01:31:37Z_1724340381.tar.gz",
                "databases/vulnerability-db_v2_2024-08-22T01:31:37Z_1724340410.tar.gz",
                "databases/vulnerability-db_v3_2024-08-22T01:31:37Z_1724340460.tar.gz",
                "databases/vulnerability-db_v4_2024-08-22T01:31:37Z_1724340541.tar.gz",
                "databases/vulnerability-db_v5_2024-08-22T01:31:37Z_1724340606.tar.gz",
            ],
            [
                "discovered 5 new database candidates to add to the listing",
                "new db: databases/vulnerability-db_v1_2024-08-22T01:31:37Z_1724340381.tar.gz",
                "downloading file from s3 bucket=testbucket key=databases/vulnerability-db_v1_2024-08-22T01:31:37Z_1724340381.tar.gz",
                # note that the download URL isn't right relative to production values (where the existing listing was pulled from)
                # but instead it's correct relative to the configuration, which specifies a localhost route.
                "adding new listing entry: Entry(built='2024-08-22T01:31:37Z', version=1, url='http://localhost:4566/testbucket/databases/vulnerability-db_v1_2024-08-22T01:31:37Z_1724340381.tar.gz', checksum='sha256:7a62753ddb1f12994fdcd41244106cc459406620c522cb32c54da46b12b86634')",
                "wrote 15 total database entries to the listing",
            ],
            id="create-new-db",
        ),
    ],
)
@mock_s3
@patch("grype_db_manager.distribution.age_from_basename")
def test_create_listing(
    mock_file_age, test_dir_path, listing_s3_mock, case_dir, expected_exit_code, extra_dbs: list[str], contains
):
    # contains an application config file
    config_dir_path = test_dir_path(f"fixtures/listing/{case_dir}")
    listing_s3_mock(config_dir_path, extra_dbs=extra_dbs)
    mock_file_age.return_value = 2  # needs to be less than distribution.MAX_DB_AGE

    with utils.set_directory(config_dir_path):
        with open("expected-listing.json") as f:
            expected_object = db.Listing.from_json(f.read())

        runner = CliRunner()
        result = runner.invoke(cli.cli, "-c .grype-db-manager.yaml listing create".split())

        # for debugging
        print(result.output)

        assert result.exit_code == expected_exit_code

        if expected_exit_code == 0:
            with open("listing.json") as f:
                actual_object = db.Listing.from_json(f.read())

    for item in contains:
        assert item in result.output

    if expected_exit_code == 0:
        assert actual_object == expected_object
