import datetime

import pytest

from yardstick import store
from yardstick.cli import config as ycfg

from grype_db_manager import grypedb
from grype_db_manager.db import validation


def _partial_db_info(checksum: str):
    return grypedb.DBInfo(
        uuid="session-id",
        schema_version=5,
        db_checksum=checksum,
        db_created=datetime.datetime.now(tz=datetime.timezone.utc),
        data_created=datetime.datetime.now(tz=datetime.timezone.utc),
        archive_path="archive-path",
    )


expected_db_info = _partial_db_info("sha256:d594a820353c99d1fcc29904ef0e4c0bace8ed7a0e21c4112325b6f57e4f9ad3")
bad_db_info = _partial_db_info("bad-checksum")


@pytest.mark.parametrize(
    "test_case, db_info, expected",
    [
        pytest.param(
            "good",
            expected_db_info,
            False,
            id="go-case",
        ),
        pytest.param(
            "inconsistent-db-checksum",
            expected_db_info,
            True,
            id="inconsistent-db-checksum",
        ),
        pytest.param(
            "missing-grype-request",
            expected_db_info,
            True,
            id="missing-grype-request",
        ),
        pytest.param(
            "unfulfilled-request",
            expected_db_info,
            True,
            id="unfulfilled-request",
        ),
        pytest.param(
            "different-image-set",
            expected_db_info,
            True,
            id="different-image-set",
        ),
        pytest.param(
            "missing-result-set",
            expected_db_info,
            True,
            id="missing-result-set",
        ),
        pytest.param(
            "good",
            bad_db_info,
            True,
            id="mismatched-db-checksum",
        ),
    ],
)
def test_is_result_set_stale(test_dir_path, test_case, db_info, expected):
    root = test_dir_path(f"fixtures/result-set-stale-detection/{test_case}")

    request_images = [
        "docker.io/anchore/test_images:grype-quality-node-d89207b@sha256:f56164678054e5eb59ab838367373a49df723b324617b1ba6de775749d7f91d4",
        "docker.io/anchore/test_images:vulnerabilities-alpine-3.11-d5be50d@sha256:01c78cee3fe398bf1f77566177770b07f1d2af01753c2434cb0735bd43a078b6",
        "docker.io/anchore/test_images:vulnerabilities-alpine-3.14-d5be50d@sha256:fe242a3a63699425317fba0a749253bceb700fb3d63e7a0f6497f53a587e38c5",
    ]

    is_stale = validation._is_result_set_stale(
        request_images=request_images, result_set="result-set", db_info=db_info, yardstick_root_dir=root
    )

    assert is_stale == expected
