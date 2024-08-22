import datetime
import json

import pytest

from grype_db_manager import db


def test_listing_add_sorts_by_date():
    subject = db.listing.empty_listing()

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=3,
            url="https://b-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=3,
            url="https://a-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=3,
            url="https://c-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=4,
            url="https://b-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=4,
            url="https://a-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=4,
            url="https://c-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    bytes = subject.to_json()

    obj = json.loads(bytes)

    # we're expecting the most recent entry first
    assert obj["available"]["3"][0]["url"] == "https://c-place.com/something.tar.gz"
    assert obj["available"]["3"][1]["url"] == "https://b-place.com/something.tar.gz"
    assert obj["available"]["3"][2]["url"] == "https://a-place.com/something.tar.gz"
    assert obj["available"]["4"][0]["url"] == "https://c-place.com/something.tar.zst"
    assert obj["available"]["4"][1]["url"] == "https://b-place.com/something.tar.zst"
    assert obj["available"]["4"][2]["url"] == "https://a-place.com/something.tar.zst"


@pytest.mark.parametrize(
    "s3_path, expected",
    (
        ("somewhere/in/the/bucket", "somewhere/in/the/bucket/listing.json"),
        ("somewhere/in/the/bucket///", "somewhere/in/the/bucket/listing.json"),
        ("//somewhere/in/the/bucket/", "somewhere/in/the/bucket/listing.json"),
    ),
)
def test_listing_url(s3_path, expected):
    assert expected == db.Listing.url(s3_path, "listing.json")


def test_listing_basenames():
    subject = db.listing.empty_listing()

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=3,
            url="https://b-place.com/something-1.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=3,
            url="https://a-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=3,
            url="https://c-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=4,
            url="https://b-place.com/something-1.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=4,
            url="https://a-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=4,
            url="https://c-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    assert {"something.tar.gz", "something-1.tar.gz", "something.tar.zst", "something-1.tar.zst"} == subject.basenames()


def test_listing_latest():
    subject = db.listing.empty_listing()

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=3,
            url="https://b-place.com/something-1.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=3,
            url="https://a-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=3,
            url="https://c-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=4,
            url="https://b-place.com/something-1.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=4,
            url="https://a-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=4,
            url="https://c-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    assert "https://c-place.com/something.tar.gz" == subject.latest(3).url
    assert "https://c-place.com/something.tar.zst" == subject.latest(4).url


def test_listing_basename_difference():
    subject = db.listing.empty_listing()

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=3,
            url="https://b-place.com/something-1.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=3,
            url="https://a-place.com/something-2.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            version=3,
            url="https://c-place.com/something-3.tar.gz",
            checksum="123456789",
        )
    )

    basenames = {"something-3.tar.gz", "something-4.tar.gz"}
    expected_missing = {"something-1.tar.gz", "something-2.tar.gz"}
    expected_new = {"something-4.tar.gz"}

    actual_new, actual_missing = subject.basename_difference(basenames)

    assert expected_new == actual_new
    assert expected_missing == actual_missing


def test_filtering_listing_basename_difference():
    subject = db.listing.empty_listing()

    something1 = db.listing.Entry(
        built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        version=3,
        url="https://b-place.com/something-1.tar.zst",  # note: this gets filtered out!
        checksum="123456789",
    )

    something2 = db.listing.Entry(
        built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        version=3,
        url="https://a-place.com/something-2.tar.gz",  # note: this gets filtered out!
        checksum="123456789",
    )

    something3 = db.listing.Entry(
        built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        version=3,
        url="https://c-place.com/something-3.tar.gz",
        checksum="123456789",
    )

    subject.add(something1)
    subject.add(something2)
    subject.add(something3)

    expected = db.listing.empty_listing()
    expected.add(something3)

    basenames_from_s3 = {"something-3.tar.gz", "something-4.tar.gz"}
    expected_missing = {"something-1.tar.zst", "something-2.tar.gz"}
    expected_new = {"something-4.tar.gz"}

    actual_new, actual_missing = subject.basename_difference(basenames_from_s3)

    assert expected_new == actual_new
    assert expected_missing == actual_missing

    subject.remove_by_basename(actual_missing)

    assert subject == expected


def listing_over_years():
    subject = db.listing.empty_listing()

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://b-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://a-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://c-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://b-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://a-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://c-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    return subject


def listing_day_by_day():
    subject = db.listing.empty_listing()

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 26, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://b-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 27, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://a-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://c-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 26, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://b-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 27, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://a-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        db.listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://c-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    return subject


@pytest.mark.parametrize(
    "subject,now,max_age,min_elements,urls",
    [
        (
            # dont prune anything...
            listing_over_years(),
            datetime.datetime(2019, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc),
            9000,
            3,
            {
                "3": [
                    "https://c-place.com/something.tar.gz",
                    "https://b-place.com/something.tar.gz",
                    "https://a-place.com/something.tar.gz",
                ],
                "4": [
                    "https://c-place.com/something.tar.zst",
                    "https://b-place.com/something.tar.zst",
                    "https://a-place.com/something.tar.zst",
                ],
            },
        ),
        (
            # we prune based on the age...
            listing_over_years(),
            datetime.datetime(2019, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc),
            7,
            1,
            {
                "3": [
                    "https://c-place.com/something.tar.gz",
                ],
                "4": [
                    "https://c-place.com/something.tar.zst",
                ],
            },
        ),
        (
            # we prune based on the age... older elements are kept to ensure minimum elements
            listing_over_years(),
            datetime.datetime(2019, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc),
            7,
            2,
            {
                "3": [
                    "https://c-place.com/something.tar.gz",
                    "https://b-place.com/something.tar.gz",
                ],
                "4": [
                    "https://c-place.com/something.tar.zst",
                    "https://b-place.com/something.tar.zst",
                ],
            },
        ),
        (
            # we prune based on the age... minimum elements is ignored
            listing_day_by_day(),
            datetime.datetime(2019, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc),
            1,
            1,
            {
                "3": [
                    "https://c-place.com/something.tar.gz",
                    "https://a-place.com/something.tar.gz",
                ],
                "4": [
                    "https://c-place.com/something.tar.zst",
                    "https://a-place.com/something.tar.zst",
                ],
            },
        ),
        (
            # we prune based on the age... minimum elements is ignored (+ 1 day in the future)
            listing_day_by_day(),
            datetime.datetime(2019, 11, 29, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc),
            2,
            1,
            {
                "3": [
                    "https://c-place.com/something.tar.gz",
                    "https://a-place.com/something.tar.gz",
                ],
                "4": [
                    "https://c-place.com/something.tar.zst",
                    "https://a-place.com/something.tar.zst",
                ],
            },
        ),
        (
            # we prune based on the age... minimum elements is ignored (+ 1 year in the future)
            listing_day_by_day(),
            datetime.datetime(2020, 11, 29, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc),
            2,
            1,
            {
                "3": [
                    "https://c-place.com/something.tar.gz",
                ],
                "4": [
                    "https://c-place.com/something.tar.zst",
                ],
            },
        ),
    ],
)
def test_prune(subject, now, max_age, min_elements, urls):
    subject.prune(max_age_days=max_age, minimum_elements=min_elements, now=now)

    obj = json.loads(subject.to_json())

    actual = {}
    for schema_version, elements in obj["available"].items():
        actual[schema_version] = [e["url"] for e in elements]

    assert urls == actual


def test_to_and_from_json():
    subject = db.listing.empty_listing()

    something1 = db.listing.Entry(
        built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        version=3,
        url="https://b-place.com/something-3.tar.zst",  # note: this gets filtered out!
        checksum="123456789",
    )

    something2 = db.listing.Entry(
        built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        version=4,
        url="https://a-place.com/something-4.tar.gz",  # note: this gets filtered out!
        checksum="123456789",
    )

    something3 = db.listing.Entry(
        built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        version=5,
        url="https://c-place.com/something-5.tar.gz",
        checksum="123456789",
    )

    subject.add(something1)
    subject.add(something2)
    subject.add(something3)

    got_to = subject.to_json()

    expected_to = '{"available": {"3": [{"built": "2017-11-28T23:55:59.342380", "checksum": "123456789", "url": "https://b-place.com/something-3.tar.zst", "version": 3}], "4": [{"built": "2016-11-28T23:55:59.342380", "checksum": "123456789", "url": "https://a-place.com/something-4.tar.gz", "version": 4}], "5": [{"built": "2019-11-28T23:55:59.342380", "checksum": "123456789", "url": "https://c-place.com/something-5.tar.gz", "version": 5}]}}'

    assert expected_to == got_to

    got_from = db.Listing.from_json(got_to)

    assert subject == got_from


@pytest.fixture
def listing():
    # out-of-order entries, including entries with the same timestamp but different suffixes
    entries = [
        db.listing.Entry(
            built="2024-08-22T01:31:37Z",
            version=1,
            url="https://grype.anchore.io/databases/vulnerability-db_v1_2024-08-21T01:31:31Z_1724213864.tar.gz",
            checksum="sha256:d0e8ca5357ebc152b767fe0a9caba8aba0dd106eacf936c653f02932a2c8e238",
        ),
        db.listing.Entry(
            built="2024-08-22T01:31:37Z",
            version=1,
            url="https://grype.anchore.io/databases/vulnerability-db_v1_2024-08-22T01:31:37Z_1724300289.tar.gz",
            checksum="sha256:5ff9f2c047514ba4fbfc45e84df234ecbd2f09c11002c2f008be3a5c2c73b6f1",
        ),
        db.listing.Entry(
            built="2024-08-22T01:31:37Z",
            version=1,
            url="https://grype.anchore.io/databases/vulnerability-db_v1_2024-08-22T01:31:37Z_1724340381.tar.gz",
            checksum="sha256:d3a298876eba3802bef8e3d9abb1941aa1f9ef2405333624951baeb85ea8f3da",
        ),
        db.listing.Entry(
            built="2024-08-21T01:31:31Z",
            version=1,
            url="https://grype.anchore.io/databases/vulnerability-db_v1_2024-08-21T01:31:31Z_1724213870.tar.gz",
            checksum="sha256:e1a298876eba3802bef8e3d9abb1941aa1f9ef2405333624951baeb85ea8f3dc",
        ),
        db.listing.Entry(
            built="2024-08-22T01:31:37Z",
            version=1,
            url="https://grype.anchore.io/databases/vulnerability-db_v1_2024-08-22T01:31:37Z_1724340382.tar.gz",
            checksum="sha256:f3a298876eba3802bef8e3d9abb1941aa1f9ef2405333624951baeb85ea8f3fb",
        ),
    ]

    available = {1: entries}
    return db.listing.Listing(available=available)


def test_listing_sort(listing):

    listing.sort()

    sorted_urls = [
        "https://grype.anchore.io/databases/vulnerability-db_v1_2024-08-22T01:31:37Z_1724340382.tar.gz",
        "https://grype.anchore.io/databases/vulnerability-db_v1_2024-08-22T01:31:37Z_1724340381.tar.gz",
        "https://grype.anchore.io/databases/vulnerability-db_v1_2024-08-22T01:31:37Z_1724300289.tar.gz",
        "https://grype.anchore.io/databases/vulnerability-db_v1_2024-08-21T01:31:31Z_1724213870.tar.gz",
        "https://grype.anchore.io/databases/vulnerability-db_v1_2024-08-21T01:31:31Z_1724213864.tar.gz",
    ]

    assert [entry.url for entry in listing.available[1]] == sorted_urls
