import datetime
import json

import pytest

from publisher.utils import listing
from publisher.utils.constants import (
    LEGACY_DB_SUFFIXES,
)


def test_listing_add_sorts_by_date():
    subject = listing.empty_listing()

    subject.add(
        listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://b-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://a-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://c-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://b-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://a-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
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
    assert expected == listing.Listing.url(s3_path)


def test_listing_basenames():
    subject = listing.empty_listing()

    subject.add(
        listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://b-place.com/something-1.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://a-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://c-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://b-place.com/something-1.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://a-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://c-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    assert {"something.tar.gz", "something-1.tar.gz", "something.tar.zst", "something-1.tar.zst"} == subject.basenames()


def test_listing_latest():
    subject = listing.empty_listing()

    subject.add(
        listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://b-place.com/something-1.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://a-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://c-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://b-place.com/something-1.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://a-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://c-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    assert "https://c-place.com/something.tar.gz" == subject.latest(3).url
    assert "https://c-place.com/something.tar.zst" == subject.latest(4).url


def test_listing_basename_difference():
    subject = listing.empty_listing()

    subject.add(
        listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://b-place.com/something-1.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://a-place.com/something-2.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
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
    subject = listing.empty_listing()

    something1 = listing.Entry(
        built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380).strftime(
            "%Y-%m-%dT%H:%M:%S.%f%z"
        ),
        version=3,
        url="https://b-place.com/something-1.tar.zst", # note: this gets filtered out!
        checksum="123456789",
    )

    something2 = listing.Entry(
        built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380).strftime(
            "%Y-%m-%dT%H:%M:%S.%f%z"
        ),
        version=3,
        url="https://a-place.com/something-2.tar.gz", # note: this gets filtered out!
        checksum="123456789",
    )

    something3 = listing.Entry(
        built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380).strftime(
            "%Y-%m-%dT%H:%M:%S.%f%z"
        ),
        version=3,
        url="https://c-place.com/something-3.tar.gz",
        checksum="123456789",
    )

    subject.add(something1)
    subject.add(something2)
    subject.add(something3)

    expected = listing.empty_listing()
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
    subject = listing.empty_listing()

    subject.add(
        listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://b-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://a-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://c-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2017, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://b-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2016, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://a-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
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
    subject = listing.empty_listing()

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 26, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://b-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 27, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://a-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=3,
            url="https://c-place.com/something.tar.gz",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 26, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://b-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 27, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://a-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    subject.add(
        listing.Entry(
            built=datetime.datetime(2019, 11, 28, 23, 55, 59, 342380, tzinfo=datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            version=4,
            url="https://c-place.com/something.tar.zst",
            checksum="123456789",
        )
    )

    return subject

@pytest.mark.parametrize("subject,now,max_age,min_elements,urls",
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
                ]
            }
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
                    ]
                }
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
                    ]
                }
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
                    ]
                }
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
                    ]
                }
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
                    ]
                }
        ),
    ]
 )
def test_prune(subject, now, max_age, min_elements, urls):
    subject.prune(max_age_days=max_age, minimum_elements=min_elements, now=now)

    obj = json.loads(subject.to_json())

    actual = {}
    for schema_version, elements in obj["available"].items():
        actual[schema_version] = [e["url"] for e in elements]

    assert urls == actual
