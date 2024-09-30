import datetime

import pytest

from grype_db_manager import distribution


@pytest.mark.parametrize(
    "basename,expected",
    [
        pytest.param("vulnerability-db_v2_2022-12-02T08:18:50Z_f1fabf7df7a8311d1f4f.tar.gz", 251, id="new-archive-style"),
        pytest.param("vulnerability-db_v3_2022-01-23T08:16:27Z.tar.gz", 564, id="original-archive-style"),
    ],
)
def test_age_from_basename(mocker, basename, expected):
    # patch grypedb.distribution._now with a mock
    mocker.patch.object(
        distribution, "_now", return_value=datetime.datetime(2023, 8, 10, 17, 50, 16, 805478, tzinfo=datetime.timezone.utc)
    )

    assert expected == distribution.age_from_basename(basename)


def test_get_paths_by_basename():
    paths = [
        "somewhere/a/place/thing-1.tar.gz",
        "/b/place/thing-2.tar.gz",
        "somewhere/thing-3.tar.gz",
        "somewhere/a/place/thing-1.tar.zst",
        "/b/place/thing-2.tar.zst",
        "somewhere/thing-3.tar.zst",
    ]

    expected = {
        "thing-1.tar.gz": "somewhere/a/place/thing-1.tar.gz",
        "thing-2.tar.gz": "/b/place/thing-2.tar.gz",
        "thing-3.tar.gz": "somewhere/thing-3.tar.gz",
        "thing-1.tar.zst": "somewhere/a/place/thing-1.tar.zst",
        "thing-2.tar.zst": "/b/place/thing-2.tar.zst",
        "thing-3.tar.zst": "somewhere/thing-3.tar.zst",
    }

    got = distribution.get_paths_by_basename(paths)

    assert expected == got


def test_get_paths_by_basename_raises_duplicates():
    paths = [
        "somewhere/a/place/thing-1.tar.gz",
        "so/thing-1.tar.gz",
        "/b/place/thing-2.tar.gz",
        "somewhere/thing-3.tar.gz",
        "somewhere/a/place/thing-1.tar.zst",
        "so/thing-1.tar.zst",
        "/b/place/thing-2.tar.zst",
        "somewhere/thing-3.tar.zst",
    ]

    with pytest.raises(RuntimeError):
        distribution.get_paths_by_basename(paths)


def test_hash_file(test_dir_path):
    path = test_dir_path("fixtures/hash/target")

    got = distribution.hash_file(path)

    expected = "sha256:e3d145615cddc198b82cfa779b5632e0090169e0686ba9c231aa7adce1954433"

    assert expected == got
