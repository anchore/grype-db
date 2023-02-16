import pytest

from publisher.console import get_paths_by_basename


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

    assert expected == get_paths_by_basename(paths)


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
        get_paths_by_basename(paths)
