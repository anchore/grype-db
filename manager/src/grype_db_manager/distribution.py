from __future__ import annotations

import datetime
import hashlib
import logging
import os
import tempfile
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

import iso8601

from grype_db_manager import s3utils
from grype_db_manager.db import listing, metadata

if TYPE_CHECKING:
    from collections.abc import Generator

DB_SUFFIXES = {".tar.gz", ".tar.zst"}
MAX_DB_AGE = 3  # old db listings are making the file large and slowing download times
MINIMUM_DB_COUNT = 3  # always include at least 2 databases, no matter how old


def listing_entries_dbs_in_s3(
    basenames: set[str],
    paths_by_basename: dict[str, str],
    s3_bucket: str,
    s3_path: str,
    suffixes: set[str] | None = None,
    max_age: int = MAX_DB_AGE,
    download_url_prefix: str = "",
) -> Generator[listing.Entry, None, None]:
    if not suffixes:
        suffixes = DB_SUFFIXES

    if not download_url_prefix:
        msg = "download_url_prefix must be specified"
        raise ValueError(msg)

    # generate metadata from each downloaded archive and add to the listing file
    for basename in basenames:
        if not any(basename.endswith(s) for s in suffixes):
            logging.debug(f"dropping db: unsupported extension {basename!r}")
            continue

        age = age_from_basename(basename)
        if age is None or age > max_age:
            logging.debug(f"dropping db: too old ({age} days) {basename!r}")
            continue

        s3_existing_path = paths_by_basename[basename]
        logging.info(f"new db: {s3_existing_path}")

        # we don't want to keep around files between processing of each db file, so purge on each iteration
        with tempfile.TemporaryDirectory(prefix="grype-downloaded-db") as tempdir:
            local_path = os.path.join(tempdir, basename)
            s3utils.download_to_file(
                bucket=s3_bucket,
                key=s3_existing_path,
                path=local_path,
            )

            # derive the checksum from the sha256 of the archive
            checksum = hash_file(path=local_path)

            # extract the metadata from the archive
            meta = metadata.from_archive(path=local_path)

            # create a new listing entry and add it to the listing
            url = f"{download_url_prefix.strip('/')}/{s3_path.strip('/')}/{basename.strip('/')}"
            url = urlunparse(urlparse(url))  # normalize the url

            yield listing.Entry(
                built=meta.built,
                version=meta.version,
                url=url,
                checksum=checksum,
            )


def existing_dbs_in_s3(s3_bucket: str, s3_path: str, suffixes: set[str] | None = None) -> dict[str, str]:
    if not suffixes:
        suffixes = DB_SUFFIXES

    # list objects in the db bucket path, download all objects not in the listing to a temp dir

    existing_databases = []

    for suffix in suffixes:
        found = list(
            s3utils.get_matching_s3_keys(bucket=s3_bucket, prefix=s3_path, suffix=suffix),
        )
        existing_databases.extend(found)

    logging.info(
        f"found {len(existing_databases)} existing databases in bucket={s3_bucket} path={s3_path}",
    )

    return get_paths_by_basename(existing_databases)


def get_paths_by_basename(paths: list[str]) -> dict[str, str]:
    paths_by_basename: dict[str, str] = {}
    for path in paths:
        basename = os.path.basename(path)
        if basename not in paths_by_basename:
            logging.debug(f"existing db {path!r}")

            paths_by_basename[basename] = path
        else:
            msg = f"duplicate basenames found (this should not happen): {basename}"
            raise RuntimeError(
                msg,
            )
    return paths_by_basename


def age_from_basename(basename: str) -> int | None:
    fields = basename.split(".", maxsplit=1)[0].split("_")
    if len(fields) < 3:
        return None

    ts_field = fields[-1]
    if not ts_field.endswith("Z"):
        ts_field = fields[-2]
    if not ts_field.endswith("Z"):
        return None

    try:
        return (_now() - iso8601.parse_date(ts_field)).days
    except:  # noqa: E722
        logging.exception(f"unable to parse age from basename {basename}")


def _now() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.UTC)


def hash_file(path: str) -> str:
    hasher = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            hasher.update(data)

    return f"sha256:{hasher.hexdigest()}"
