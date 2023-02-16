#!/usr/bin/env python3
import os
import hashlib
import tempfile
import logging.config
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse
from typing import Dict, Set, Generator, List, Optional

import iso8601  # type: ignore
import click

import publisher.utils.grype as grype
import publisher.utils.builder as builder
import publisher.utils.test as test
import publisher.utils.listing as listing
import publisher.utils.metadata as metadata
import publisher.utils.s3utils as s3utils
from publisher.utils.constants import (
    DB_DIR,
    DB_SUFFIXES,
    LEGACY_DB_SUFFIXES,
    NEW_DB_SUFFIXES,
    GOLDEN_REPORT_LOCATION,
    TEST_IMAGE,
    STAGE_DIR,
)

MAX_DB_AGE = 120  # ~4 months in days
MINIMUM_DB_COUNT = MAX_DB_AGE  # number of db entries per schema
GRYPE_TEST_SCHEMA = os.environ.get("GRYPE_TEST_SCHEMA", None)
GRYPE_TEST_RELEASE = os.environ.get("GRYPE_TEST_BRANCH", None)


@click.group(help="Tooling to support generating the publishing supported versions of grype DB.")
def cli():
    # pylint: disable=redefined-outer-name, import-outside-toplevel
    import logging.config

    logging.config.dictConfig(
        {
            'version': 1,
            'formatters': {
                'standard': {
                    'format': '%(asctime)s [%(levelname)s] [%(module)s.%(funcName)s] %(message)s',
                    'datefmt': '',
                },
            },
            'handlers': {
                'default': {
                    'level': 'DEBUG',
                    'formatter': 'standard',
                    'class': 'logging.StreamHandler',
                    'stream': 'ext://sys.stdout',  # (default is stderr)
                },
            },
            'loggers': {
                '': { # root logger
                    'handlers': ['default'],
                    'level': 'DEBUG',
                },
            }
        }
    )


@cli.command()
@click.option("--schema-version", required=True, help="the DB schema version to build and package")
def generate(schema_version: int):
    golden_image_report = os.path.join(
        GOLDEN_REPORT_LOCATION, "%s.json" % TEST_IMAGE.replace(":", "-")
    )

    runner = test.Runner(user_input=TEST_IMAGE, golden_report_path=golden_image_report)

    # TODO: use a released version of grype-db
    logging.info(f"using grype-db from main branch")

    db_builder = builder.GrypeDbBuilder()
    grype_obj = grype.Grype(schema_version=schema_version, release=GRYPE_TEST_RELEASE)

    # build set of test cases derived from the grype version and its configured schema versions
    runner.add_case(
        case=test.Case(
            grype=grype_obj, schema_version=schema_version, builder=db_builder
        )
    )

    # build a database for the schema needed
    db_builder.build_and_package(
        db_dir=os.path.join(DB_DIR, str(schema_version)),
        schema_version=schema_version,
        stage_dir=STAGE_DIR,
    )

    # run the test runner (an exception will be raised on failure)
    runner.run()

    logging.info("all DBs generated & passed acceptance testing")
    logging.info(f"staged DB artifacts @ {STAGE_DIR}")



@cli.command()
@click.option("--s3-bucket", required=True, help="S3 bucket to upload the DBs")
@click.option(
    "--s3-path",
    required=True,
    help="base path in the S3 bucket where assets should be uploaded to (DBs and listing files)",
)
@click.option(
    "--dry-run",
    default=False,
    is_flag=True,
    help="do everything except upload the listing file",
)
def upload_listing(s3_bucket: str, s3_path: str, dry_run: bool):
    if not dry_run:
        ensure_running_in_CI()
    else:
        logging.warning(f"DRY-RUN! nothing in S3 will be added or changed")

    # get existing listing file... if does not exist, create new empty listing file
    the_listing = listing.fetch(bucket=s3_bucket, path=s3_path)

    # look for existing DBs in S3
    existing_paths_by_basename = existing_dbs_in_s3(
        s3_bucket=s3_bucket, s3_path=s3_path, suffixes=LEGACY_DB_SUFFIXES,
    )

    # determine what basenames are new relative to the listing file and the current S3 state
    new_basenames, missing_basenames = the_listing.basename_difference(
        set(existing_paths_by_basename.keys()),
    )

    if missing_basenames:
        logging.warning(f"missing {len(missing_basenames)} databases in S3 which were in the existing listing file (removing entries in the next listing file)")
        for basename in missing_basenames:
            logging.warning(f"   {basename}")

    the_listing.remove_by_basename(missing_basenames)

    # add DBs that were discovered in S3 but not already in the listing file
    logging.info(f"discovered {len(new_basenames)} new databases to add to the listing")
    for entry in listing_entries_dbs_in_s3(
            basenames=new_basenames,
            paths_by_basename=existing_paths_by_basename,
            s3_bucket=s3_bucket,
            s3_path=s3_path,
            suffixes=LEGACY_DB_SUFFIXES,
            max_age=MAX_DB_AGE,
    ):
        the_listing.add(entry)

    # prune the listing to the top X many, by schema, sorted by build date
    # note: we do not delete the entries from S3 in case they need to be referenced again
    the_listing.prune(max_age_days=MAX_DB_AGE, minimum_elements=MINIMUM_DB_COUNT)

    # TODO: test out the new listing file with all supported versions of grype
    logging.info("acceptance testing the new listing")
    override_schema_release = None
    if GRYPE_TEST_SCHEMA and GRYPE_TEST_RELEASE:
        override_schema_release = (GRYPE_TEST_SCHEMA, GRYPE_TEST_RELEASE)
    listing.acceptance_test(test_listing=the_listing, image=TEST_IMAGE, override_schema_release=override_schema_release)

    the_listing.log()

    if dry_run:
        logging.warning(f"DRY-RUN! skipping upload...")
        return

    # upload the listing
    s3utils.upload(bucket=s3_bucket,
                   key=the_listing.url(s3_path),
                   contents=the_listing.to_json(),
                   CacheControl="public,max-age=2700")  # type: ignore

    # TODO: for a future PR: add deletion of pruned objects...
    # delete all objects in the bucket that were pruned from the listing
    # for entry in extra:
    #     db_url = urlparse(entry.url, allow_fragments=False)
    #     path = "/".join([path, os.path.basename(db_url.path)])
    #     if not any([path.endswith(s) for s in DB_SUFFIXES]):
    #         raise RuntimeError(f"attempted to delete non-archive: {s3_path}")
    #
    #     s3utils.delete(bucket=s3_bucket, key=s3_path)


def listing_entries_dbs_in_s3(
        basenames: Set[str], paths_by_basename: Dict[str, str], s3_bucket: str, s3_path: str, suffixes: set[str], max_age: int
) -> Generator[listing.Entry, None, None]:
    # generate metadata from each downloaded archive and add to the listing file
    for basename in basenames:
        if not any([basename.endswith(s) for s in suffixes]):
            logging.info(f"    skipping db (unsupported extension) {basename}")
            continue

        age = age_from_basename(basename)
        if age is None or age > max_age:
            logging.info(f"    skipping db (too old -- {age} days) {basename}")
            continue

        s3_existing_path = paths_by_basename[basename]
        logging.info(f"    new db {s3_existing_path}")

        # we don't want to keep around files between processing of each db file, so purge on each iteration
        with tempfile.TemporaryDirectory(prefix="grype-downloaded-db") as tempdir:
            local_path = os.path.join(tempdir, basename)
            s3utils.download_to_file(
                bucket=s3_bucket, key=s3_existing_path, path=local_path
            )

            # derive the checksum from the sha256 of the archive
            checksum = hash_file(path=local_path)

            # extract the metadata from the archive
            meta = metadata.from_archive(path=local_path)

            # create a new listing entry and add it to the listing
            url = "https://{}".format("/".join([s3_bucket, s3_path, basename]))
            url = urlunparse(urlparse(url))  # normalize the url

            yield listing.Entry(
                built=meta.built, version=meta.version, url=url, checksum=checksum
            )


def existing_dbs_in_s3(s3_bucket: str, s3_path: str, suffixes: set[str]) -> Dict[str, str]:
    # list objects in the db bucket path, download all objects not in the listing to a temp dir
    existing_databases = []

    for suffix in suffixes:
        found = list(
            s3utils.get_matching_s3_keys(bucket=s3_bucket, prefix=s3_path, suffix=suffix)
        )
        logging.info(
            f"{len(found)} existing databases in bucket={s3_bucket} path={s3_path} suffix={suffix}"
        )
        existing_databases.extend(found)

    return get_paths_by_basename(existing_databases)


def get_paths_by_basename(paths: List[str]) -> Dict[str, str]:
    paths_by_basename: Dict[str, str] = {}
    for path in paths:
        basename = os.path.basename(path)
        if basename not in paths_by_basename:
            logging.info(f"    existing db {path}")

            paths_by_basename[basename] = path
        else:
            raise RuntimeError(
                f"duplicate basenames found (this should not happen): {basename}"
            )
    return paths_by_basename

def age_from_basename(basename: str) -> Optional[int]:
    fields = basename.split("_")
    if len(fields) < 3:
        return None
    try:
        return (datetime.now(timezone.utc)-iso8601.parse_date(fields[2])).days
    except:
        logging.error(f"unable to parse age from basename {basename}")

def hash_file(path: str) -> str:
    hasher = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            hasher.update(data)

    return "sha256:%s" % hasher.hexdigest()

def ensure_running_in_CI():
    # make certain we are in CI (see https://docs.github.com/en/actions/reference/environment-variables#default-environment-variables)
    if not os.environ.get("CI"):
        raise RuntimeError("This is only intended to run within CI, not in a local development workflow.")
