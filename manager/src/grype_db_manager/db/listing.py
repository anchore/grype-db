from __future__ import annotations

import contextlib
import datetime
import functools
import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

import iso8601
from dataclass_wizard import asdict, fromdict

from grype_db_manager import distribution, grype, s3utils
from grype_db_manager.db import schema

if TYPE_CHECKING:
    from collections.abc import Iterator

LISTING_FILENAME = "listing.json"


# Entry is a dataclass that represents a single entry from a listing.json for schemas v1-v5.
@dataclass
class Entry:
    built: str
    version: int
    url: str
    checksum: str

    def basename(self) -> str:
        basename = os.path.basename(urlparse(self.url, allow_fragments=False).path)
        if not has_suffix(basename, suffixes=distribution.DB_SUFFIXES):
            msg = f"entry url is not a db archive: {basename}"
            raise RuntimeError(msg)

        return basename

    def age_in_days(self, now: datetime.datetime | None = None) -> int:
        if not now:
            now = datetime.datetime.now(tz=datetime.timezone.utc)
        return (now - iso8601.parse_date(self.built)).days


# Listing is a dataclass that represents the listing.json for schemas v1-v5.
@dataclass
class Listing:
    available: dict[int, list[Entry]]

    @classmethod
    def from_json(cls, contents: str) -> Listing:
        return cls.from_dict(json.loads(contents))

    @classmethod
    def from_dict(cls, contents: dict) -> Listing:
        return fromdict(cls, contents)

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_dict(self) -> dict:
        return asdict(self)

    def prune(self, max_age_days: int, minimum_elements: int, now: datetime.datetime | None = None) -> None:
        self.sort()

        for schema_version, entries in self.available.items():
            kept = []
            pruned = []

            if len(entries) <= minimum_elements:
                logging.warning(
                    f"too few entries to prune for schema version {schema_version} ({len(entries)} entries < {minimum_elements})",
                )
                continue

            for entry in entries:
                if entry.age_in_days(now) > max_age_days:
                    pruned.append(entry)
                else:
                    kept.append(entry)

            while len(kept) < minimum_elements and len(pruned) > 0:
                kept.append(pruned.pop(0))

            if not pruned:
                logging.debug(f"no entries to prune from schema version {schema_version}")
                continue

            logging.info(f"pruning {len(pruned)} entries from schema version {schema_version}, {len(kept)} entries remain")
            self.available[schema_version] = kept

    def add(self, entry: Entry, quiet: bool = False) -> None:
        if not quiet:
            logging.info(f"adding new listing entry: {entry}")

        if not self.available.get(entry.version):
            self.available[entry.version] = []

        self.available[entry.version].append(entry)

        # keep listing entries sorted by date (rfc3339 formatted entries, which iso8601 is a superset of)
        self.available[entry.version].sort(
            key=lambda x: x.url,
            reverse=True,
        )

    def remove_by_basename(self, basenames: set[str], quiet: bool = False) -> None:
        if not basenames:
            return

        if not quiet:
            logging.info(f"removing {len(basenames)} from existing listing")

        for _version, entries in self.available.items():
            remove = []
            for entry in entries:
                if entry.basename() in basenames:
                    remove.append(entry)
            for entry in remove:
                entries.remove(entry)

    def log(self) -> None:
        logging.info("listing contents:")
        for schema_version, entries in self.available.items():
            logging.info(f"  schema-version: {schema_version}")
            for entry in entries:
                logging.info(f"    entry: {entry}")

    @staticmethod
    def url(path: str, filename: str) -> str:
        url = os.path.normpath("/".join([path, filename]).lstrip("/"))
        return urlunparse(urlparse(url))  # normalize the url

    def basenames(self) -> set[str]:
        names = set()
        for _, entries in self.available.items():
            for entry in entries:
                names.add(entry.basename())
        return names

    def basename_difference(self, other: set[str]) -> tuple[set[str], set[str]]:
        basenames = self.basenames()
        new_basenames = other - basenames
        missing_basenames = basenames - other
        return new_basenames, missing_basenames

    def latest(self, schema_version: int) -> Entry:
        return self.available[schema_version][0]

    def sort(self) -> None:
        for _, v in self.available.items():
            v.sort(key=lambda x: x.url, reverse=True)


def has_suffix(el: str, suffixes: set[str] | None) -> bool:
    if not suffixes:
        return True
    return any(el.endswith(s) for s in suffixes)


def empty_listing() -> Listing:
    return Listing(available={})


def fetch(bucket: str, path: str, filename: str, create_if_missing: bool = False) -> Listing:
    if not path or not bucket:
        if create_if_missing:
            logging.warning("no path or bucket specified, creating empty listing")
            return empty_listing()
        msg = "S3 path and S3 bucket are not specified"
        raise ValueError(msg)

    logging.info(f"fetching existing listing from s3://{bucket}/{path}")
    listing_path = Listing.url(path, filename)
    try:
        listing_contents = s3utils.get_s3_object_contents(
            bucket=bucket,
            key=listing_path,
        )
        if listing_contents:
            logging.info(
                f"discovered existing listing entry bucket={bucket} key={listing_path}",
            )
            return Listing.from_json(listing_contents)

        if create_if_missing:
            logging.warning("could not find existing listing in bucket, assuming empty")
            return empty_listing()
        msg = f"could not find existing listing file at s3://{bucket}/{listing_path}"
        raise ValueError(msg)

    except json.decoder.JSONDecodeError:
        logging.exception("listing exists, but json parse failed")
        raise


@contextlib.contextmanager
def _http_server(directory: str) -> Iterator[str]:
    server_address = ("127.0.0.1", 5555)
    url = f"http://{server_address[0]}:{server_address[1]}"
    listing_url = f"{url}/{LISTING_FILENAME}"

    def serve() -> None:
        httpd = HTTPServer(
            server_address,
            functools.partial(SimpleHTTPRequestHandler, directory=directory),
        )
        logging.info(f"starting test server at {url}")
        httpd.serve_forever()

    thread = threading.Thread(target=serve)
    thread.daemon = True
    thread.start()
    try:
        yield listing_url
    finally:
        pass


def _smoke_test(
    schema_version: str | int,
    listing_url: str,
    image: str,
    minimum_packages: int,
    minimum_vulnerabilities: int,
    store_root: str,
) -> None:
    logging.info(f"testing listing.json grype schema-version={schema_version!r}")
    tool_obj = grype.Grype(
        schema_version=schema_version,
        store_root=store_root,
        update_url=listing_url,
    )

    output = tool_obj.run(user_input=image)
    packages, vulnerabilities = grype.Report(report_contents=output).parse()
    logging.info(f"scan result with downloaded DB: packages={len(packages)} vulnerabilities={len(vulnerabilities)}")
    if not packages or not vulnerabilities:
        msg = "validation failed: missing packages and/or vulnerabilities"
        raise ValueError(msg)

    if len(packages) < minimum_packages:
        msg = f"validation failed: expected at least {minimum_packages} packages, got {len(packages)}"
        raise ValueError(msg)

    if len(vulnerabilities) < minimum_vulnerabilities:
        msg = f"validation failed: expected at least {minimum_vulnerabilities} vulnerabilities, got {len(vulnerabilities)}"
        raise ValueError(msg)


def smoke_test(
    test_listing: Listing,
    image: str,
    minimum_packages: int,
    minimum_vulnerabilities: int,
    override_schema_release: tuple[str, str] | None = None,
) -> None:
    # write the listing to a temp dir that is served up locally on an HTTP server. This is used by grype to locally
    # download the listing file and check that it works against S3 (since the listing entries have DB urls that
    # reside in S3).
    with tempfile.TemporaryDirectory(prefix="grype-db-smoke-test") as tempdir:
        listing_contents = test_listing.to_json()

        installation_path = os.path.join(tempdir, "grype-install")

        # way too verbose!
        logging.info(listing_contents)
        with open(os.path.join(tempdir, LISTING_FILENAME), "w") as f:
            f.write(listing_contents)

        # ensure grype can perform a db update for all supported schema versions. Note: we are only testing the
        # listing entry for the DB is usable (the download succeeds and grype and the update process, which does
        # checksum verifications, passes). This test does NOT check the integrity of the DB since that has already
        # been tested in the build steps.
        with _http_server(directory=tempdir) as listing_url:
            if override_schema_release:
                override_schema, override_release = override_schema_release
                logging.warning(f"overriding schema={override_schema!r} with release={override_release!r}")
                _smoke_test(
                    schema_version=override_schema,
                    listing_url=listing_url,
                    image=image,
                    minimum_packages=minimum_packages,
                    minimum_vulnerabilities=minimum_vulnerabilities,
                    store_root=installation_path,
                )

            else:
                schema_versions = schema.supported_schema_versions()
                # only accept schema versions up through v5
                schema_versions = [s for s in schema_versions if s <= 5]
                logging.info(f"testing all supported schema-versions={schema_versions}")
                for schema_version in schema_versions:
                    _smoke_test(
                        schema_version=schema_version,
                        listing_url=listing_url,
                        image=image,
                        minimum_packages=minimum_packages,
                        minimum_vulnerabilities=minimum_vulnerabilities,
                        store_root=installation_path,
                    )
