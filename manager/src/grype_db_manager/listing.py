from __future__ import annotations

import os
import json
import datetime
import logging
import tempfile
import threading
import contextlib
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, urlunparse
from dataclasses import dataclass

import iso8601
from dataclass_wizard import fromdict, asdict

from grype_db_manager import schema, grype, s3utils, distribution

LISTING_FILENAME = "listing.json"


@dataclass
class Entry:
    built: str
    version: int
    url: str
    checksum: str

    def basename(self):
        basename = os.path.basename(urlparse(self.url, allow_fragments=False).path)
        if not has_suffix(basename, suffixes=distribution.DB_SUFFIXES):
            raise RuntimeError(f"entry url is not a db archive: {basename}")

        return basename

    def age(self, now=None):
        if not now:
            now = datetime.datetime.now(tz=datetime.timezone.utc)
        return (now-iso8601.parse_date(self.built)).days


@dataclass
class Listing:
    available: dict[int, list[Entry]]

    @classmethod
    def from_json(cls, contents: str):
        return cls.from_dict(json.loads(contents))

    @classmethod
    def from_dict(cls, contents: dict):
        return fromdict(cls, contents)

    def to_json(self, indent=None):
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_dict(self):
        return asdict(self)

    def prune(self, max_age_days, minimum_elements, now=None):
        for schema_version, entries in self.available.items():
            kept = []
            pruned = []

            if len(entries) <= minimum_elements:
                logging.warning(f"too few entries to prune for schema version {schema_version} ({len(entries)} entries < {minimum_elements})")
                continue

            for entry in entries:
                if entry.age(now) > max_age_days:
                    pruned.append(entry)
                else:
                    kept.append(entry)

            # latest elements are in the back
            pruned.sort(
                key=lambda x: iso8601.parse_date(x.built)
            )

            while len(kept) < minimum_elements and len(pruned) > 0:
                kept.append(pruned.pop())

            # latest elements are in the front
            kept.sort(
                key=lambda x: iso8601.parse_date(x.built),
                reverse=True
            )

            if not pruned:
                logging.debug(f"no entries to prune from schema version {schema_version}")
                continue

            logging.info(f"pruning {len(pruned)} entries from schema version {schema_version}, {len(kept)} entries remain")
            self.available[schema_version] = kept

    def add(self, entry: Entry, quiet: bool = False):
        if not quiet:
            logging.info(f"adding new listing entry: {entry}")

        if not self.available.get(entry.version):
            self.available[entry.version] = []

        self.available[entry.version].append(entry)

        # keep listing entries sorted by date (rfc3339 formatted entries, which iso8601 is a superset of)
        self.available[entry.version].sort(
            key=lambda x: iso8601.parse_date(x.built),
            reverse=True
        )

    def remove_by_basename(self, basenames: set[str], quiet: bool = False):
        if not basenames:
            return

        if not quiet:
            logging.info(f"removing {len(basenames)} from existing listing")

        for version, entries in self.available.items():
            remove = []
            for entry in entries:
                if entry.basename() in basenames:
                    remove.append(entry)
            for entry in remove:
                entries.remove(entry)

    def log(self):
        logging.info(f"listing contents:")
        for schema, entries in self.available.items():
            logging.info(f"  schema: {schema}")
            for entry in entries:
                logging.info(f"    entry: {entry}")

    @staticmethod
    def url(path: str):
        url = os.path.normpath("/".join([path, LISTING_FILENAME]).lstrip("/"))
        return urlunparse(urlparse(url))  # normalize the url

    def basenames(self) -> set[str]:
        names = set()
        for _, entries in self.available.items():
            for entry in entries:
                names.add(entry.basename())
        return names

    def basename_difference(self, other: set[str]) -> (set[str], set[str]):
        basenames = self.basenames()
        new_basenames = other - basenames
        missing_basenames = basenames - other
        return new_basenames, missing_basenames

    def latest(self, schema_version: int) -> Entry:
        return self.available[schema_version][0]


def has_suffix(el: str, suffixes: set[str] | None):
    if not suffixes:
        return True
    for s in suffixes:
        if el.endswith(s):
            return True
    return False


def empty_listing() -> Listing:
    return Listing(available={})


def fetch(bucket: str, path: str, create_if_missing: bool = False) -> Listing:
    if not path or not bucket:
        if create_if_missing:
            logging.warning("no path or bucket specified, creating empty listing")
            return empty_listing()
        else:
            raise ValueError("S3 path and S3 bucket are not specified")

    logging.info(f"fetching existing listing from s3://{bucket}/{path}")
    listing_path = Listing.url(path)
    try:
        listing_contents = s3utils.get_s3_object_contents(
            bucket=bucket, key=listing_path
        )
        if listing_contents:
            logging.info(
                f"discovered existing listing entry bucket={bucket} key={listing_path}"
            )
            return Listing.from_json(listing_contents)

        if create_if_missing:
            logging.warning("could not find existing listing in bucket, assuming empty")
            return empty_listing()
        else:
            raise ValueError(f"could not find existing listing file at s3://{bucket}/{listing_path}")
    except json.decoder.JSONDecodeError:
        logging.error("listing exists, but json parse failed")
        raise


@contextlib.contextmanager
def http_server(directory: str):
    server_address = ("127.0.0.1", 5555)
    url = f"http://{server_address[0]}:{server_address[1]}"
    listing_url = f"{url}/{LISTING_FILENAME}"

    def serve():
        os.chdir(directory)
        httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
        logging.info(f"starting test server at {url}")
        httpd.serve_forever()

    thread = threading.Thread(target=serve)
    thread.daemon = True
    thread.start()
    try:
        yield listing_url
    finally:
        pass


def acceptance_test(test_listing: Listing, image: str, store_root: str, override_schema_release: tuple[str, str] | None = None):
    # write the listing to a temp dir that is served up locally on an HTTP server. This is used by grype to locally
    # download the listing file and check that it works against S3 (since the listing entries have DB urls that
    # reside in S3).
    with tempfile.TemporaryDirectory(prefix="grype-db-acceptance") as tempdir:
        listing_contents = test_listing.to_json()
        # way too verbose!
        # logging.info(listing_contents)
        with open(os.path.join(tempdir, LISTING_FILENAME), "w") as f:
            f.write(listing_contents)  # type: ignore

        # ensure grype can perform a db update for all supported schema versions. Note: we are only testing the
        # listing entry for the DB is usable (the download succeeds and grype and the update process, which does
        # checksum verifications, passes). This test does NOT check the integrity of the DB since that has already
        # been tested in the build steps.
        with http_server(directory=tempdir) as listing_url:
            if override_schema_release:
                override_schema, override_release = override_schema_release
                logging.warning(f"overriding schema={override_schema!r} with release={override_release!r}")
                logging.info(f"testing grype schema-version={override_schema!r}")
                tool_obj = grype.Grype(
                    schema_version=override_schema,
                    store_root=store_root,
                    update_url=listing_url,
                    release=override_release
                )
            else:
                for schema_version in schema.supported_schema_versions():
                    logging.info(f"testing grype schema-version={schema_version!r}")
                    tool_obj = grype.Grype(
                        schema_version=schema_version,
                        store_root=store_root,
                        update_url=listing_url,
                    )

            output = tool_obj.run(user_input=image)
            packages, vulnerabilities = grype.Report(report_contents=output).parse()
            logging.info(f"scan result with downloaded DB: packages={len(packages)} vulnerabilities={len(vulnerabilities)}")
            if not packages or not vulnerabilities:
                raise RuntimeError("validation failed: missing packages and/or vulnerabilities")
