from __future__ import annotations

import contextlib
import functools
import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass

# note: this is needed for dataclass loading from json (do not port to a type check block)
from datetime import datetime  # noqa: TC003
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import TYPE_CHECKING

from dataclass_wizard import asdict, fromdict

from grype_db_manager import grype

if TYPE_CHECKING:
    from collections.abc import Iterator

LATEST_FILENAME = "latest.json"


# Latest is a dataclass that represents the latest.json document for schemas v6.
@dataclass
class Latest:
    # status indicates if the database is actively being maintained and distributed
    status: str | None = None

    # schema version of the DB schema
    schema_version: str | None = None

    # timestamp the database was built
    built: datetime | None = None

    # path to a DB archive relative to the listing file hosted location (NOT the absolute URL)
    path: str = ""

    # self-describing digest of the database archive referenced in path
    checksum: str = ""

    @classmethod
    def from_json(cls, contents: str) -> Latest:
        return cls.from_dict(json.loads(contents))

    @classmethod
    def from_dict(cls, contents: dict) -> Latest:
        return fromdict(cls, contents)

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_dict(self) -> dict:
        return asdict(self)


@contextlib.contextmanager
def _http_server(directory: str, schema_version: str) -> Iterator[str]:
    major_version = schema_version.split(".", maxsplit=1)[0].removeprefix("v")
    server_address = ("127.0.0.1", 5555)
    url = f"http://{server_address[0]}:{server_address[1]}"
    latest_url = f"{url}/v{major_version}/{LATEST_FILENAME}"

    def serve() -> None:
        httpd = HTTPServer(
            server_address,
            functools.partial(SimpleHTTPRequestHandler, directory=directory),
        )
        logging.info(f"starting test server at {url!r}")
        # show tree output of the given directory to the log
        _log_dir(directory)

        httpd.serve_forever()

    thread = threading.Thread(target=serve)
    thread.daemon = True
    thread.start()
    try:
        yield latest_url
    finally:
        pass


def _log_dir(path: str, prefix: str = "") -> None:
    items = sorted(os.listdir(path))
    for i, item in enumerate(items):
        is_last = i == len(items) - 1
        connector = "└── " if is_last else "├── "
        logging.info(f"{prefix}{connector}{item}")
        new_prefix = prefix + ("    " if is_last else "│   ")
        item_path = os.path.join(path, item)
        if os.path.isdir(item_path):
            _log_dir(item_path, new_prefix)


def _smoke_test(
    schema_version: str,
    listing_url: str,
    image: str,
    minimum_packages: int,
    minimum_vulnerabilities: int,
    store_root: str,
) -> None:
    logging.info(f"testing latest.json grype schema-version={schema_version!r}")
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
    test_latest: Latest,
    archive_path: str,
    image: str,
    minimum_packages: int,
    minimum_vulnerabilities: int,
) -> None:
    # write the listing to a temp dir that is served up locally on an HTTP server. This is used by grype to locally
    # download the latest.json file and check that it works against S3 (since the listing entries have DB urls that
    # reside in S3).
    with tempfile.TemporaryDirectory(prefix="grype-db-smoke-test") as tempdir:
        listing_contents = test_latest.to_json()

        installation_path = os.path.join(tempdir, "grype-install")

        major_version = test_latest.schema_version.split(".")[0].removeprefix("v")

        sub_path = os.path.join(tempdir, "v" + major_version)
        os.makedirs(sub_path, exist_ok=True)

        logging.info(listing_contents)
        with open(os.path.join(sub_path, LATEST_FILENAME), "w") as f:
            f.write(listing_contents)

        # make the archive available at the expected location via symlink
        archive_dest = os.path.join(sub_path, test_latest.path)
        os.symlink(archive_path, archive_dest)

        # ensure grype can perform a db update for all supported schema versions. Note: we are only testing the
        # latest.json for the DB is usable (the download succeeds and grype and the update process, which does
        # checksum verifications, passes). This test does NOT check the integrity of the DB since that has already
        # been tested in the build steps.
        with _http_server(directory=tempdir, schema_version=test_latest.schema_version) as listing_url:
            _smoke_test(
                schema_version=test_latest.schema_version,
                listing_url=listing_url,
                image=image,
                minimum_packages=minimum_packages,
                minimum_vulnerabilities=minimum_vulnerabilities,
                store_root=installation_path,
            )
