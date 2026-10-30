from __future__ import annotations

import collections
import json
import logging
import os
import re
import subprocess
import tempfile
from typing import TYPE_CHECKING

from grype_db_manager.db import schema
from grype_db_manager.utils import tool_path

if TYPE_CHECKING:
    from collections.abc import Iterable

Package = collections.namedtuple("Package", "name type version")
Vulnerability = collections.namedtuple("Vulnerability", "id")


class Grype:
    def __init__(self, schema_version: int | str, store_root: str, update_url: str = "", release: str | None = None):
        if isinstance(schema_version, str):
            schema_version = int(schema_version.split(".")[0].removeprefix("v"))
        self.schema_version = schema_version
        if release:
            logging.warning(f"overriding grype release for schema={schema_version!r} with release={release!r}")
            self.release = release
        else:
            self.release = schema.grype_version(schema_version)
        logging.debug(f"using grype release={self.release!r} for schema={schema_version!r}")

        self.env = os.environ.copy()
        self.env.update(
            {
                "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                "GRYPE_DB_VALIDATE_AGE": "false",
                "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_DB_CACHE_DIR": os.path.join(store_root, "db"),
            },
        )
        if update_url:
            self.env["GRYPE_DB_UPDATE_URL"] = update_url

        self.bin = install(self.release, os.path.join(store_root, "bin"))
        self.update_db()

    def update_db(self) -> None:
        subprocess.run([self.bin, "db", "update", "-vv"], env=self.env, check=True)  # noqa: S603

    def run(self, user_input: str) -> str:
        return subprocess.check_output([self.bin, "-o", "json", "-v", user_input], env=self.env).decode("utf-8")  # noqa: S603


def install(release: str, path: str) -> str:
    """the path to a grype binary for the given release (a version tag or branch)"""
    # grype main is installed by binny, anything else is built from source on demand
    binny_grype = tool_path("grype")
    if release == "main" and os.path.exists(binny_grype):
        return binny_grype

    binary = os.path.abspath(os.path.join(path, "grype"))
    logging.info(f"building grype@{release} to {binary!r}")

    # note: "go install ...@<ref>" would be simpler, but it refuses branch names containing a "/"
    env = os.environ.copy()
    env["GOWORK"] = "off"
    with tempfile.TemporaryDirectory(prefix="grype-src-") as src:
        clone = ["git", "clone", "--depth", "1", "--branch", release, "https://github.com/anchore/grype.git", src]
        subprocess.run(clone, check=True)  # noqa: S603, S607
        subprocess.run(["go", "build", "-o", binary, "./cmd/grype"], cwd=src, env=env, check=True)  # noqa: S603, S607
    return binary


class Report:
    def __init__(self, report_contents: str):
        self.report_contents = report_contents

    def _enumerate(self, section: str) -> Iterable[dict]:
        data = json.loads(self.report_contents)

        if section == "matches" and isinstance(data, list):
            # < v0.1.0-beta.10 there was no mapping at the root of the document (so could only support matches info)
            for entry in data:
                yield entry
        else:
            # try the new approach has section names (supported >= v0.1.0-beta.10)
            for entry in data[section]:
                yield entry

    def parse(self) -> tuple[set[Package], set[Vulnerability]]:
        packages = set()
        vulnerabilities = set()
        for entry in self._enumerate(section="matches"):
            # not all versions of grype included epoch in the version, so for comparison it is vital that
            # we do not consider this field of the version at all.
            version = entry["artifact"]["version"]
            if re.match(r"^\d+:", version):
                version = ":".join(version.split(":")[1:])

            package = Package(
                name=entry["artifact"]["name"],
                type=entry["artifact"]["type"],
                version=version,
            )
            vulnerability = Vulnerability(id=entry["vulnerability"]["id"])

            packages.add(package)
            vulnerabilities.add(vulnerability)
        return packages, vulnerabilities
