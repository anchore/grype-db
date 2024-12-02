from __future__ import annotations

import collections
import json
import logging
import os
import re
from typing import TYPE_CHECKING

from yardstick.tool import grype

from grype_db_manager.db import schema
from grype_db_manager.utils import repo_root

if TYPE_CHECKING:
    from collections.abc import Iterable

Package = collections.namedtuple("Package", "name type version")
Vulnerability = collections.namedtuple("Vulnerability", "id")


class Grype:
    BIN = "grype"

    def __init__(self, schema_version: int | str, store_root: str, update_url: str = "", release: str | None = None):
        if isinstance(schema_version, str):
            schema_version = int(schema_version.split(".")[0])
        self.schema_version = schema_version
        if release:
            logging.warning(f"overriding grype release for schema={schema_version!r} with release={release!r}")
            self.release = release
        else:
            self.release = schema.grype_version(schema_version)
        logging.debug(f"using grype release={self.release!r} for schema={schema_version!r}")

        env = self._env()
        if update_url:
            env["GRYPE_DB_UPDATE_URL"] = update_url
        self.tool = grype.Grype.install(version=self.release, path=os.path.join(store_root, self.release), env=env)

    @staticmethod
    def supported_schema_versions() -> list[str]:
        path = os.path.join(repo_root(), "grype-schema-version-mapping.json")
        with open(path) as fh:
            obj = json.load(fh)
        return obj.keys()

    def _env(self, env: dict[str, str] | None = None) -> dict[str, str]:
        if not env:
            env = os.environ.copy()
        if self.schema_version >= 6:
            env.update(
                {
                    "GRYPE_EXP_DBV6": "true",
                },
            )
        return env

    def update_db(self) -> None:
        self.tool.run("db", "update", "-vv", env=self._env())

        # ensure the db cache is not empty for the current schema
        check_db_cache_dir(self.schema_version, os.path.join(self.tool.path, "db"))

    def import_db(self, db_path: str) -> None:
        self.tool.run("db", "import", db_path, env=self._env())

        # ensure the db cache is not empty for the current schema
        check_db_cache_dir(self.schema_version, os.path.join(self.tool.path, "db"))

    def run(self, user_input: str) -> str:
        return self.tool.run("-o", "json", "-v", user_input, env=self._env())


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


def check_db_cache_dir(schema_version: int, db_runtime_dir: str) -> None:
    """
    Ensure that there is a `metadata.json` file for the cache directory, which signals that there
    are files related to a database pull
    """
    # ensure the db cache is not empty for the current schema
    if schema_version == 1:
        # older grype versions do not support schema-based cache directories
        db_metadata_file = os.path.join(db_runtime_dir, "metadata.json")
    else:
        db_metadata_file = os.path.join(db_runtime_dir, str(schema_version), "metadata.json")

    if os.path.exists(db_metadata_file):
        # the metadata.json file exists and grype will be able to work with it
        return

    logging.error(f"db_runtime_dir: {db_runtime_dir}")
    logging.error(
        f"db import appears to have failed, was expecting path: {db_metadata_file}",
    )
    logging.error("db runtime directory has these files: ")
    for _f in os.listdir(db_runtime_dir):
        logging.error(f"{_f}")

    raise RuntimeError(
        "db import appears to have failed, was expecting path: %s" % db_metadata_file,
    )
