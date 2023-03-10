import os
import re
import json
import logging
import collections
from typing import Tuple, Set, Optional

from yardstick.tool import grype

from publisher.utils.constants import ERROR_DIR, ASSET_DIR
from publisher.utils.repo_root import repo_root


# +/- ratio for matching packages and vulnerabilities
# we know that there could be slight differences in grype output between versions
# and if new vulnerability data is used.
TOLERANCE = 0.1


class Grype:

    BIN = "grype"

    def __init__(self, schema_version: int, update_url: str = "", release: Optional[str] = None):
        self.schema_version = schema_version
        if release:
            logging.warning(f"overriding grype release for schema={schema_version!r} with release={release!r}")
            self.release = release
        else:
            self.release = self.release_version_for_schema_version(schema_version)
        logging.debug(f"using grype release={self.release!r} for schema={schema_version!r}")

        env = {}
        if update_url:
            env["GRYPE_DB_UPDATE_URL"] = update_url
        self.tool = grype.Grype.install(version=self.release, path=os.path.join(ASSET_DIR, self.release), env=env)

    @staticmethod
    def release_version_for_schema_version(schema_version: int):
        path = os.path.join(repo_root(), "grype-schema-version-mapping.json")
        with open(path) as fh:
            obj = json.load(fh)
        return obj[str(schema_version)]

    @staticmethod
    def supported_schema_versions():
        path = os.path.join(repo_root(), "grype-schema-version-mapping.json")
        with open(path) as fh:
            obj = json.load(fh)
        return obj.keys()

    def update_db(self):
        self.tool.run("db", "update", "-vv")

        # ensure the db cache is not empty for the current schema
        check_db_cache_dir(self.schema_version, os.path.join(self.tool.path, "db"))

    def import_db(self, db_path: str):
        self.tool.run("db", "import", db_path)

        # ensure the db cache is not empty for the current schema
        check_db_cache_dir(self.schema_version, os.path.join(self.tool.path, "db"))

    def run(self, user_input: str) -> str:
        return self.tool.run("-o", "json", "-v", user_input)


Package = collections.namedtuple("Package", "name type version")
Vulnerability = collections.namedtuple("Vulnerability", "id")


class Report:
    def __init__(self, report_contents):
        self.report_contents = report_contents

    def _enumerate(self, section):
        try:
            data = json.loads(self.report_contents)
        except Exception as exc:
            os.makedirs(ERROR_DIR, exist_ok=True)
            report_path = os.path.join(ERROR_DIR, "grype-error.json")
            with open(report_path, "w") as f:
                f.write(self.report_contents)

            preview = self.report_contents
            if len(preview) > 100:
                preview = preview[:100] + "..."
            logging.error(
                f"json decode failed, full contents written to: {report_path}\npreview: {preview}", exc_info=exc
            )
            raise

        if section == "matches" and isinstance(data, list):
            # < v0.1.0-beta.10 there was no mapping at the root of the document (so could only support matches info)
            for entry in data:
                yield entry
        else:
            # try the new approach has section names (supported >= v0.1.0-beta.10)
            for entry in data[section]:
                yield entry

    def parse(self) -> Tuple[Set["Package"], Set["Vulnerability"]]:
        packages = set()
        vulnerabilities = set()
        for entry in self._enumerate(section="matches"):
            # not all versions of grype included epoch in the version, so for comparison it is vital that
            # we do not consider this field of the version at all.
            version = entry["artifact"]["version"]
            if re.match(r'^\d+:', version):
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

    def compare(self, other: "Report"):
        my_packages, my_vulnerabilities = self.parse()
        their_packages, their_vulnerabilities = other.parse()

        # this is valid, but suspicious. We should never use a test image with no results. Assume the worst and fail.
        if not their_packages and not my_packages:
            raise RuntimeError("nobody found any packages")

        if len(my_vulnerabilities) == 0 and len(their_vulnerabilities) == 0:
            raise RuntimeError("nobody found any vulnerabilities")

        # find differences in packages
        same_packages = their_packages & my_packages
        percent_overlap_packages = (
            float(len(same_packages)) / float(len(my_packages))
        ) * 100.0

        extra_packages = their_packages - my_packages
        missing_packages = my_packages - their_packages

        # find differences in vulnerabilities
        same_vulnerabilities = their_vulnerabilities & my_vulnerabilities
        percent_overlap_vulnerabilities = (
            float(len(same_vulnerabilities)) / float(len(my_vulnerabilities))
        ) * 100.0

        extra_vulnerabilities = their_vulnerabilities - my_vulnerabilities
        missing_vulnerabilities = my_vulnerabilities - their_vulnerabilities

        if extra_packages:
            logging.error("extra packages: %s" % repr(sorted(list(extra_packages))))

        if len(missing_packages) > 0:
            logging.error("missing packages: %s" % repr(sorted(list(missing_packages))))

        if len(extra_vulnerabilities) > 0:
            logging.error("extra vulnerabilities: %d" % len(extra_vulnerabilities))
            for v in sorted(list(extra_vulnerabilities)):
                print("   ", v)

        if len(missing_vulnerabilities) > 0:
            logging.error("missing vulnerabilities: %d" % len(missing_vulnerabilities))
            for v in sorted(list(missing_vulnerabilities)):
                print("   ", v)

        logging.info(f"baseline packages: {len(my_packages)}")
        logging.info(f"new packages:      {len(their_packages)}")

        logging.info(
            "baseline packages matched: %.2f %% (%d/%d packages)"
            % (percent_overlap_packages, len(same_packages), len(my_packages))
        )
        logging.info(
            "baseline vulnerabilities matched: %.2f %% (%d/%d vulnerabilities)"
            % (
                percent_overlap_vulnerabilities,
                len(same_vulnerabilities),
                len(my_vulnerabilities),
            )
        )

        if not within_tolerance(len(my_packages), len(their_packages)):
            raise RuntimeError(
                "failed quality gate: packages not within tolerance (%d vs %d)"
                % (len(my_packages), len(their_packages))
            )

        if not within_tolerance(len(my_vulnerabilities), len(their_vulnerabilities)):
            raise RuntimeError(
                "failed quality gate: vulnerabilities not within tolerance (%d vs %d)"
                % (len(my_vulnerabilities), len(their_vulnerabilities))
            )


def within_tolerance(under_test, golden, tolerance=TOLERANCE):
    return golden * (1 - tolerance) <= under_test <= golden * (1 + tolerance)


def check_db_cache_dir(schema_version, db_runtime_dir):
    """
    Ensure that there is a `metadata.json` file for the cache directory, which signals that there
    are files related to a database pull
    """
    # ensure the db cache is not empty for the current schema
    if schema_version == "1":
        # older grype versions do not support schema-based cache directories
        db_metadata_file = os.path.join(db_runtime_dir, "metadata.json")
    else:
        db_metadata_file = os.path.join(db_runtime_dir, schema_version, "metadata.json")

    if os.path.exists(db_metadata_file):
        # the metadata.json file exists and grype will be able to work with it
        return

    logging.error(f"db_runtime_dir: {db_runtime_dir}")
    logging.error(
        f"db import appears to have failed, was expecting path: {db_metadata_file}"
    )
    logging.error("db runtime directory has these files: ")
    for _f in os.listdir(db_runtime_dir):
        logging.error(f"{_f}")

    raise RuntimeError(
        "db import appears to have failed, was expecting path: %s" % db_metadata_file
    )
