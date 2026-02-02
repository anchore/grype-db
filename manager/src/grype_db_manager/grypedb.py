from __future__ import annotations

import dataclasses
import datetime
import glob
import json
import logging
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import uuid

import requests
import xxhash

from grype_db_manager.db.format import Format

TOOLS_DIR = "tools"
BIN_DIR = f"{TOOLS_DIR}/grype-db/bin"
CLONE_DIR = f"{TOOLS_DIR}/grype-db/src"
DB_DIR = "dbs"

# TODO:
# - add tests for GrypeDB.install*

# these are the minimum expected namespaces that should be present in the DB based on the v4+ schema.
# TODO: ideally this would be coupled to the definitions defined in the vunnel quality gate config file
# https://github.com/anchore/vunnel/blob/v0.17.2/tests/quality/config.yaml#L53
# however, its important to use the file for the same version of vunnel used by grype-db to build the DB, which
# isn't always possible to know. Ideally this version info would be captured in the vunnel data directory directly.
# For the meantime this is a snapshot of the expected namespaces for vunnel 0.17.2 in Oct 2023 (boo! 👻).
v5_additional_namespaces = [
    "mariner:distro:azurelinux:3.0",
]

v4_expected_namespaces = [
    "alpine:distro:alpine:3.10",
    "alpine:distro:alpine:3.11",
    "alpine:distro:alpine:3.12",
    "alpine:distro:alpine:3.13",
    "alpine:distro:alpine:3.14",
    "alpine:distro:alpine:3.15",
    "alpine:distro:alpine:3.16",
    "alpine:distro:alpine:3.17",
    "alpine:distro:alpine:3.18",
    "alpine:distro:alpine:3.2",
    "alpine:distro:alpine:3.3",
    "alpine:distro:alpine:3.4",
    "alpine:distro:alpine:3.5",
    "alpine:distro:alpine:3.6",
    "alpine:distro:alpine:3.7",
    "alpine:distro:alpine:3.8",
    "alpine:distro:alpine:3.9",
    "alpine:distro:alpine:edge",
    "amazon:distro:amazonlinux:2",
    "amazon:distro:amazonlinux:2022",
    "amazon:distro:amazonlinux:2023",
    "chainguard:distro:chainguard:rolling",
    "debian:distro:debian:10",
    "debian:distro:debian:11",
    "debian:distro:debian:12",
    "debian:distro:debian:13",
    "debian:distro:debian:7",
    "debian:distro:debian:8",
    "debian:distro:debian:9",
    "debian:distro:debian:unstable",
    "github:language:dart",
    "github:language:dotnet",
    "github:language:go",
    "github:language:java",
    "github:language:javascript",
    "github:language:php",
    "github:language:python",
    "github:language:ruby",
    "github:language:rust",
    "github:language:swift",
    "mariner:distro:mariner:1.0",
    "mariner:distro:mariner:2.0",
    # "minimos:distro:minimos:rolling",
    "nvd:cpe",
    "oracle:distro:oraclelinux:5",
    "oracle:distro:oraclelinux:6",
    "oracle:distro:oraclelinux:7",
    "oracle:distro:oraclelinux:8",
    "oracle:distro:oraclelinux:9",
    "redhat:distro:redhat:5",
    "redhat:distro:redhat:6",
    "redhat:distro:redhat:7",
    "redhat:distro:redhat:8",
    "redhat:distro:redhat:9",
    "sles:distro:sles:11",
    "sles:distro:sles:11.1",
    "sles:distro:sles:11.2",
    "sles:distro:sles:11.3",
    "sles:distro:sles:11.4",
    "sles:distro:sles:12",
    "sles:distro:sles:12.1",
    "sles:distro:sles:12.2",
    "sles:distro:sles:12.3",
    "sles:distro:sles:12.4",
    "sles:distro:sles:12.5",
    "sles:distro:sles:15",
    "sles:distro:sles:15.1",
    "sles:distro:sles:15.2",
    "sles:distro:sles:15.3",
    "sles:distro:sles:15.4",
    "sles:distro:sles:15.5",
    "ubuntu:distro:ubuntu:12.04",
    "ubuntu:distro:ubuntu:12.10",
    "ubuntu:distro:ubuntu:13.04",
    "ubuntu:distro:ubuntu:14.04",
    "ubuntu:distro:ubuntu:14.10",
    "ubuntu:distro:ubuntu:15.04",
    "ubuntu:distro:ubuntu:15.10",
    "ubuntu:distro:ubuntu:16.04",
    "ubuntu:distro:ubuntu:16.10",
    "ubuntu:distro:ubuntu:17.04",
    "ubuntu:distro:ubuntu:17.10",
    "ubuntu:distro:ubuntu:18.04",
    "ubuntu:distro:ubuntu:18.10",
    "ubuntu:distro:ubuntu:19.04",
    "ubuntu:distro:ubuntu:19.10",
    "ubuntu:distro:ubuntu:20.04",
    "ubuntu:distro:ubuntu:20.10",
    "ubuntu:distro:ubuntu:21.04",
    "ubuntu:distro:ubuntu:21.10",
    "ubuntu:distro:ubuntu:22.04",
    "ubuntu:distro:ubuntu:22.10",
    "ubuntu:distro:ubuntu:23.04",
    "ubuntu:distro:ubuntu:23.10",
    "ubuntu:distro:ubuntu:24.04",
    "wolfi:distro:wolfi:rolling",
]


def expected_namespaces(schema_version: int) -> list[str]:
    if schema_version < 5:
        msg = f"schema {schema_version} is EOL. v5 is latest supported version"
        raise ValueError(msg)
    return v4_expected_namespaces + v5_additional_namespaces


@dataclasses.dataclass
class DBInfo:
    uuid: str
    schema_version: int
    db_checksum: str
    db_created: datetime.datetime
    data_created: datetime.datetime
    archive_path: str
    latest_path: str | None = None


class DBInvalidException(Exception):
    pass


class DBNamespaceException(Exception):
    pass


class DBProviderException(Exception):
    pass


class DBManager:
    def __init__(self, root_dir: str):
        self.db_dir = os.path.join(root_dir, DB_DIR)

    def db_paths(self, db_uuid: str) -> tuple[str, str]:
        session_dir = os.path.join(self.db_dir, db_uuid)
        stage_dir = os.path.join(session_dir, "stage")
        build_dir = os.path.join(session_dir, "build")
        return stage_dir, build_dir

    def new_session(self) -> str:
        db_uuid = str(uuid.uuid4())

        stage_dir, build_dir = self.db_paths(db_uuid)

        os.makedirs(stage_dir)
        os.makedirs(build_dir)

        session_dir = os.path.join(self.db_dir, db_uuid)
        with open(os.path.join(session_dir, "timestamp"), "w") as f:
            now = datetime.datetime.now(tz=datetime.UTC)
            f.write(now.isoformat())

        return db_uuid

    def list_providers(self, db_uuid: str) -> list[str]:
        _, build_dir = self.db_paths(db_uuid=db_uuid)
        # a sqlite3 db
        db_path = os.path.join(build_dir, "vulnerability.db")

        # select distinct values in the "namespace" column of the "vulnerability" table
        con = sqlite3.connect(db_path)
        crsr = con.cursor()
        crsr.execute("SELECT DISTINCT id FROM providers")
        result = crsr.fetchall()
        con.close()

        return sorted([r[0] for r in result])

    def list_namespaces(self, db_uuid: str) -> list[str]:
        _, build_dir = self.db_paths(db_uuid=db_uuid)
        # a sqlite3 db
        db_path = os.path.join(build_dir, "vulnerability.db")

        # check if there is a metadata.json file in the build directory
        metadata_path = os.path.join(build_dir, "metadata.json")
        if not os.path.exists(metadata_path):
            msg = f"missing metadata.json for DB {db_uuid!r}"
            raise DBInvalidException(msg)

        # select distinct values in the "namespace" column of the "vulnerability" table
        con = sqlite3.connect(db_path)
        crsr = con.cursor()
        crsr.execute("SELECT DISTINCT namespace FROM vulnerability")
        result = crsr.fetchall()
        con.close()

        return sorted([r[0] for r in result])

    def validate_providers(self, db_uuid: str, expected: list[str]) -> None:
        if not expected:
            msg = "expected at least one provider"
            raise DBProviderException(msg)

        missing_providers = set(expected) - set(self.list_providers(db_uuid=db_uuid))

        if missing_providers:
            msg = f"missing providers in DB {db_uuid!r}: {sorted(missing_providers)!r}"
            raise DBProviderException(msg)

        logging.info(f"minimum expected providers present in {db_uuid!r}")

    def validate_namespaces(self, db_uuid: str) -> None:
        db_info = self.get_db_info(db_uuid)
        expected = expected_namespaces(db_info.schema_version)
        missing_namespaces = set(expected) - set(self.list_namespaces(db_uuid=db_uuid))

        if missing_namespaces:
            msg = f"missing namespaces in DB {db_uuid!r}: {sorted(missing_namespaces)!r}"
            raise DBNamespaceException(msg)

        logging.info(f"minimum expected namespaces present in {db_uuid!r}")

    def get_db_info(self, db_uuid: str) -> DBInfo | None:
        session_dir = os.path.join(self.db_dir, db_uuid)
        if not os.path.exists(session_dir):
            msg = f"path does not exist: {session_dir!r}"
            raise DBInvalidException(msg)

        # get the created timestamp
        db_created_timestamp = None
        timestamp_path = os.path.join(session_dir, "timestamp")
        if os.path.exists(timestamp_path):
            with open(timestamp_path) as f:
                db_created_timestamp = datetime.datetime.fromisoformat(f.read())

        # read info from the metadata file in build/metadata.json (v1 - v5) or build/latest.json (v6+)
        metadata = db_metadata(build_dir=os.path.join(session_dir, "build"))

        stage_dir, _ = self.db_paths(db_uuid=db_uuid)
        db_pattern = os.path.join(
            stage_dir,
            "vulnerability-db*.tar.*",
        )

        matches = glob.glob(db_pattern)
        if not matches:
            msg = f"db archive not found for {db_uuid!r}"
            raise DBInvalidException(msg)
        if len(matches) > 1:
            msg = f"multiple db archives found for {db_uuid!r}"
            raise DBInvalidException(msg)

        abs_archive_path = os.path.abspath(matches[0])

        db_created = db_created_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        if "db_created" in metadata:
            db_created = metadata["db_created"]

        return DBInfo(
            uuid=db_uuid,
            schema_version=metadata["version"],
            db_checksum=metadata["db_checksum"],
            db_created=db_created,
            data_created=metadata["data_created"],
            archive_path=abs_archive_path,
            latest_path=metadata.get("latest_path", None),
        )

    def list_dbs(self) -> list[DBInfo]:
        if not os.path.exists(self.db_dir):
            return []

        db_uuids = os.listdir(self.db_dir)
        sessions = []
        for db_uuid in db_uuids:
            try:
                info = self.get_db_info(db_uuid=db_uuid)
                if info:
                    sessions.append(info)
            except DBInvalidException as e:
                logging.debug(f"failed to get info for session {db_uuid!r}: {e}")

        return sorted(sessions, key=lambda x: x.db_created)

    def remove_db(self, db_uuid: str) -> bool:
        session_dir = os.path.join(self.db_dir, db_uuid)
        if os.path.exists(session_dir):
            shutil.rmtree(session_dir)
            return True
        return False


def db_metadata(build_dir: str) -> dict:
    metadata_path = os.path.join(build_dir, "metadata.json")

    if os.path.exists(metadata_path):
        # supports v1 - v5
        with open(metadata_path) as f:
            metadata = json.load(f)
            return {
                "version": int(metadata["version"]),
                "db_checksum": metadata["checksum"],
                "data_created": metadata["built"],
            }

    db_path = os.path.join(build_dir, "vulnerability.db")
    if not os.path.exists(db_path):
        msg = "missing vulnerability.db for DB"
        raise DBInvalidException(msg)

    db_checksum = xxhash.xxh64()
    with open(db_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            db_checksum.update(chunk)

    latest_path = os.path.join(build_dir, "latest.json")
    if os.path.exists(latest_path):
        # supports v6+
        with open(latest_path) as f:
            metadata = json.load(f)
            # example data:
            # {
            #  "status": "active",
            #  "schemaVersion": "v6.0.0",
            #  "built": "2024-11-26T20:24:24Z",
            #  "path": "vulnerability-db_v6.0.0_2024-11-25T01:31:56Z_1732652663.tar.zst",
            #  "checksum": "sha256:1a0ec0ba815083d0ef50790c8c94307c822fd7d09632dee9c3edb6bf5a58e6ff"
            # }
            return {
                "version": int(metadata["schemaVersion"].split(".")[0].removeprefix("v")),
                "db_checksum": "xxh64:" + db_checksum.hexdigest(),
                "db_created": metadata["built"],
                "data_created": parse_datetime(metadata["path"].split("_")[2]),
                "latest_path": os.path.abspath(latest_path),
            }

    msg = "missing metadata.json and latest.json for DB"
    raise DBInvalidException(msg)


def parse_datetime(s: str) -> datetime.datetime:
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.UTC)


class GrypeDB:
    def __init__(self, bin_path: str, config_path: str = ""):
        if bin_path:
            self.version = os.path.basename(bin_path).removeprefix("grype-db-")
        else:
            logging.info("using existing grype-db that is on path")
            self.version = ""

        self.bin_path = bin_path
        self.config_path = config_path

    @classmethod
    def list_installed(cls, root_dir: str) -> list[GrypeDB]:
        bin_dir = os.path.join(root_dir, BIN_DIR)
        os.makedirs(bin_dir, exist_ok=True)

        if not os.path.exists(bin_dir):
            return []

        bins = []
        for bin_name in sorted(os.listdir(bin_dir)):
            if bin_name.startswith("grype-db-"):
                bins.append(cls(bin_path=os.path.join(bin_dir, bin_name)))
        return bins

    @classmethod
    def install(cls, version: str, config_path: str, root_dir: str) -> GrypeDB:
        bin_path = None
        if version != "disabled":
            bin_path = _install_grype_db(
                input_version=version,
                bin_dir=os.path.join(root_dir, BIN_DIR),
                clone_dir=os.path.join(root_dir, CLONE_DIR),
            )

        return cls(bin_path=bin_path, config_path=config_path)

    def build_and_package(self, schema_version: int, provider_root_dir: str, root_dir: str) -> str:
        db_manager = DBManager(root_dir=root_dir)
        db_uuid = db_manager.new_session()

        logging.info(f"building DB schema={schema_version} db-session={db_uuid!r}")

        stage_dir, build_dir = db_manager.db_paths(db_uuid=db_uuid)

        # generate a new DB archive
        self.build_db(build_dir=build_dir, schema_version=schema_version, provider_root_dir=provider_root_dir)
        self.package_db(build_dir=build_dir, provider_root_dir=provider_root_dir)

        db_pattern = os.path.join(
            build_dir,
            f"*_v{schema_version}[._]*.tar.*",
        )

        matches = glob.glob(db_pattern)
        if len(matches) != 1:
            logging.error(f"no db file matches found: {matches}")
            msg = "failed to build db"
            raise RuntimeError(msg)

        logging.info(f"db archive created: {matches[0]}")

        # move the build db archive to the staging dir
        dest = os.path.join(stage_dir, os.path.basename(matches[0]))
        logging.info(f"promoting db archive to {dest}")
        shutil.move(matches[0], dest)

        return db_uuid

    def build_db(self, build_dir: str, schema_version: int, provider_root_dir: str) -> None:
        self.run(
            "build",
            "--schema",
            str(schema_version),
            "--dir",
            build_dir,
            provider_root_dir=provider_root_dir,
            config=self.config_path,
        )

    def package_db(self, build_dir: str, provider_root_dir: str) -> None:
        self.run(
            "package",
            "--dir",
            build_dir,
            provider_root_dir=provider_root_dir,
            config=self.config_path,
        )

    def run(self, *args, provider_root_dir: str, config: str) -> int:
        cmd = [self.bin_path, *args] if self.bin_path else ["grype-db", *args]
        level = logging.getLevelName(logging.getLogger().getEffectiveLevel())
        if level == "TRACE":
            # trace is not supported in grype-db yet
            level = "DEBUG"

        logging.info(f"running (log-level={level}) {cmd!r}")
        print_annotation("[begin grype-db output]")

        env = dict(  # noqa: PIE804
            **os.environ.copy(),
            GRYPE_DB_VUNNEL_ROOT=provider_root_dir,
            GRYPE_DB_CONFIG=config,
            GRYPE_DB_LOG_LEVEL=level,
        )

        ret = subprocess.check_call(cmd, env=env)  # noqa: S603

        print_annotation("[end grype-db output]")
        return ret


def print_annotation(s: str, italic: bool = True, grey: bool = True) -> None:
    prefix = ""
    if italic:
        prefix += str(Format.ITALIC)
    if grey:
        prefix += str(Format.GREY)
    if prefix and sys.stderr.isatty():
        s = f"{prefix}{s}{Format.RESET}"
    sys.stderr.write(s + "\n")


def _check_executable_path_override() -> str | None:
    """Check for existing grype-db binary via GRYPE_DB_EXECUTABLE_PATH environment variable."""
    if grype_db_path := os.getenv("GRYPE_DB_EXECUTABLE_PATH"):
        if shutil.which(grype_db_path):
            logging.info(f"Using grype-db from GRYPE_DB_EXECUTABLE_PATH: {grype_db_path}")
            return grype_db_path
        logging.warning(f"GRYPE_DB_EXECUTABLE_PATH points to non-executable: {grype_db_path}")
    return None


def _install_grype_db(input_version: str, bin_dir: str, clone_dir: str) -> str:  # noqa: PLR0912, C901
    """
    Install grype-db CLI from a specified version.

    This can be a specific semver version (e.g. v0.7.0), "latest", a GitHub repo (e.g. user/repo or user/repo@branch),
    or a local file path (e.g. file:///path/to/grype-db).
    If an environment variable GRYPE_DB_EXECUTABLE_PATH is set and points to an executable, that binary will be used instead.

    Args:
        input_version (str): The version or source to install from.
        bin_dir (str): The directory to install the binary into.
        clone_dir (str): The directory to clone the repository into if needed.

    Returns:
        str | None: The path to the installed binary, or None if no installation was performed.

    """
    if not input_version:
        msg = "grype-db version is required (set grype_db.version in config)"
        raise ValueError(msg)

    os.makedirs(bin_dir, exist_ok=True)

    # Check for explicit grype-db binary override (opt-in only)
    if existing_binary := _check_executable_path_override():
        return existing_binary

    version = input_version
    is_semver = re.match(r"v\d+\.\d+\.\d+", input_version)
    repo_user_and_name = "anchore/grype-db"
    using_local_file = input_version.startswith("file://")

    if using_local_file:
        clone_dir = os.path.expanduser(input_version.replace("file://", ""))
    else:  # noqa: PLR5501
        if "/" in input_version:
            # this is a fork...
            if "@" in input_version:
                # ... with a branch specification
                repo_user_and_name, version = input_version.split("@")
            else:
                repo_user_and_name = input_version
                version = "main"

    repo_url = f"https://github.com/{repo_user_and_name}"

    if input_version == "latest":
        version = (
            requests.get(
                "https://github.com/anchore/grype-db/releases/latest",
                headers={"Accept": "application/json"},
                timeout=10,
            )
            .json()
            .get("tag_name", "")
        )
        logging.info(f"latest released grype-db version is {version!r}")

    elif is_semver:
        install_version = version
        bin_path = os.path.join(bin_dir, _grype_db_bin_name(install_version))
        if os.path.exists(bin_path):
            existing_version = (
                subprocess.check_output([bin_path, "--version"]).decode("utf-8").strip().split(" ")[-1]  # noqa: S603
            )
            if existing_version == install_version:
                if "dirty" in install_version:
                    logging.info(
                        f"grype-db already installed at version {install_version!r}, but was from dirty git state. Rebuilding...",
                    )
                else:
                    logging.info(f"grype-db already installed at version {install_version!r}")
                    return None
            else:
                logging.warning(
                    f"found existing grype-db installation with mismatched version: existing={existing_version!r} vs installed={install_version!r}",
                )
        else:
            logging.debug(f"cannot find existing grype-db installation at version {install_version!r}")

    if using_local_file:
        return _install_from_user_source(bin_dir=bin_dir, clone_dir=clone_dir)

    return _install_from_clone(
        bin_dir=bin_dir,
        checkout=version,
        clone_dir=clone_dir,
        repo_url=repo_url,
        repo_user_and_name=repo_user_and_name,
    )


def _install_from_clone(bin_dir: str, checkout: str, clone_dir: str, repo_url: str, repo_user_and_name: str) -> str:
    logging.info(f"creating grype-db repo at {clone_dir!r}")

    if os.path.exists(clone_dir):
        remote_url = (
            subprocess.check_output(["git", "remote", "get-url", "origin"], cwd=clone_dir).decode().strip()  # noqa: S603, S607
        )
        if not remote_url.endswith(repo_user_and_name) or remote_url.endswith(repo_user_and_name + ".git"):
            logging.info(f"removing grype-db clone at {clone_dir!r} because remote url does not match {repo_url!r}")
            shutil.rmtree(clone_dir)

    if not os.path.exists(clone_dir):
        subprocess.run(["git", "clone", repo_url, clone_dir], env={"GIT_LFS_SKIP_SMUDGE": "1"}, check=True)  # noqa: S603, S607
    else:
        subprocess.run(["git", "fetch", "--all"], env={"GIT_LFS_SKIP_SMUDGE": "1"}, cwd=clone_dir, check=True)  # noqa: S603, S607

    subprocess.run(["git", "checkout", checkout], env={"GIT_LFS_SKIP_SMUDGE": "1"}, cwd=clone_dir, check=True)  # noqa: S603, S607

    install_version = (
        subprocess.check_output(["git", "describe", "--always", "--tags", "--dirty"], cwd=clone_dir)  # noqa: S603, S607
        .decode("utf-8")
        .strip()
    )

    return _build_grype_db(bin_dir=bin_dir, install_version=install_version, clone_dir=clone_dir)


def _install_from_user_source(bin_dir: str, clone_dir: str) -> str:
    abs_clone_path = os.path.abspath(clone_dir)
    logging.info(f"using user grype-db repo at {clone_dir!r} ({abs_clone_path!r})")
    install_version = (
        subprocess.check_output(["git", "describe", "--always", "--tags", "--dirty"], cwd=abs_clone_path)  # noqa: S603, S607
        .decode("utf-8")
        .strip()
    )
    return _build_grype_db(bin_dir=bin_dir, install_version=install_version, clone_dir=abs_clone_path)


def _build_grype_db(bin_dir: str, install_version: str, clone_dir: str) -> str:
    logging.info(f"installing grype-db at version {install_version!r}")

    bin_name = f"grype-db-{install_version}"
    abs_bin_dir_path = os.path.abspath(bin_dir)
    bin_path = os.path.join(abs_bin_dir_path, bin_name)

    pkg_path = "./cmd/grype-db"
    if not os.path.exists(os.path.join(clone_dir, pkg_path)):
        pkg_path = "."

    ld_flags = f"-ldflags=\"-X 'github.com/anchore/grype-db/cmd/grype-db/application.version={install_version}'\""
    cmd = f"go build -v {ld_flags} -o {bin_path} {pkg_path}"

    logging.info(f"building grype-db: {cmd}")

    subprocess.run(shlex.split(cmd), cwd=clone_dir, env=os.environ, check=True)  # noqa: S603, S607

    return bin_path


def _grype_db_bin_name(install_version: str) -> str:
    return f"grype-db-{install_version}"
