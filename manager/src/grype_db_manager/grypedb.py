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
import subprocess
import sys
import uuid

import requests

from grype_db_manager.format import Format

TOOLS_DIR = "tools"
BIN_DIR = f"{TOOLS_DIR}/grype-db/bin"
CLONE_DIR = f"{TOOLS_DIR}/grype-db/src"
DB_DIR = "dbs"

# TODO:
# - add tests for GrypeDB.install*


@dataclasses.dataclass
class DBInfo:
    session_id: str
    schema_version: int
    db_checksum: str
    db_created: datetime.datetime
    data_created: datetime.datetime
    archive_path: str


class DBInvalidException(Exception):
    pass


class DBManager:
    def __init__(self, root_dir: str):
        self.db_dir = os.path.join(root_dir, DB_DIR)

    def db_paths(self, session_id: str) -> tuple[str, str]:
        session_dir = os.path.join(self.db_dir, session_id)
        stage_dir = os.path.join(session_dir, "stage")
        build_dir = os.path.join(session_dir, "build")
        return stage_dir, build_dir

    def new_session(self) -> str:
        session_id = str(uuid.uuid4())

        stage_dir, build_dir = self.db_paths(session_id)

        os.makedirs(stage_dir)
        os.makedirs(build_dir)

        session_dir = os.path.join(self.db_dir, session_id)
        with open(os.path.join(session_dir, "timestamp"), "w") as f:
            now = datetime.datetime.now(tz=datetime.timezone.utc)
            f.write(now.isoformat())

        return session_id

    def get_db_info(self, session_id: str, allow_missing_archive: bool = False) -> DBInfo | None:
        session_dir = os.path.join(self.db_dir, session_id)
        if not os.path.exists(session_dir):
            raise DBInvalidException(f"path does not exist: {session_dir!r}")

        # get the created timestamp
        db_created_timestamp = None
        timestamp_path = os.path.join(session_dir, "timestamp")
        if os.path.exists(timestamp_path):
            with open(timestamp_path) as f:
                db_created_timestamp = datetime.datetime.fromisoformat(f.read())

        # read info from the metadata file in build/metadata.json
        metadata_path = os.path.join(session_dir, "build", "metadata.json")
        if not os.path.exists(metadata_path):
            raise DBInvalidException(f"missing metadata.json for session {session_id!r}")

        with open(metadata_path) as f:
            metadata = json.load(f)

        stage_dir, _ = self.db_paths(session_id=session_id)
        db_pattern = os.path.join(
            stage_dir,
            "vulnerability-db*.tar.*",
        )

        matches = glob.glob(db_pattern)
        if not matches:
            raise DBInvalidException(f"db archive not found for {session_id!r}")
        if len(matches) > 1:
            raise DBInvalidException(f"multiple db archives found for {session_id!r}")

        abs_archive_path = os.path.abspath(matches[0])

        return DBInfo(
            session_id=session_id,
            schema_version=metadata["version"],
            db_checksum=metadata["checksum"],
            db_created=db_created_timestamp,
            data_created=metadata["built"],
            archive_path=abs_archive_path,
        )

    def list_dbs(self) -> list[DBInfo]:
        if not os.path.exists(self.db_dir):
            return []

        session_ids = os.listdir(self.db_dir)
        sessions = []
        for session_id in session_ids:
            try:
                info = self.get_db_info(session_id=session_id)
                if info:
                    sessions.append(info)
            except DBInvalidException as e:
                logging.debug(f"failed to get info for session {session_id!r}: {e}")

        return sessions


class GrypeDB:
    def __init__(self, bin_path: str, config_path: str = ""):
        self.version = os.path.basename(bin_path).removeprefix("grype-db-")
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
        bin_path = _install_grype_db(
            input_version=version,
            bin_dir=os.path.join(root_dir, BIN_DIR),
            clone_dir=os.path.join(root_dir, CLONE_DIR),
        )
        return cls(bin_path=bin_path, config_path=config_path)

    def build_and_package(self, schema_version: int, provider_root_dir: str, root_dir: str) -> str:
        db_manager = DBManager(root_dir=root_dir)
        session_id = db_manager.new_session()

        logging.info(f"building DB schema={schema_version} db-session={session_id!r}")

        stage_dir, build_dir = db_manager.db_paths(session_id=session_id)

        # generate a new DB archive
        self.build_db(build_dir=build_dir, schema_version=schema_version, provider_root_dir=provider_root_dir)
        self.package_db(build_dir=build_dir, provider_root_dir=provider_root_dir)

        db_pattern = os.path.join(
            build_dir,
            f"*_v{schema_version}_*.tar.*",
        )

        matches = glob.glob(db_pattern)
        if len(matches) != 1:
            logging.error(f"no db file matches found: {matches}")
            raise RuntimeError("failed to build db")

        logging.info(f"db archive created: {matches[0]}")

        # move the build db archive to the staging dir
        dest = os.path.join(stage_dir, os.path.basename(matches[0]))
        logging.info(f"promoting db archive to {dest}")
        shutil.move(matches[0], dest)

        return session_id

    def build_db(self, build_dir: str, schema_version: int, provider_root_dir: str):
        self.run(
            "build",
            "--schema",
            str(schema_version),
            "--dir",
            build_dir,
            provider_root_dir=provider_root_dir,
            config=self.config_path,
        )

    def package_db(self, build_dir: str, provider_root_dir: str):
        self.run(
            "package",
            "--dir",
            build_dir,
            provider_root_dir=provider_root_dir,
            config=self.config_path,
        )

    def run(self, *args, provider_root_dir: str, config: str):
        cmd = " ".join([self.bin_path, *args])
        level = logging.getLevelName(logging.getLogger().getEffectiveLevel())
        if level == "TRACE":
            # trace is not supported in grype-db yet
            level = "DEBUG"

        logging.info(f"running (log-level={level}) {cmd!r}")
        print_annotation("[begin grype-db output]")

        env = dict(  # noqa: PIE804
            **os.environ.copy(),
            **{
                "GRYPE_DB_VUNNEL_ROOT": provider_root_dir,
                "GRYPE_DB_CONFIG": config,
                "GRYPE_DB_LOG_LEVEL": level,
            },
        )

        ret = subprocess.check_call(cmd, env=env, shell=True)  # noqa: S602

        print_annotation("[end grype-db output]")
        return ret


def print_annotation(s: str, italic: bool = True, grey: bool = True):
    prefix = ""
    if italic:
        prefix += str(Format.ITALIC)
    if grey:
        prefix += str(Format.GREY)
    if prefix and sys.stderr.isatty():
        s = f"{prefix}{s}{Format.RESET}"
    return sys.stderr.write(s + "\n")


def _install_grype_db(input_version: str, bin_dir: str, clone_dir: str) -> str:  # noqa: PLR0912
    os.makedirs(bin_dir, exist_ok=True)

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
