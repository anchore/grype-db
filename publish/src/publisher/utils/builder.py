import os
import logging
import glob
import subprocess
import shutil
from typing import Dict


from publisher.utils.repo_root import repo_root
from publisher.utils.constants import CACHE_DIR, GRYPE_DB_CONFIG, MAX_ALLOWABLE_DB_MB_SIZE


class GrypeDbBuilder:
    def __init__(self):
        self.dbs: Dict[int, str] = {}

    def build_and_package(self, db_dir: str, schema_version: int, stage_dir: str):
        logging.info(f"building DB (schema={schema_version})")

        # create the staging dir and ensure it is empty
        os.makedirs(stage_dir, exist_ok=True)
        if list(os.listdir(stage_dir)):
            raise RuntimeError("staging directory must be empty")

        db_pattern = os.path.join(
            db_dir, f"*_v{schema_version}_*.tar.*"
        )
        matches = glob.glob(db_pattern)
        if len(matches):
            raise RuntimeError(f"there are already existing DB archives: {matches}")

        # generate a new DB archive
        self.build_db(build_dir=db_dir, schema_version=schema_version)
        self.package_db(build_dir=db_dir)

        matches = glob.glob(db_pattern)
        if len(matches) != 1:
            logging.error(f"no db file matches found: {matches}")
            raise RuntimeError("failed to build db")
        logging.info(f"db archive created: {matches[0]}")

        # check if the DB is above the max allowable size. This is an arbitrary threshold and a bit of a sanity check.
        # If this fails someone should take a look to see if the DB is growing too large or if the threshold is too low.
        db_size = os.path.getsize(matches[0])
        if db_size > MAX_ALLOWABLE_DB_MB_SIZE:
            raise RuntimeError(
                f"DB size ({db_size} bytes) is above the max allowable size ({MAX_ALLOWABLE_DB_MB_SIZE} bytes)"
            )

        # move the build db archive to the staging dir
        dest = os.path.join(stage_dir, os.path.basename(matches[0]))
        logging.info(f"copying db archive to {dest}")
        shutil.copy(matches[0], dest)

        self.dbs[schema_version] = dest

    def db_path(self, scheme_version: int):
        return self.dbs[scheme_version]

    @classmethod
    def run(cls, *args, cache_dir=CACHE_DIR, config=GRYPE_DB_CONFIG, caller=subprocess.check_call):
        cmd = " ".join(["go run ./cmd/grype-db/main.go", *args])
        print(f"running {cmd!r}")

        env = dict(
            **os.environ.copy(),
            **{
                "GRYPE_DB_PROVIDER_ROOT": cache_dir,
                "GRYPE_DB_CONFIG": config,
            },
        )

        return caller(cmd, cwd=repo_root(), env=env, shell=True)

    @classmethod
    def build_db(cls, build_dir, schema_version: int, cache_dir=CACHE_DIR):
        cls.run("build", "-v", "--schema", str(schema_version), "--dir", build_dir,
                 cache_dir=cache_dir,
                )

    @classmethod
    def package_db(cls, build_dir, cache_dir=CACHE_DIR):
        cls.run("package", "-v", "--dir", build_dir,
                 cache_dir=cache_dir,
                 )

    @classmethod
    def pull(cls):
        if not cls.cache_exists():
            cls.run("pull", "-v")

    @classmethod
    def cache_exists(cls):
        try:
            return "Last Pull" in cls.run(
                "cache",
                caller=subprocess.check_output,
            ).decode("utf-8")
        except subprocess.CalledProcessError:
            return False
