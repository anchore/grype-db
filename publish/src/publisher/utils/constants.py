import os

from publisher.utils.repo_root import repo_root

root = repo_root()

TEST_IMAGE = "centos:8.2.2004"
# note: this is additionally set as a constant in upload_dbs.sh
STAGE_DIR = os.path.join(root, "publish", "stage")
BUILD_DIR = os.path.join(root, "publish", "build")
CACHE_DIR = os.path.join(root, "publish", "cache")
ASSET_DIR = os.path.join(BUILD_DIR, "assets")
DB_DIR = os.path.join(BUILD_DIR, "dbs")
ERROR_DIR = os.path.join(BUILD_DIR, "errors")
GRYPE_DB_CONFIG = os.path.join(root, "publish", ".grype-db.yaml")

# BUCKET = os.environ["AWS_BUCKET"]         # e.g. "toolbox-data.anchore.io"
# DBS_PATH = os.environ["AWS_BUCKET_PATH"]  # e.g. "grype/databases"

DB_SUFFIXES = {".tar.gz", ".tar.zst"}
GOLDEN_REPORT_LOCATION = os.path.join(root, "publish", "test-fixtures")


MAX_ALLOWABLE_DB_MB_SIZE = 200 * 1024 * 1024  # 200MB
