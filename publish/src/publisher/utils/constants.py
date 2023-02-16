import os

from publisher.utils.repo_root import repo_root


TEST_IMAGE = "centos:8.2.2004"
# note: this is additionally set as a constant in upload_dbs.sh
STAGE_DIR = os.path.join(repo_root(), "publish", "stage")
BUILD_DIR = os.path.join(repo_root(), "publish", "build")
CACHE_DIR = os.path.join(repo_root(), "publish", "cache")
ASSET_DIR = os.path.join(BUILD_DIR, "assets")
DB_DIR = os.path.join(BUILD_DIR, "dbs")
ERROR_DIR = os.path.join(BUILD_DIR, "errors")

# BUCKET = os.environ["AWS_BUCKET"]         # e.g. "toolbox-data.anchore.io"
# DBS_PATH = os.environ["AWS_BUCKET_PATH"]  # e.g. "grype/databases"
LEGACY_DB_SUFFIXES = {".tar.gz"}
NEW_DB_SUFFIXES = {".tar.zst"}
DB_SUFFIXES = {*LEGACY_DB_SUFFIXES, *NEW_DB_SUFFIXES}
GOLDEN_REPORT_LOCATION = os.path.join(repo_root(), "publish", "test-fixtures")
