import os

from grype_db_manager.cli import config


def test_load_from_env_vars():
    os.environ["GRYPE_DB_MANAGER_VALIDATE_LISTING_OVERRIDE_GRYPE_VERSION"] = "grype-version"
    os.environ["GRYPE_DB_MANAGER_VALIDATE_LISTING_OVERRIDE_DB_SCHEMA_VERSION"] = "schema-version"

    # asserts that we defer the env var lookup until the object creation and that the values are wired up correctly
    cfg = config.Application()

    assert cfg.validate.listing.override_grype_version == "grype-version"
    assert cfg.validate.listing.override_db_schema_version == "schema-version"


def test_load_default():
    cfg = config.Application()

    actual = cfg.to_yaml()

    expected = """\
distribution:
  awsRegion: null
  listingFileName: listing.json
  s3Bucket: null
  s3EndpointUrl: null
  s3Path: null
grypeDb:
  config: ''
  version: latest
log:
  level: INFO
root: .grype-db-manager
validate:
  db:
    defaultMaxYear: 2021
    gate:
      f1ScoreThreshold: 0.0
      introducedFnsThreshold: 0
      unlabeledMatchesThreshold: 10.0
    grype:
      config: ''
      version: latest
    images: []
    syft:
      config: ''
      version: latest
  listing:
    image: null
    minimumPackages: null
    minimumVulnerabilities: null
    overrideDbSchemaVersion: null
    overrideGrypeVersion: null
vunnelRoot: data/vunnel
yardstickRoot: data/yardstick
"""

    assert actual == expected


def test_load(test_dir_path):
    config_path = test_dir_path("fixtures/config/full.yaml")

    cfg = config.load(config_path, wire_values=False)

    actual = cfg.to_yaml()

    expected = """\
distribution:
  awsRegion: us-west-2
  listingFileName: listing.json
  s3Bucket: testbucket
  s3EndpointUrl: http://localhost:4566
  s3Path: grype/databases
grypeDb:
  config: config/grype-db-nightly-publisher.yaml
  version: file://.
log:
  level: INFO
root: data/manager
validate:
  db:
    defaultMaxYear: 2021
    gate:
      f1ScoreThreshold: 0.0
      introducedFnsThreshold: 0
      unlabeledMatchesThreshold: 10.0
    grype:
      config: ''
      version: latest
    images:
      - docker.io/cloudbees/cloudbees-core-agent:2.289.2.2@sha256:d48f0546b4cf5ef4626136242ce302f94a42751156b7be42f4b1b75a66608880
    syft:
      config: ''
      version: v0.86.1
  listing:
    image: centos:8.2.2004
    minimumPackages: 85
    minimumVulnerabilities: 400
    overrideDbSchemaVersion: null
    overrideGrypeVersion: null
vunnelRoot: data/vunnel
yardstickRoot: data/yardstick
"""

    assert actual == expected
