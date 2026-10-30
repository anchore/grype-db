import os

import pytest
import yaml

from grype_db_manager.cli import config


def test_include_tag_is_registered():
    """Test that the !include constructor is properly registered with yaml.SafeLoader."""
    assert "!include" in yaml.SafeLoader.yaml_constructors


def test_override_from_environment():
    env = {
        "TEST_APP_LOG_LEVEL": "DEBUG",
    }

    cfg = config.Application(
        log=config.Log(
            level="INFO",
        ),
    )

    config.override_from_environment(cfg, prefix="TEST_APP", env=env)

    assert cfg.log.level == "DEBUG"


def test_load_from_env_vars_overrides_disk(test_dir_path):
    env = {
        "GRYPE_DB_MANAGER_VALIDATE_LISTING_OVERRIDE_GRYPE_VERSION": "grype-version",
        "GRYPE_DB_MANAGER_VALIDATE_LISTING_OVERRIDE_DB_SCHEMA_VERSION": "schema-version",
        "GRYPE_DB_MANAGER_DISTRIBUTION_S3_PATH": "s3-path",
    }

    # ensure that we override values from disk with env vars
    config_path = test_dir_path("fixtures/config/full.yaml")
    cfg = config.load(config_path, wire_values=False, env=env)

    assert cfg.validate.listing.override_grype_version == "grype-version"
    assert cfg.validate.listing.override_db_schema_version == "schema-version"
    assert cfg.distribution.s3_path == "s3-path"


def test_load(test_dir_path):
    config_path = test_dir_path("fixtures/config/full.yaml")

    cfg = config.load(config_path, wire_values=False)

    actual = cfg.to_yaml()

    expected = """\
assertAwsCredentials: false
data:
  root: data/manager
  vunnelRoot: data/vunnel
  yardstickRoot: data/yardstick
distribution:
  awsRegion: us-west-2
  downloadUrlPrefix: http://localhost:4566/testbucket
  listingFileName: listing.json
  listingReplicas:
    - awsRegion: us-west-2
      listingFileName: listing.json
      s3Bucket: testbucket
      s3Path: grype/databases
  s3AlwaysSuffixSchemaVersion: false
  s3Bucket: testbucket
  s3EndpointUrl: http://localhost:4566
  s3Path: grype/databases
grypeDb:
  config: config/grype-db-nightly-publisher.yaml
  version: file://.
log:
  level: INFO
schemaMappingFile: mapping.json
validate:
  defaultMaxYear: 2021
  expectedProviders:
    - alpine
  gates:
    - gate:
        maxF1Regression: 0.15
        maxNewFalseNegatives: 10
        maxYear: 2021
      images:
        - docker.io/cloudbees/cloudbees-core-agent:2.289.2.2@sha256:d48f0546b4cf5ef4626136242ce302f94a42751156b7be42f4b1b75a66608880
  listing:
    image: centos:8.2.2004
    minimumPackages: 85
    minimumVulnerabilities: 400
    overrideDbSchemaVersion: null
    overrideGrypeVersion: null
verbosity: 2
"""

    assert actual == expected


def test_load_rejects_unsupported_gate_keys(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
validate:
  gates:
    - gate:
        max_f1_regression: 0.15
        max_unlabeled_percent: 50
      images: [docker.io/alpine:3.2]
""",
    )

    with pytest.raises(ValueError, match="max_unlabeled_percent"):
        config.load(str(config_path), wire_values=False)
