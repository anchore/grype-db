import yaml

from grype_db_manager.cli import config
from grype_db_manager.db import validation


def _validate() -> config.Validate:
    return config.Validate(
        default_max_year=2021,
        gates=[
            config.ValidateDB(
                images=["docker.io/alpine:3.2@sha256:abc", "docker.io/debian:7@sha256:def"],
                gate=config.Gate(max_f1_regression=0.15, max_new_false_negatives=10),
            ),
            config.ValidateDB(
                images=["ghcr.io/anchore/test-images/azurelinux3@sha256:123"],
                gate=config.Gate(max_year=2022),
            ),
        ],
    )


def test_write_gates(tmp_path):
    paths = validation.write_gates(
        _validate(),
        images=[],
        grype_bin=str(tmp_path / ".tool" / "grype"),
        db_archive=str(tmp_path / "data" / "db.tar.zst"),
        gates_dir=str(tmp_path / "gates"),
    )

    assert [p.removeprefix(str(tmp_path)) for p in paths] == ["/gates/gate-0.yaml", "/gates/gate-1.yaml"]

    with open(paths[0]) as f:
        gate = yaml.safe_load(f)

    assert gate == {
        "schema": "v1",
        "name": "gate-0",
        "description": "grype with the newly built DB vs the same grype with the published DB",
        # paths are relative to the gate file
        "candidate": {"grype": "../.tool/grype", "db": "../data/db.tar.zst"},
        "reference": {"grype": "../.tool/grype", "db": "latest"},
        "undecided": "pass",
        "subjects": ["oci:docker.io/alpine:3.2@sha256:abc", "oci:docker.io/debian:7@sha256:def"],
        "checks": [
            {"name": "f1NotWorse", "params": {"tolerance": 0.15}},
            {"name": "noNewFalseNegatives", "params": {"max": 10}},
        ],
        "vulnerabilities": {"maxYear": 2021},
    }

    with open(paths[1]) as f:
        # a gate's own max year wins over the default
        assert yaml.safe_load(f)["vulnerabilities"] == {"maxYear": 2022}


def test_write_gates_filters_images(tmp_path):
    paths = validation.write_gates(
        _validate(),
        images=["docker.io/debian:7@sha256:def"],
        grype_bin="/bin/grype",
        db_archive="/db.tar.zst",
        gates_dir=str(tmp_path),
    )

    # the second gate has none of the requested images, so it is not written
    assert len(paths) == 1
    with open(paths[0]) as f:
        assert yaml.safe_load(f)["subjects"] == ["oci:docker.io/debian:7@sha256:def"]
