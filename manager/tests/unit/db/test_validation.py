import subprocess

import pytest
import yaml

from grype_db_manager.cli import config
from grype_db_manager.db import validation


def _validate() -> config.Validate:
    return config.Validate(
        default_max_year=2021,
        claims=["github.com/anchore/claims@f2bef354324428f961262d87adec716bb669338f"],
        gates=[
            config.ValidateDB(
                images=["docker.io/alpine:3.2@sha256:abc", "docker.io/debian:7@sha256:def"],
                gate=config.Gate(max_f1_regression=0.15, max_new_false_negatives=10, max_unlabeled_changes=50),
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
            {"name": "unlabeledChangesAtMost", "params": {"max": 50}},
        ],
        "claims": ["github.com/anchore/claims@f2bef354324428f961262d87adec716bb669338f"],
        "vulnerabilities": {"maxYear": 2021},
    }

    with open(paths[1]) as f:
        gate = yaml.safe_load(f)

    # a gate's own max year wins over the default, and no unlabeled limit means no check for it
    assert gate["vulnerabilities"] == {"maxYear": 2022}
    assert [c["name"] for c in gate["checks"]] == ["f1NotWorse", "noNewFalseNegatives"]


def test_gate_max_year_zero_disables_the_filter():
    entry = config.ValidateDB(images=["docker.io/alpine:3.2@sha256:abc"], gate=config.Gate(max_year=0))
    gate = validation.gate("gate-0", entry, entry.images, "grype", "db.tar.zst", _validate())
    assert "vulnerabilities" not in gate


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


def test_write_gates_removes_stale_gates(tmp_path):
    validate = _validate()
    args = {"grype_bin": "/bin/grype", "db_archive": "/db.tar.zst", "gates_dir": str(tmp_path)}
    validation.write_gates(validate, images=[], **args)
    validation.write_gates(validate, images=["docker.io/debian:7@sha256:def"], **args)

    # the filter neither leaves the earlier gate-1 behind nor changes the config
    assert sorted(p.name for p in tmp_path.iterdir()) == ["gate-0.yaml"]
    assert len(validate.gates[0].images) == 2


@pytest.mark.parametrize(
    ("code", "raises"),
    [
        (0, None),
        # undecided gates pass (undecided: pass), so yardstick exits 0 for them too
        (1, validation.GateFailedError),
        (2, validation.GateError),
    ],
)
def test_run(mocker, monkeypatch, code, raises):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    mocker.patch("grype_db_manager.db.validation.tool_path", return_value="/tool/yardstick")
    run = mocker.patch("subprocess.run", return_value=subprocess.CompletedProcess([], code))

    if raises:
        with pytest.raises(raises):
            validation.run(["gate-0.yaml"], rescan=True, verbosity=2)
    else:
        validation.run(["gate-0.yaml"], rescan=True, verbosity=2)

    assert run.call_args.args[0] == ["/tool/yardstick", "gate-0.yaml", "--rescan", "-vv"]
    assert "AWS_SECRET_ACCESS_KEY" not in run.call_args.kwargs["env"]
