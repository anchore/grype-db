from __future__ import annotations

import glob
import logging
import os
import subprocess
from typing import TYPE_CHECKING, Any

import yaml

from grype_db_manager.utils import tool_path

if TYPE_CHECKING:
    from grype_db_manager.cli import config


class GateFailedError(Exception):
    pass


class GateError(Exception):
    pass


def gate(
    name: str,
    entry: config.ValidateDB,
    images: list[str],
    grype_bin: str,
    db_archive: str,
    validate: config.Validate,
) -> dict[str, Any]:
    """
    the yardstick gate file for one configured gate, as a dict ready to dump to YAML
    (see https://github.com/anchore/yardstick/blob/main/docs/gate-file.md)
    """
    checks: list[dict[str, Any]] = [
        {"name": "f1NotWorse", "params": {"tolerance": entry.gate.max_f1_regression}},
        {"name": "noNewFalseNegatives", "params": {"max": entry.gate.max_new_false_negatives}},
    ]
    if entry.gate.max_unlabeled_changes is not None:
        # never undecided, so this bounds how much unlabeled churn an undecided gate can pass with
        checks.append({"name": "unlabeledChangesAtMost", "params": {"max": entry.gate.max_unlabeled_changes}})

    obj: dict[str, Any] = {
        "schema": "v1",
        "name": name,
        "description": "grype with the newly built DB vs the same grype with the published DB",
        "candidate": {"grype": grype_bin, "db": db_archive},
        "reference": {"grype": grype_bin, "db": "latest"},
        # unlabeled matches that only one side reports can't decide F1 or FN, which leaves the gate undecided. The
        # gate is diff-based, so undecided passes (unlabeledChangesAtMost still bounds how many there may be)
        "undecided": "pass",
        "subjects": [f"oci:{image}" for image in images],
        "checks": checks,
    }

    if validate.claims:
        obj["claims"] = list(validate.claims)

    max_year = entry.gate.max_year if entry.gate.max_year is not None else validate.default_max_year
    if max_year:
        obj["vulnerabilities"] = {"maxYear": max_year}

    return obj


def write_gates(
    validate: config.Validate,
    images: list[str],
    grype_bin: str,
    db_archive: str,
    gates_dir: str,
) -> list[str]:
    """write a yardstick gate file per configured gate, keeping only the given images (all when none are given)"""
    os.makedirs(gates_dir, exist_ok=True)

    # gates from an earlier run (e.g. one with fewer images) would otherwise be re-scored alongside these
    for stale in glob.glob(os.path.join(gates_dir, "*.yaml")):
        os.remove(stale)

    # yardstick resolves paths against the gate file and compares them that way when re-scoring, so relative paths
    # keep a gate (and its scans) re-scorable from another checkout (e.g. from a CI artifact). yardstick resolves
    # symlinks in the gate's directory first, so do the same here
    real_gates_dir = os.path.realpath(gates_dir)
    grype_bin = os.path.relpath(os.path.realpath(grype_bin), real_gates_dir)
    db_archive = os.path.relpath(os.path.realpath(db_archive), real_gates_dir)

    paths = []
    for idx, entry in enumerate(validate.gates):
        entry_images = [i for i in entry.images if i in images] if images else entry.images

        if not entry_images:
            logging.info(f"no images found for gate {idx}")
            continue

        name = f"gate-{idx}"
        path = os.path.join(gates_dir, f"{name}.yaml")
        logging.info(f"writing yardstick gate to {path!r}")
        with open(path, "w") as f:
            f.write(yaml.safe_dump(gate(name, entry, entry_images, grype_bin, db_archive, validate), sort_keys=False))
        paths.append(path)

    return paths


def run(gate_paths: list[str], rescan: bool = False, verbosity: int = 0) -> None:
    """run the yardstick gates, raising GateFailedError when one fails and GateError when yardstick can't run them"""
    cmd = [tool_path("yardstick"), *gate_paths]
    if rescan:
        cmd.append("--rescan")
    if verbosity:
        cmd.append("-" + "v" * verbosity)

    # yardstick (a downloaded binary) has no need for the publisher's credentials
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}

    logging.info(f"running {' '.join(cmd)}")
    code = subprocess.run(cmd, env=env, check=False).returncode  # noqa: S603
    if code == 1:
        msg = "quality gate failed"
        raise GateFailedError(msg)
    if code:
        msg = f"yardstick could not run the quality gates (exit {code})"
        raise GateError(msg)
