from __future__ import annotations

import logging
import os
import subprocess
from typing import TYPE_CHECKING, Any

import yaml

from grype_db_manager.utils import tool_path

if TYPE_CHECKING:
    from grype_db_manager.cli import config


def gate(name: str, entry: config.ValidateDB, grype_bin: str, db_archive: str, default_max_year: int) -> dict[str, Any]:
    """
    the yardstick gate file for one configured gate, as a dict ready to dump to YAML
    (see https://github.com/anchore/yardstick/blob/main/docs/gate-file.md)
    """
    obj: dict[str, Any] = {
        "schema": "v1",
        "name": name,
        "description": "grype with the newly built DB vs the same grype with the published DB",
        "candidate": {"grype": grype_bin, "db": db_archive},
        "reference": {"grype": grype_bin, "db": "latest"},
        # matches only one side reports that no label judges leave the F1/FN checks undecided. The gate is
        # diff-based, so only a decided regression fails
        "undecided": "pass",
        "subjects": [f"oci:{image}" for image in entry.images],
        "checks": [
            {"name": "f1NotWorse", "params": {"tolerance": entry.gate.max_f1_regression}},
            {"name": "noNewFalseNegatives", "params": {"max": entry.gate.max_new_false_negatives}},
        ],
    }

    max_year = entry.gate.max_year or default_max_year
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

    paths = []
    for idx, entry in enumerate(validate.gates):
        if images:
            entry.images = [i for i in entry.images if i in images]

        if not entry.images:
            logging.info(f"no images found for gate {idx}")
            continue

        name = f"gate-{idx}"
        path = os.path.join(gates_dir, f"{name}.yaml")
        logging.info(f"writing yardstick gate to {path!r}")
        with open(path, "w") as f:
            f.write(yaml.safe_dump(gate(name, entry, grype_bin, db_archive, validate.default_max_year), sort_keys=False))
        paths.append(path)

    return paths


def run(gate_paths: list[str], rescan: bool = False, verbosity: int = 0) -> bool:
    """run the yardstick gates (from the current directory, where yardstick reads .yardstick.yaml), True if all passed"""
    cmd = [tool_path("yardstick"), *gate_paths]
    if rescan:
        cmd.append("--rescan")
    if verbosity:
        cmd.append("-" + "v" * verbosity)

    logging.info(f"running {' '.join(cmd)}")
    return subprocess.run(cmd, check=False).returncode == 0  # noqa: S603
