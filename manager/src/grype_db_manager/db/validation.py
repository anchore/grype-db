from __future__ import annotations

import collections
import logging
from dataclasses import InitVar, dataclass, field
from typing import TYPE_CHECKING, Any

import yardstick
from yardstick import artifact, capture, comparison, store

from grype_db_manager import grypedb
from grype_db_manager.db import format
from grype_db_manager.db.format import Format

if TYPE_CHECKING:
    from yardstick.cli import config as ycfg


@dataclass
class GateConfig:
    # between 0 and 1, the maximum allowable difference below the OSS F1 score before the gate fails (default 0,
    # meaning the test F1 score must be equal to or greater than the OSS F1 score to pass the gate)
    f1_score_threshold: float = 0.0

    # between 0 and 100, the maximum % of unlabeled matches for a scan result before the gate fails (default 10%,
    # meaning the test scan must have less than 10% unlabeled matches to pass the gate)
    unlabeled_matches_threshold: float = 10.0

    # integer, the maximum allowable introduced FNs by the test scan (but found by the OSS scan) before the gate fails
    # (default 0, meaning the test scan must have the same or fewer FNs than the OSS scan to pass the gate)
    introduced_fns_threshold: int = 0


# note: a class property on a dataclass will not work since it is not mutable (cannot convey
# changes to all future instances)
_default_gate_config = GateConfig()  # noqa: PLW0603


def _get_config() -> GateConfig:
    return _default_gate_config


def set_default_gate_config(config: GateConfig) -> None:
    global _default_gate_config  # noqa: PLW0603
    _default_gate_config = config


def capture_results(cfg: ycfg.Application, db_uuid: str, result_set: str, root_dir: str, recapture: bool = False) -> None:
    dbm = grypedb.DBManager(root_dir=root_dir)
    db_info = dbm.get_db_info(db_uuid)

    request_images = cfg.result_sets[result_set].images()
    is_stale = _is_result_set_stale(
        request_images=request_images,
        result_set=result_set,
        db_info=db_info,
        yardstick_root_dir=cfg.store_root,
    )

    if is_stale or recapture:
        capture.result_set(
            result_set=result_set,
            scan_requests=cfg.result_sets[result_set].scan_requests(),
            profiles=cfg.profiles.data,
        )
    else:
        logging.info(f"skipping grype capture for result-set={result_set} (already exists)")


def _is_result_set_stale(
    request_images: list[str],
    result_set: str,
    db_info: grypedb.DBInfo,
    yardstick_root_dir: str,
) -> bool:
    try:
        result_set_object = yardstick.store.result_set.load(result_set, store_root=yardstick_root_dir)
    except FileNotFoundError as e:
        logging.warning(f"result-set does not exist: {e}")
        return True

    if not result_set_object:
        logging.warning("result-set does is empty")
        return True

    if _is_db_checksums_stale(result_set_object, db_info):
        return True

    if _is_result_set_consistent(result_set_object, request_images):
        return True

    return False


def _is_result_set_consistent(result_set_object: artifact.ResultSet, request_images: list[str]) -> bool:
    # all requests should have configs...
    requests_with_no_configs = [s.request for s in result_set_object.state if not s.config]
    if requests_with_no_configs:
        logging.warning(f"result-set has unfulfilled requests ({len(requests_with_no_configs)} missing results)")
        return True

    grype_requests_by_image = collections.defaultdict(list)
    for s in result_set_object.state:
        if s.config and "grype" in s.config.tool:
            grype_requests_by_image[s.config.full_image].append(s.request)

    missing_grype_requests = [
        image for image in request_images if image not in grype_requests_by_image or len(grype_requests_by_image[image]) != 2
    ]

    if missing_grype_requests:
        logging.warning(f"result-set has missing grype requests: {missing_grype_requests}")
        return True

    grype_config_images = {s.config.full_image for s in result_set_object.state if s.config and "grype" in s.config.tool_name}
    mismatched_images = set(request_images) != set(grype_config_images)
    if mismatched_images:
        logging.warning("result-set has mismatched image sets")
        return True

    return False


def _is_db_checksums_stale(result_set_object: artifact.ResultSet, db_info: grypedb.DBInfo) -> bool:
    # all existing requests should be for the same db we are validating...
    db_checksums = {
        s.config.detail.get("db", {}).get("checksum", "")
        for s in result_set_object.state
        if s.config and s.request.tool.startswith("grype") and s.request.label == "custom-db"
    }

    if len(db_checksums) > 1:
        logging.warning("result-set has multiple db checksums")
        return True

    if not db_checksums:
        logging.warning("result-set has no db checksums")
        return True

    if db_info.db_checksum not in db_checksums:
        logging.warning(
            f"result-set was captured for a different db: expected={db_info.db_checksum} actual={next(iter(db_checksums))}",
        )
        return True

    return False


def guess_tool_orientation(tools: list[str]) -> tuple[str, str]:
    if len(tools) != 2:
        raise RuntimeError("expected 2 tools, got %s" % tools)

    current_tool = None
    latest_release_tool = None
    for _idx, tool_name_version in enumerate(tools):
        if "@" not in tool_name_version:
            msg = f"tool is missing a version: {tool_name_version}"
            raise ValueError(msg)
        if "custom-db" not in tool_name_version:
            latest_release_tool = tool_name_version
            continue
        current_tool = tool_name_version

    if latest_release_tool is None:
        # "latest" value isn't accessible, so we do a best guess at which version is latest
        latest_release_tool, current_tool = sorted(tools)

    if current_tool is None:
        msg = "current tool not found"
        raise ValueError(msg)
    return latest_release_tool, current_tool
