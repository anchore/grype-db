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


@dataclass
class Gate:
    label_comparisons: InitVar[list[comparison.AgainstLabels] | None]
    label_comparison_stats: InitVar[comparison.ImageToolLabelStats | None]

    reasons: list[str] = field(default_factory=list)
    config: GateConfig = field(default_factory=_get_config)

    def __post_init__(
        self,
        label_comparisons: list[comparison.AgainstLabels] | None,
        label_comparison_stats: comparison.ImageToolLabelStats | None,
    ):
        if not label_comparisons and not label_comparison_stats:
            return

        if not self.config:
            msg = "default GateConfig must be specified before creating a Gate instance"
            raise RuntimeError(msg)

        reasons = []

        latest_release_tool, current_tool = guess_tool_orientation(label_comparison_stats.tools)

        latest_release_comparisons_by_image = {
            comp.config.image: comp for comp in label_comparisons if comp.config.tool == latest_release_tool
        }
        current_comparisons_by_image = {comp.config.image: comp for comp in label_comparisons if comp.config.tool == current_tool}

        for image, comp in current_comparisons_by_image.items():
            reasons.extend(
                not_empty(
                    [
                        self._evaluate_f1_score(
                            last_f1_score=latest_release_comparisons_by_image[image].summary.f1_score,
                            current_f1_score=comp.summary.f1_score,
                            context=image,
                        ),
                        self._evaluate_indeterminate_percent(
                            indeterminate_percent=comp.summary.indeterminate_percent,
                            context=image,
                        ),
                        self._evaluate_fns(
                            last_fns=latest_release_comparisons_by_image[image].summary.false_negatives,
                            current_fns=comp.summary.false_negatives,
                            context=image,
                        ),
                    ],
                ),
            )

        self.reasons = reasons

    def _evaluate_f1_score(self, last_f1_score: float, current_f1_score: float, context: str) -> str | None:
        test_f1_value = last_f1_score - self.config.f1_score_threshold
        if current_f1_score < test_f1_value:
            return str(
                f"current F1 score is lower than the last release F1 score: {Format.BOLD}{Format.UNDERLINE}"
                f"current={current_f1_score:0.2f} last={last_f1_score:0.2f} "
                f"by-margin={self.config.f1_score_threshold:0.2f}{Format.RESET} image={context}",
            )
        return None

    def _evaluate_indeterminate_percent(self, indeterminate_percent: float, context: str) -> str | None:
        if indeterminate_percent > self.config.unlabeled_matches_threshold:
            return str(
                f"current indeterminate matches % is greater than {self.config.unlabeled_matches_threshold}%: {Format.BOLD}{Format.UNDERLINE}"
                f"current={indeterminate_percent:0.2f}%{Format.RESET} image={context}",
            )
        return None

    def _evaluate_fns(self, last_fns: int, current_fns: int, context: str) -> str | None:
        test_fns = last_fns + self.config.introduced_fns_threshold
        if current_fns > test_fns:
            return str(
                f"current false negatives is greater than the last release false negatives: {Format.BOLD}{Format.UNDERLINE}"
                f"current={current_fns} last={last_fns} "
                f"by-margin={self.config.introduced_fns_threshold}{Format.RESET} image={context}",
            )
        return None

    def passed(self) -> bool:
        return len(self.reasons) == 0


def not_empty(value: list[str | None]) -> list[str]:
    return [v for v in value if v is not None]


def validate(
    cfg: ycfg.Application,
    result_set: str,
    db_uuid: str,
    root_dir: str,
    verbosity: int = 0,
    recapture: bool = False,
) -> list[Gate]:
    # get new grype scans and SBOMs (or use any existing ones)

    capture_results(
        cfg=cfg,
        db_uuid=db_uuid,
        result_set=result_set,
        recapture=recapture,
        root_dir=root_dir,
    )

    # validate the DB based on the grype scan results...

    result_set_obj = store.result_set.load(name=result_set)
    images = sorted({s.config.image for s in result_set_obj.state})
    logging.info("loading labels...")
    label_entries = store.labels.load_for_image(images, year_max_limit=cfg.default_max_year)
    # label_collection = artifact.LabelEntryCollection(label_entries)

    lines = [f"result-set: {result_set}", f"labels: {len(label_entries)}", f"max-cve-year: {cfg.default_max_year}"]
    banner = f"validating db={db_uuid}\n{format.treeify(lines)}"
    logging.info(banner)

    ret = []
    states = result_set_obj.result_state_by_image.items()
    for idx, (image, result_states) in enumerate(states):
        if images and image not in images:
            logging.debug(f"skipping image={image}")
            continue

        lines = [f"{state.config.ID} : {state.config.tool}" for state in result_states]
        image_banner = f"{Format.HEADER}comparing image results {idx+1} of {len(states)} image={image}{Format.RESET} with\n{format.treeify(lines)}"
        logging.info(image_banner)

        gate = validate_image(
            cfg,
            descriptions=[s.config.path for s in result_states],
            verbosity=verbosity,
            # label_entries=label_collection.for_image(image),
            label_entries=label_entries,
        )
        ret.append(gate)

        failure = not gate.passed()
        if failure:
            logging.info(f"{Format.FAIL}failed quality gate{Format.RESET} for image={image}\n{format.treeify(gate.reasons)}")

    return ret


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


def validate_image(
    cfg: ycfg.Application,
    descriptions: list[str],
    verbosity: int = 0,
    label_entries: list[artifact.LabelEntry] | None = None,
    store_root: str | None = None,
) -> Gate:
    # compare each grype result against one another, looking for matching differences
    relative_comparison = yardstick.compare_results(
        descriptions=descriptions,
        year_max_limit=cfg.default_max_year,
        store_root=store_root,
    )

    # apply labels to all results
    results, label_entries, comparisons_by_result_id, stats_by_image_tool_pair = yardstick.compare_results_against_labels(
        descriptions=descriptions,
        year_max_limit=cfg.default_max_year,
        label_entries=label_entries,
        store_root=store_root,
    )

    # show the label stats for each image/tool pair
    # as well as qualify all of the match differences relative to the labels to help understand
    # if the matching performance is getting better or worse, outputting enough information for
    # someone to start investigating why.
    log_validation_results(
        relative_comparison=relative_comparison,
        results=results,
        comparisons_by_result_id=comparisons_by_result_id,
        stats_by_image_tool_pair=stats_by_image_tool_pair,
        verbosity=verbosity,
    )

    # populate the quality gate with data that can evaluate pass/fail conditions for this script
    found_differences = sum([len(relative_comparison.unique[result.ID]) for result in relative_comparison.results])
    if not found_differences:
        return Gate(None, None)

    return Gate(label_comparisons=comparisons_by_result_id.values(), label_comparison_stats=stats_by_image_tool_pair)


def log_validation_results(
    relative_comparison: comparison.ByPreservedMatch,
    results: list[artifact.ScanResult],
    comparisons_by_result_id: dict[str, list[comparison.AgainstLabels]],
    stats_by_image_tool_pair: comparison.ImageToolLabelStats,
    verbosity: int = 0,
) -> None:
    if verbosity > 2:
        _log_stats(stats_by_image_tool_pair)

    if verbosity > 1:
        _log_fns(results, comparisons_by_result_id)

    _log_differences(relative_comparison, results, comparisons_by_result_id, verbosity)


def _log_differences(
    relative_comparison: comparison.ByPreservedMatch,
    results: list[artifact.ScanResult],
    comparisons_by_result_id: dict[str, list[comparison.AgainstLabels]],
    verbosity: int,
) -> None:
    latest_release_tool, current_tool = guess_tool_orientation([r.config.tool for r in results])

    table, diffs = format.match_differences_table(
        latest_release_tool=latest_release_tool,
        relative_comparison=relative_comparison,
        comparisons_by_result_id=comparisons_by_result_id,
    )

    if not diffs:
        logging.info("no differences found between tooling")
    else:  # noqa: PLR5501
        if verbosity > 0:
            logging.info(f"match differences found between tooling:\n{table}")
        else:
            logging.info(f"match differences found between tooling: {diffs}")


def _log_stats(stats_by_image_tool_pair: comparison.ImageToolLabelStats) -> None:
    image = sorted(stats_by_image_tool_pair.true_positives.keys())[0]
    tools = sorted(stats_by_image_tool_pair.true_positives[image].keys())
    table = format.stats_table_by_tool(
        tools,
        image,
        stats_by_image_tool_pair,
    )

    logging.info(table)


def _log_fns(results: list[artifact.ScanResult], comparisons_by_result_id: dict[str, list[comparison.AgainstLabels]]) -> None:
    # show false negative label entries
    fns_by_id = {}
    for result in results:
        comp = comparisons_by_result_id[result.ID]
        fns = comp.false_negative_label_entries
        fns_by_id[result.ID] = fns

    unique_fns_by_id = collections.defaultdict(list)
    for result_id, fns in fns_by_id.items():
        for fn in fns:
            if _is_unique_fn(fns_by_id, result_id, fn):
                unique_fns_by_id[result_id].append(fn)

    for result in results:
        fns = unique_fns_by_id[result.ID]
        ret = f"false negatives found uniquely in result={result.ID}: {len(fns)}\n"
        for label in fns:
            ret += f"{format.space}    {label.summarize()}\n"
        logging.info(ret.rstrip())


def _is_unique_fn(fns_by_id: dict[str, set[str]], result_id: str, fn: Any) -> bool:
    for other_result_id, other_fns in fns_by_id.items():
        if other_result_id == result_id:
            continue
        if fn in other_fns:
            return False
    return True


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
