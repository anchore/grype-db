from __future__ import annotations

import collections
import json
import logging
from dataclasses import InitVar, dataclass, field
from functools import lru_cache
from importlib.resources import files
from typing import TYPE_CHECKING

import yardstick
from yardstick import artifact, capture, comparison, store

from grype_db_manager import format, grypedb, sbom
from grype_db_manager.format import Format

if TYPE_CHECKING:
    from yardstick.cli import config as ycfg


@dataclass
class Gate:
    label_comparisons: InitVar[list[comparison.AgainstLabels] | None]
    label_comparison_stats: InitVar[comparison.ImageToolLabelStats | None]

    reasons: list[str] = field(default_factory=list)

    def __post_init__(
        self,
        label_comparisons: list[comparison.AgainstLabels] | None,
        label_comparison_stats: comparison.ImageToolLabelStats | None,
    ):
        if not label_comparisons and not label_comparison_stats:
            return

        reasons = []

        # - fail when current F1 score drops below last release F1 score (or F1 score is indeterminate)
        # - fail when indeterminate % > 10%
        # - fail when there is a rise in FNs
        latest_release_tool, current_tool = guess_tool_orientation(label_comparison_stats.tools)

        latest_release_comparisons_by_image = {
            comp.config.image: comp for comp in label_comparisons if comp.config.tool == latest_release_tool
        }
        current_comparisons_by_image = {comp.config.image: comp for comp in label_comparisons if comp.config.tool == current_tool}

        # # this doesn't make sense in all cases, especially if we aren't failing any other gates against the current changes
        # # we might want this in the future to protect against no labels for images in an edge case, but that reason is not
        # # currently apparent
        # for image, comp in latest_release_comparisons_by_image.items():
        #     if comp.summary.indeterminate_percent > 10:
        #         reasons.append(
        #             f"latest indeterminate matches % is greater than 10%: {Format.BOLD}{Format.UNDERLINE}" +
        #             f"current={comp.summary.indeterminate_percent:0.2f}%{Format.RESET} image={image}",
        #         )

        for image, comp in current_comparisons_by_image.items():
            latest_f1_score = latest_release_comparisons_by_image[image].summary.f1_score
            current_f1_score = comp.summary.f1_score
            if current_f1_score < latest_f1_score:
                reasons.append(
                    f"current F1 score is lower than the latest release F1 score: {Format.BOLD}{Format.UNDERLINE}"
                    f"current={current_f1_score:0.2f} latest={latest_f1_score:0.2f}{Format.RESET} image={image}",
                )

            if comp.summary.indeterminate_percent > 10:
                reasons.append(
                    f"current indeterminate matches % is greater than 10%: {Format.BOLD}{Format.UNDERLINE}"
                    f"current={comp.summary.indeterminate_percent:0.2f}%{Format.RESET} image={image}",
                )

            latest_fns = latest_release_comparisons_by_image[image].summary.false_negatives
            current_fns = comp.summary.false_negatives
            if current_fns > latest_fns:
                reasons.append(
                    f"current false negatives is greater than the latest release false negatives: {Format.BOLD}{Format.UNDERLINE}"
                    f"current={current_fns} latest={latest_fns}{Format.RESET} image={image}",
                )

        self.reasons = reasons

    def passed(self):
        return len(self.reasons) == 0


def validate(  # noqa: PLR0913
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
    label_entries = store.labels.load_for_image(images, year_max_limit=cfg.default_max_year)

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
            label_entries=label_entries,
        )
        ret.append(gate)

        failure = not gate.passed()
        if failure:
            logging.error(f"failed quality gate for image={image}")
            logging.info(format.treeify(gate.reasons))

    return ret


def capture_results(cfg: ycfg.Application, db_uuid: str, result_set: str, root_dir: str, recapture: bool = False):
    dbm = grypedb.DBManager(root_dir=root_dir)
    dbm.get_db_info(db_uuid)

    sbom.download(cfg=cfg, result_set=result_set)

    request_images = cfg.result_sets[result_set].images()
    is_stale = _is_result_set_stale(request_images=request_images, result_set=result_set, yardstick_root_dir=cfg.store_root)

    if is_stale or recapture:
        capture.result_set(result_set=result_set, scan_requests=cfg.result_sets[result_set].scan_requests())
    else:
        logging.info(f"skipping grype capture for result-set={result_set} (already exists)")


def _is_result_set_stale(request_images: list[str], result_set: str, yardstick_root_dir: str) -> bool:  # noqa: C901, PLR0911
    try:
        result_set_object = yardstick.store.result_set.load(result_set, store_root=yardstick_root_dir)
    except FileNotFoundError as e:
        logging.info(f"result-set does not exist: {e}")
        return True

    if not result_set_object:
        logging.info("result-set does is empty")
        return True

    syft_config_images = {s.config.full_image for s in result_set_object.state if s.config and "syft" in s.config.tool_name}
    grype_config_images = {s.config.full_image for s in result_set_object.state if s.config and "grype" in s.config.tool_name}
    mismatched_images = set(request_images) != set(syft_config_images) or set(request_images) != set(grype_config_images)

    if mismatched_images:
        logging.info("result-set has mismatched image sets")
        return True

    requests_with_no_configs = [s.request for s in result_set_object.state if not s.config]

    if requests_with_no_configs:
        logging.info(f"result-set has unfulfilled requests ({len(requests_with_no_configs)} missing results)")
        return True

    # make certain that all images have 1 syft request and 2 grype requests
    syft_requests_by_image = collections.defaultdict(list)
    for s in result_set_object.state:
        if s.config and "syft" in s.config.tool:
            syft_requests_by_image[s.config.full_image].append(s.request)

    missing_syft_requests = [image for image in request_images if image not in syft_requests_by_image]

    if missing_syft_requests:
        logging.info(f"result-set has missing syft requests: {missing_syft_requests}")
        return True

    grype_requests_by_image = collections.defaultdict(list)
    for s in result_set_object.state:
        if s.config and "grype" in s.config.tool:
            grype_requests_by_image[s.config.full_image].append(s.request)

    missing_grype_requests = [
        image for image in request_images if image not in grype_requests_by_image or len(grype_requests_by_image[image]) != 2
    ]

    if missing_grype_requests:
        logging.info(f"result-set has missing grype requests: {missing_grype_requests}")
        return True

    return False


def validate_image(
    cfg: ycfg.Application,
    descriptions: list[str],
    verbosity: int = 0,
    label_entries: list[artifact.LabelEntry] | None = None,
    store_root: str | None = None,
):
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
):
    if verbosity > 1:
        image = sorted(stats_by_image_tool_pair.true_positives.keys())[0]
        tools = sorted(stats_by_image_tool_pair.true_positives[image].keys())
        table = format.stats_table_by_tool(
            tools,
            image,
            stats_by_image_tool_pair,
        )

        logging.info(table)

    if verbosity > 2:
        # show false negative label entries
        for result in results:
            comp = comparisons_by_result_id[result.ID]
            fns = comp.false_negative_label_entries
            ret = f"false negative matches found in result={result.ID}: {len(fns)}\n"
            for label in fns:
                ret += f"{format.space}    {label.summarize()}\n"
            logging.info(ret.rstrip())

    latest_release_tool, current_tool = guess_tool_orientation([r.config.tool_name for r in results])

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
            logging.info(f"match differences between tooling: {diffs}")


def guess_tool_orientation(tools: list[str]):
    if len(tools) != 2:
        raise RuntimeError("expected 2 tools, got %s" % tools)

    current_tool = None
    latest_release_tool = None
    for _idx, tool_name_version in enumerate(tools):
        if "custom-db" not in tool_name_version:
            latest_release_tool = tool_name_version
            continue
        current_tool = tool_name_version

    if latest_release_tool is None:
        # "latest" value isn't accessible, so we do a best guess at which version is latest
        latest_release_tool, current_tool = sorted(tools)

    if current_tool is None:
        raise ValueError("current tool not found")
    return latest_release_tool, current_tool


@lru_cache
def _get_schema_mapping() -> dict[str, str]:
    content = files("grype_db_manager.data").joinpath("grype-schema-version-mapping.json").read_text()
    return json.loads(content)


def grype_version(schema_version: int) -> str:
    mapping = _get_schema_mapping()
    return mapping[str(schema_version)]
