from __future__ import annotations

import json
import re
import logging
from dataclasses import dataclass, InitVar, field
from functools import lru_cache
from importlib.resources import files
from typing import Any

import yardstick
from yardstick import capture, comparison, artifact, store
from yardstick.cli import config as ycfg
from yardstick.cli import display
from tabulate import tabulate

from grype_db_manager import grypedb, sbom


ansi_grey = "\033[90m"
ansi_reset = "\033[0m"
space = " " * 6

def treeify(lines: list[str], prefix: str = "", postfix: str = "──", color: str = ansi_grey) -> str:
    ret = ""
    for idx, line in enumerate(lines):
        branch = "├"
        if idx == len(lines) - 1:
            branch = "└"
        ret += f"{prefix}{color}{branch}{postfix}{ansi_reset} {line}\n"
    return ret.rstrip()

def validate(
        cfg: ycfg.Application,
        result_set: str,
        db_uuid: str,
        root_dir: str,
        verbosity: int = 0,
        recapture: bool = False,
        always_run_label_comparison: bool = False,
):

    capture_results(
        cfg=cfg,
        db_uuid=db_uuid,
        result_set=result_set,
        recapture=recapture,
        root_dir=root_dir,
    )

    result_set_obj = store.result_set.load(name=result_set)
    images = sorted(list(set([s.config.image for s in result_set_obj.state])))
    label_entries = store.labels.load_for_image(images, year_max_limit=cfg.default_max_year)

    lines = [f"result-set: {result_set}", f"labels: {len(label_entries)}", f"max-cve-year: {cfg.default_max_year}"]
    banner = f"validating db={db_uuid}\n{treeify(lines, prefix=space)}"
    logging.info(banner)

    ret = []
    for image, result_states in result_set_obj.result_state_by_image.items():
        if images and image not in images:
            logging.debug(f"skipping image={image}")
            continue

        lines = [f"{state.config.ID} : {state.config.tool}" for state in result_states]
        image_banner = f"testing image={image} with\n{treeify(lines, prefix=space)}"
        logging.banner(image_banner)
    
        gate = validate_image(
            cfg,
            descriptions=[s.config.path for s in result_states],
            always_run_label_comparison=always_run_label_comparison,
            verbosity=verbosity,
            label_entries=label_entries,
        )
        ret.append(gate)
    
        failure = not gate.passed()
        if failure:
            logging.error(f"failed quality gate for image={image}")
            logging.info(treeify(gate.reasons, prefix=space))
    
        # print()
        # size = 120
        # print("▁" * size)
        # print("░" * size)
        # print("▔" * size)
    return ret


def capture_results(cfg: ycfg.Application, db_uuid: str, result_set: str, root_dir: str, recapture: bool = False):
    dbm = grypedb.DBManager(root_dir=root_dir)
    dbm.get_db_info(db_uuid)

    sbom.download(cfg=cfg, result_set=result_set)

    result_set_object = yardstick.store.result_set.load(result_set)

    request_images = cfg.result_sets[result_set].images()
    config_images = set([s.config.image for s in result_set_object.state])
    mismatched_images = len(request_images) != len(config_images)

    # TODO: detect tool differences (is that possible in all cases?)

    requests_with_no_configs = [s.request for s in result_set_object.state if not s.config]

    is_stale = any(requests_with_no_configs) or mismatched_images

    if is_stale or recapture:
        capture.result_set(result_set=result_set, scan_requests=cfg.result_sets[result_set].scan_requests())
    else:
        logging.info(f"skipping grype capture for result-set={result_set} (already exists)")

def format_percent(value: float) -> str:
    if value < 0:
        return ""
    return (
            # "(" +
            format_value_red_green_spectrum(
        value,
        min_value=0,
        max_value=50,
        invert=True,
    )
            # + " %)"
          + " %"
    )

import colorsys
from colr import color

def get_section_rgb_tuple(index, sections):
    half_sections = int(sections / 2)
    red_hsv_tuples = list(reversed([(0, float(x) / float(half_sections - 1), 1) for x in range(half_sections)]))
    green_hsv_tuples = [(0.33, float(x) / float(half_sections - 1), 1) for x in range(half_sections)]
    spectrum = red_hsv_tuples + green_hsv_tuples
    values = list(map(lambda x: colorsys.hsv_to_rgb(*x), spectrum))[index]
    return values[0] * 255, values[1] * 255, values[2] * 255


def get_section_index(value, min_value, max_value, sections, invert):
    value = min(max(value, min_value), max_value)
    value_ratio = float(value - min_value) / float(max_value - min_value)
    if invert:
        value_ratio = 1.0 - value_ratio
    return min(max(int(sections * value_ratio), 0), sections - 1), value_ratio



def format_value_red_green_spectrum(value, min_value=0, max_value=1, sections=10, invert=False):
    index, value_ratio = get_section_index(value, min_value, max_value, sections, invert)
    color_rgb_tuple = get_section_rgb_tuple(index, sections)

    formatted_value = color(f"{value:6.2f}", fore=color_rgb_tuple)

    if value_ratio > 0.9:
        # bold
        formatted_value = "\033[1m" + formatted_value
    if value_ratio > 0.95:
        # underline
        formatted_value = "\033[4m" + formatted_value
    return formatted_value



def summarize_by_tool(
        tools, tp, fp, fn, intedeterminate, intedeterminate_percent, f1, f1_ranges
) -> str :  # pylint: disable=too-many-arguments
    header = [g("TOOL"), g("TP"), g("FP"), g("FN"), g("Indeterminate"), g("F1 Score")]
    all_rows = []
    for tool in sorted(list(tools)):
        f1r = ""
        if f1_ranges.get(tool, None) and f1.get(tool, -1) > 0:
            f1r = f"{f1_ranges[tool][0]:0.2f}-{f1_ranges[tool][1]:0.2f}"

        f1s = ""
        if f1.get(tool, -1) > 0:
            f1s = f"{format_value_red_green_spectrum(f1.get(tool))}"

        row = [
         tool,
            tp.get(tool, ""),
            fp.get(tool, ""),
            fn.get(tool, ""),
            f"{str(intedeterminate.get(tool, '')):3s} {format_percent(intedeterminate_percent.get(tool, -1))}",
            f1s + " " + f1r,
        ]
        all_rows.append(row)

    return tabulate(all_rows, tablefmt="plain", headers=header)


def indent_block(text, prefix=" ") -> str:
    return "".join(prefix + line for line in text.splitlines(True))

def validate_image(
        cfg: ycfg.Application,
        descriptions: list[str],
        always_run_label_comparison: bool = False,
        verbosity: int = 0,
        label_entries: list[artifact.LabelEntry] | None = None,
):

    # do a relative comparison
    # - show comparison summary (no gating action)
    # - list out all individual match differences

    relative_comparison = yardstick.compare_results(
        descriptions=descriptions,
        year_max_limit=cfg.default_max_year,
    )
    # show_results_used(relative_comparison.results)

    # show the relative comparison results
    # if verbosity > 0:
    #     details = False
    #     display.preserved_matches(relative_comparison, details=details, summary=True, common=False)
    #     print()

    # bail if there are no differences found
    if not always_run_label_comparison and not sum(
            [len(relative_comparison.unique[result.ID]) for result in relative_comparison.results],
    ):
        print("no differences found between tool results")
        return Gate(None, None)

    # do a label comparison
    results, label_entries, comparisons_by_result_id, stats_by_image_tool_pair = yardstick.compare_results_against_labels(
        descriptions=descriptions,
        year_max_limit=cfg.default_max_year,
        label_entries=label_entries,
    )
    # show_results_used(results)

    if verbosity > 1:
        image = sorted(list(stats_by_image_tool_pair.true_positives.keys()))[0]
        tools = sorted(list(stats_by_image_tool_pair.true_positives[image].keys()))
        ret = summarize_by_tool(
            tools,
            stats_by_image_tool_pair.true_positives[image],
            stats_by_image_tool_pair.false_positives[image],
            stats_by_image_tool_pair.false_negatives[image],
            stats_by_image_tool_pair.indeterminate[image],
            stats_by_image_tool_pair.indeterminate_percent[image],
            stats_by_image_tool_pair.f1_scores[image],
            stats_by_image_tool_pair.f1_score_ranges[image],
        )


        report = "label statistics per-tool:\n" + indent_block(ret, space + "    ")

        logging.info(report)

        # show_fns = verbosity > 1
        # display.label_comparison(
        #     results,
        #     comparisons_by_result_id,
        #     stats_by_image_tool_pair,
        #     show_fns=show_fns,
        #     show_summaries=True,
        # )

    latest_release_tool, current_tool = guess_tool_orientation([r.config.tool_name for r in results])

    # show the relative comparison unique differences paired up with label conclusions (TP/FP/FN/TN/Unknown)
    all_rows: list[list[Any]] = []
    for result in relative_comparison.results:
        label_comparison = comparisons_by_result_id[result.ID]
        for unique_match in relative_comparison.unique[result.ID]:
            labels = label_comparison.labels_by_match[unique_match.ID]
            if not labels:
                label = "(unknown)"
            elif len(set(labels)) > 1:
                label = ", ".join([l.name for l in labels])
            else:
                label = labels[0].name

            color = ""
            commentary = ""
            if result.config.tool == latest_release_tool:
                # the tool which found the unique result is the latest release tool...
                if label == artifact.Label.TruePositive.name:
                    # drats! we missed a case (this is a new FN)
                    color = format.FAIL
                    commentary = "(this is a new FN 😱)"
                elif artifact.Label.FalsePositive.name in label:
                    # we got rid of a FP! ["hip!", "hip!"]
                    color = format.OKBLUE
                    commentary = "(got rid of a former FP 🙌)"
            else:
                # the tool which found the unique result is the current tool...
                if label == artifact.Label.TruePositive.name:
                    # highest of fives! we found a new TP that the previous tool release missed!
                    color = format.OKBLUE
                    commentary = "(this is a new TP 🙌)"
                elif artifact.Label.FalsePositive.name in label:
                    # welp, our changes resulted in a new FP... not great, maybe not terrible?
                    color = format.FAIL
                    commentary = "(this is a new FP 😱)"

            all_rows.append(
                [
                    f"{color}{result.config.tool} ONLY{format.RESET}",
                    f"{color}{unique_match.package.name}@{unique_match.package.version}{format.RESET}",
                    f"{color}{unique_match.vulnerability.id}{format.RESET}",
                    f"{color}{label}{format.RESET}",
                    f"{commentary}",
                ],
            )

    def escape_ansi(line):
        ansi_escape = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
        return ansi_escape.sub("", line)

    # sort but don't consider ansi escape codes
    all_rows = sorted(all_rows, key=lambda x: escape_ansi(str(x[0] + x[1] + x[2] + x[3])))
    if len(all_rows) == 0:
        logging.info("no differences found between tooling")
    else:

        if verbosity > 0:
            report = "match differences found between tooling:\n"
            indent = space
            report += indent + tabulate(
                    all_rows,
                    headers=[g("TOOL PARTITION"), g("PACKAGE"), g("VULNERABILITY"), g("LABEL"), g("COMMENTARY")],
                    # tablefmt="rounded_outline",
                    tablefmt="plain",
                    showindex="always",
                ).replace("\n", "\n" + indent) + "\n"

            logging.info(report)
        else:
            logging.info(f"match differences between tooling: {len(all_rows)}")

    # populate the quality gate with data that can evaluate pass/fail conditions
    return Gate(label_comparisons=comparisons_by_result_id.values(), label_comparison_stats=stats_by_image_tool_pair)


def g(s: str) -> str:
    return f"{ansi_grey}{s}{format.RESET}"

# def show_results_used(results: list[artifact.ScanResult]):
#     print("   Results used:")
#     for idx, result in enumerate(results):
#         branch = "├──"
#         if idx == len(results) - 1:
#             branch = "└──"
#         print(f"    {branch} {result.ID} : {result.config.tool_name}@{result.config.tool_version} against {result.config.image}")
#     print()


@lru_cache
def _get_schema_mapping() -> dict[str, str]:
    content = files("grype_db_manager.data").joinpath("grype-schema-version-mapping.json").read_text()
    return json.loads(content)


def grype_version(schema_version: int) -> str:
    mapping = _get_schema_mapping()
    return mapping[str(schema_version)]


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

        # this doesn't make sense in all cases, especially if we aren't failing any other gates against the current changes
        # we might want this in the future to protect against no labels for images in an edge case, but that reason is not
        # currently apparent
        # for image, comp in latest_release_comparisons_by_image.items():
        #     if comp.summary.indeterminate_percent > 10:
        #         reasons.append(
        #             f"latest indeterminate matches % is greater than 10%: {format.BOLD+format.UNDERLINE}current={comp.summary.indeterminate_percent:0.2f}%{format.RESET} image={image}",
        #         )

        for image, comp in current_comparisons_by_image.items():
            latest_f1_score = latest_release_comparisons_by_image[image].summary.f1_score
            current_f1_score = comp.summary.f1_score
            if current_f1_score < latest_f1_score:
                reasons.append(
                    f"current F1 score is lower than the latest release F1 score: {format.BOLD+format.UNDERLINE}current={current_f1_score:0.2f} latest={latest_f1_score:0.2f}{format.RESET} image={image}",
                )

            if comp.summary.indeterminate_percent > 10:
                reasons.append(
                    f"current indeterminate matches % is greater than 10%: {format.BOLD+format.UNDERLINE}current={comp.summary.indeterminate_percent:0.2f}%{format.RESET} image={image}",
                )

            latest_fns = latest_release_comparisons_by_image[image].summary.false_negatives
            current_fns = comp.summary.false_negatives
            if current_fns > latest_fns:
                reasons.append(
                    f"current false negatives is greater than the latest release false negatives: {format.BOLD+format.UNDERLINE}current={current_fns} latest={latest_fns}{format.RESET} image={image}",
                )

        self.reasons = reasons

    def passed(self):
        return len(self.reasons) == 0


def guess_tool_orientation(tools: list[str]):
    if len(tools) != 2:
        raise RuntimeError("expected 2 tools, got %s" % tools)

    current_tool = None
    latest_release_tool = None
    for idx, tool_name_version in enumerate(tools):
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

class format:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"
