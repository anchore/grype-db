import colorsys
import enum
import os
import re
from typing import Any

from colr import color
from supports_color import supportsColor
from tabulate import tabulate
from yardstick import artifact, comparison

space = " " * 6


class Format(enum.Enum):
    HEADER = "\033[1m"  # noqa: PIE796
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    GREY = "\033[90m"
    FAIL = "\033[91m"
    BOLD = "\033[1m"  # noqa: PIE796
    UNDERLINE = "\033[4m"
    ITALIC = "\033[3m"
    RESET = "\033[0m"

    def __init__(self, value: str):
        if not supportsColor.stderr or os.environ.get("NO_COLOR", None):
            self._value = ""
        else:
            self._value = value

    def __str__(self):
        return self._value


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


def get_section_rgb_tuple(index, sections):
    half_sections = int(sections / 2)
    red_hsv_tuples = list(reversed([(0, float(x) / float(half_sections - 1), 1) for x in range(half_sections)]))
    green_hsv_tuples = [(0.33, float(x) / float(half_sections - 1), 1) for x in range(half_sections)]
    spectrum = red_hsv_tuples + green_hsv_tuples
    values = [colorsys.hsv_to_rgb(*x) for x in spectrum][index]
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


def stats_table_by_tool(
    tools: list[str],
    image: str,
    stats_by_image_tool_pair: comparison.ImageToolLabelStats,
) -> str:
    tp = stats_by_image_tool_pair.true_positives[image]
    fp = stats_by_image_tool_pair.false_positives[image]
    fn = stats_by_image_tool_pair.false_negatives[image]
    indeterminate = stats_by_image_tool_pair.indeterminate[image]
    indeterminate_percent = stats_by_image_tool_pair.indeterminate_percent[image]
    f1 = stats_by_image_tool_pair.f1_scores[image]
    f1_ranges = stats_by_image_tool_pair.f1_score_ranges[image]

    header = [g("TOOL"), g("TP"), g("FP"), g("FN"), g("Indeterminate"), g("F1 Score")]
    all_rows = []
    for tool in sorted(tools):
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
            f"{indeterminate.get(tool, '')!s:3s} {format_percent(indeterminate_percent.get(tool, -1))}",
            f1s + " " + f1r,
        ]
        all_rows.append(row)

    table = tabulate(all_rows, tablefmt="plain", headers=header)
    return "label statistics per-tool:\n" + indent_block(table, space + "    ")


def match_differences_table(  # noqa: C901
    latest_release_tool: str,
    relative_comparison: comparison.ByPreservedMatch,
    comparisons_by_result_id: dict[str, list[comparison.AgainstLabels]],
):
    # show the relative comparison unique differences paired up with label conclusions (TP/FP/FN/TN/Unknown)
    all_rows: list[list[Any]] = []
    for result in relative_comparison.results:
        label_comparison = comparisons_by_result_id[result.ID]
        for unique_match in relative_comparison.unique[result.ID]:
            labels = label_comparison.labels_by_match[unique_match.ID]
            if not labels:
                label = "(unknown)"
            elif len(set(labels)) > 1:
                label = ", ".join([label.name for label in labels])
            else:
                label = labels[0].name

            color = ""
            commentary = ""
            if result.config.tool == latest_release_tool:
                # the tool which found the unique result is the latest release tool...
                if label == artifact.Label.TruePositive.name:
                    # drats! we missed a case (this is a new FN)
                    color = Format.FAIL
                    commentary = "(this is a new FN 😱)"
                elif artifact.Label.FalsePositive.name in label:
                    # we got rid of a FP! ["hip!", "hip!"]
                    color = Format.OKBLUE
                    commentary = "(got rid of a former FP 🙌)"
            else:  # noqa: PLR5501
                # the tool which found the unique result is the current tool...
                if label == artifact.Label.TruePositive.name:
                    # highest of fives! we found a new TP that the previous tool release missed!
                    color = Format.OKBLUE
                    commentary = "(this is a new TP 🙌)"
                elif artifact.Label.FalsePositive.name in label:
                    # welp, our changes resulted in a new FP... not great, maybe not terrible?
                    color = Format.FAIL
                    commentary = "(this is a new FP 😱)"

            all_rows.append(
                [
                    f"{color}{result.config.tool} ONLY{Format.RESET}",
                    f"{color}{unique_match.package.name}@{unique_match.package.version}{Format.RESET}",
                    f"{color}{unique_match.vulnerability.id}{Format.RESET}",
                    f"{color}{label}{Format.RESET}",
                    f"{commentary}",
                ],
            )

    def escape_ansi(line):
        ansi_escape = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
        return ansi_escape.sub("", line)

    # sort but don't consider ansi escape codes
    all_rows = sorted(all_rows, key=lambda x: escape_ansi(str(x[0] + x[1] + x[2] + x[3])))

    table = ""
    if len(all_rows) > 0:
        table = (
            space
            + tabulate(
                all_rows,
                headers=[g("TOOL PARTITION"), g("PACKAGE"), g("VULNERABILITY"), g("LABEL"), g("COMMENTARY")],
                # tablefmt="rounded_outline",
                tablefmt="plain",
                showindex="always",
            ).replace("\n", "\n" + space)
            + "\n"
        )

    return table.rstrip(), len(all_rows)


def treeify(lines: list[str], prefix: str = space, postfix: str = "──", color: Format = Format.GREY) -> str:
    ret = ""
    for idx, line in enumerate(lines):
        branch = "├"
        if idx == len(lines) - 1:
            branch = "└"
        ret += f"{prefix}{color}{branch}{postfix}{Format.RESET} {line}\n"
    return ret.rstrip()


def indent_block(text, prefix=" ") -> str:
    return "".join(prefix + line for line in text.splitlines(True))


def g(text: str) -> str:
    return f"{Format.ITALIC}{Format.UNDERLINE}{text}{Format.RESET}"
