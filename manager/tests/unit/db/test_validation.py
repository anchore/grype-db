import datetime

import pytest

from yardstick import store
from yardstick.cli import config as ycfg

from grype_db_manager import grypedb
from grype_db_manager.db import validation


def test_guess_tool_orientation():
    latest_release_tool, current_tool = validation.guess_tool_orientation(["grype@latest", "grype[custom-db]@latest"])

    assert latest_release_tool == "grype@latest"
    assert current_tool == "grype[custom-db]@latest"

    with pytest.raises(ValueError):
        validation.guess_tool_orientation(["grype@latest", "grype@latest"])

    with pytest.raises(ValueError):
        validation.guess_tool_orientation(["grype@latest", "grype[custom-db]"])


def _partial_db_info(checksum: str):
    return grypedb.DBInfo(
        uuid="session-id",
        schema_version=5,
        db_checksum=checksum,
        db_created=datetime.datetime.now(tz=datetime.timezone.utc),
        data_created=datetime.datetime.now(tz=datetime.timezone.utc),
        archive_path="archive-path",
    )


expected_db_info = _partial_db_info("sha256:d594a820353c99d1fcc29904ef0e4c0bace8ed7a0e21c4112325b6f57e4f9ad3")
bad_db_info = _partial_db_info("bad-checksum")


@pytest.mark.parametrize(
    "test_case, db_info, expected",
    [
        pytest.param(
            "good",
            expected_db_info,
            False,
            id="go-case",
        ),
        pytest.param(
            "inconsistent-db-checksum",
            expected_db_info,
            True,
            id="inconsistent-db-checksum",
        ),
        pytest.param(
            "missing-grype-request",
            expected_db_info,
            True,
            id="missing-grype-request",
        ),
        pytest.param(
            "unfulfilled-request",
            expected_db_info,
            True,
            id="unfulfilled-request",
        ),
        pytest.param(
            "different-image-set",
            expected_db_info,
            True,
            id="different-image-set",
        ),
        pytest.param(
            "missing-result-set",
            expected_db_info,
            True,
            id="missing-result-set",
        ),
        pytest.param(
            "good",
            bad_db_info,
            True,
            id="mismatched-db-checksum",
        ),
    ],
)
def test_is_result_set_stale(test_dir_path, test_case, db_info, expected):
    root = test_dir_path(f"fixtures/result-set-stale-detection/{test_case}")

    request_images = [
        "docker.io/anchore/test_images:grype-quality-node-d89207b@sha256:f56164678054e5eb59ab838367373a49df723b324617b1ba6de775749d7f91d4",
        "docker.io/anchore/test_images:vulnerabilities-alpine-3.11-d5be50d@sha256:01c78cee3fe398bf1f77566177770b07f1d2af01753c2434cb0735bd43a078b6",
        "docker.io/anchore/test_images:vulnerabilities-alpine-3.14-d5be50d@sha256:fe242a3a63699425317fba0a749253bceb700fb3d63e7a0f6497f53a587e38c5",
    ]

    is_stale = validation._is_result_set_stale(
        request_images=request_images, result_set="result-set", db_info=db_info, yardstick_root_dir=root
    )

    assert is_stale == expected


@pytest.mark.parametrize(
    "result_set, label_set, expected_reasons",
    [
        pytest.param(
            "go-case",
            "all-tp",
            [],
            id="pass-when-no-differences",
        ),
        pytest.param(
            "new-db-run-missing-half",
            "all-tp",
            [
                "current F1 score is lower than the last release F1 score: current=0.53 last=1.00 by-margin=0.00 image=docker.io/oraclelinux@sha256:a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495",
                "current false negatives is greater than the last release false negatives: current=9 last=0 by-margin=0 image=docker.io/oraclelinux@sha256:a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495",
            ],
            id="fail-when-introduced-fns",
        ),
        pytest.param(
            "old-db-run-missing-half",
            "all-tp",
            [],
            id="pass-when-introduced-tps",
        ),
        pytest.param(
            "new-db-run-missing-half",
            "first-half-fp",
            [],
            id="pass-when-eliminated-fps",
        ),
        pytest.param(
            "old-db-run-missing-half",
            "first-half-fp",
            [
                "current F1 score is lower than the last release F1 score: current=0.53 last=1.00 by-margin=0.00 image=docker.io/oraclelinux@sha256:a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495"
            ],
            id="fail-when-introduced-fps",
        ),
    ],
)
def test_validate_image(test_dir_path, result_set, label_set, expected_reasons):
    yardstick_root = test_dir_path(f"fixtures/validate-image/yardstick")
    expected_pass = len(expected_reasons) == 0

    result_set_obj = store.result_set.load(result_set, store_root=yardstick_root)
    images = sorted({s.config.image for s in result_set_obj.state})

    assert len(images) == 1

    image = images[0]

    tools = [
        ycfg.Tool(
            label=s.request.label,
            name=s.request.tool.split("@")[0],
            takes=s.request.takes,
            version=s.request.tool.split("@")[1],
        )
        for s in result_set_obj.state
    ]

    assert len(tools) == 2

    yardstick_cfg = ycfg.Application(
        store_root=yardstick_root,
        default_max_year=2022,
        result_sets={
            result_set: ycfg.ResultSet(
                description="test",
                matrix=ycfg.ScanMatrix(
                    images=[image],
                    tools=tools,
                ),
            ),
        },
    )

    label_set_root = test_dir_path(f"fixtures/validate-image/label-sets/{label_set}")
    label_entries = store.labels.load_for_image(images, year_max_limit=yardstick_cfg.default_max_year, store_root=label_set_root)

    gate = validation.validate_image(
        cfg=yardstick_cfg,
        descriptions=result_set_obj.descriptions,
        label_entries=label_entries,
        store_root=yardstick_root,
    )

    assert gate
    assert gate.passed() == expected_pass
    assert gate.reasons == expected_reasons


@pytest.mark.parametrize(
    "last, current, config, expect_fail",
    [
        pytest.param(
            0.5,
            0.5,
            validation.GateConfig(),
            False,
            id="default-config-pass-when-no-difference",
        ),
        pytest.param(
            0.5,
            0.55,
            validation.GateConfig(),
            False,
            id="default-config-pass-when-there-is-better-performance",
        ),
        pytest.param(
            0.5,
            0.49,
            validation.GateConfig(),
            True,
            id="default-config-fail-when-below-0-threshold",
        ),
        pytest.param(
            0.5,
            0.5,
            validation.GateConfig(f1_score_threshold=0.1),
            False,
            id="custom-config-pass-when-no-difference",
        ),
        pytest.param(
            0.5,
            0.55,
            validation.GateConfig(f1_score_threshold=0.1),
            False,
            id="custom-config-pass-when-there-is-better-performance",
        ),
        pytest.param(
            0.5,
            0.49,
            validation.GateConfig(f1_score_threshold=0.1),
            False,
            id="custom-config-pass-when-within-margin",
        ),
        pytest.param(
            0.5,
            0.4,
            validation.GateConfig(f1_score_threshold=0.1),
            False,
            id="custom-config-pass-when-at-margin",
        ),
        pytest.param(
            0.5,
            0.39,
            validation.GateConfig(f1_score_threshold=0.1),
            True,
            id="custom-config-fail-when-below-margin",
        ),
    ],
)
def test_gate_evaluate_f1_score(last, current, config, expect_fail):
    gate = validation.Gate(None, None, config=config)
    reason = gate._evaluate_f1_score(
        last_f1_score=last,
        current_f1_score=current,
        context="test",
    )

    reason_is_fail = reason is not None

    assert reason_is_fail == expect_fail


@pytest.mark.parametrize(
    "last, current, config, expect_fail",
    [
        pytest.param(
            5,
            5,
            validation.GateConfig(),
            False,
            id="default-config-pass-when-no-difference",
        ),
        pytest.param(
            5,
            4,
            validation.GateConfig(),
            False,
            id="default-config-pass-when-there-is-better-performance",
        ),
        pytest.param(
            5,
            6,
            validation.GateConfig(),
            True,
            id="default-config-fail-when-below-0-threshold",
        ),
        pytest.param(
            5,
            5,
            validation.GateConfig(introduced_fns_threshold=2),
            False,
            id="custom-config-pass-when-no-difference",
        ),
        pytest.param(
            5,
            4,
            validation.GateConfig(introduced_fns_threshold=2),
            False,
            id="custom-config-pass-when-there-is-better-performance",
        ),
        pytest.param(
            5,
            6,
            validation.GateConfig(introduced_fns_threshold=2),
            False,
            id="custom-config-pass-when-within-margin",
        ),
        pytest.param(
            5,
            7,
            validation.GateConfig(introduced_fns_threshold=2),
            False,
            id="custom-config-pass-when-at-margin",
        ),
        pytest.param(
            5,
            8,
            validation.GateConfig(introduced_fns_threshold=2),
            True,
            id="custom-config-fail-when-below-margin",
        ),
    ],
)
def test_gate_evaluate_fns(last, current, config, expect_fail):
    gate = validation.Gate(None, None, config=config)
    reason = gate._evaluate_fns(
        last_fns=last,
        current_fns=current,
        context="test",
    )

    reason_is_fail = reason is not None

    assert reason_is_fail == expect_fail


@pytest.mark.parametrize(
    "indeterminate_percent, config, expect_fail",
    [
        pytest.param(
            9,
            validation.GateConfig(),
            False,
            id="default-config-pass-when-below-threshold",
        ),
        pytest.param(
            10,
            validation.GateConfig(),
            False,
            id="default-config-pass-when-at-threshold",
        ),
        pytest.param(
            11,
            validation.GateConfig(),
            True,
            id="default-config-fail-when-above-threshold",
        ),
        pytest.param(
            9,
            validation.GateConfig(unlabeled_matches_threshold=20),
            False,
            id="custom-config-pass-when-below-margin",
        ),
        pytest.param(
            20,
            validation.GateConfig(unlabeled_matches_threshold=20),
            False,
            id="custom-config-pass-when-at-margin",
        ),
        pytest.param(
            19,
            validation.GateConfig(unlabeled_matches_threshold=20),
            False,
            id="custom-config-pass-when-within-margin",
        ),
        pytest.param(
            21,
            validation.GateConfig(unlabeled_matches_threshold=20),
            True,
            id="custom-config-fail-when-above-margin",
        ),
    ],
)
def test_evaluate_indeterminate_percent(indeterminate_percent, config, expect_fail):
    gate = validation.Gate(None, None, config=config)
    reason = gate._evaluate_indeterminate_percent(
        indeterminate_percent=indeterminate_percent,
        context="test",
    )

    reason_is_fail = reason is not None

    assert reason_is_fail == expect_fail
