import pytest

from yardstick import store
from yardstick.cli import config as ycfg

from grype_db_manager import validate


def test_grype_version():
    assert "v0.7.0" == validate.grype_version(1)
    assert "v0.12.1" == validate.grype_version(2)
    assert "v0.40.1" == validate.grype_version(3)
    assert "v0.50.2" == validate.grype_version(4)
    assert "main" == validate.grype_version(5)


def test_guess_tool_orientation():
    latest_release_tool, current_tool = validate.guess_tool_orientation(["grype@latest", "grype[custom-db]@latest"])

    assert latest_release_tool == "grype@latest"
    assert current_tool == "grype[custom-db]@latest"

    with pytest.raises(ValueError):
        validate.guess_tool_orientation(["grype@latest", "grype@latest"])


@pytest.mark.parametrize(
    "test_case, expected",
    [
        ("good", False),
        ("missing-grype-request", True),
        ("missing-syft-request", True),
        ("unfulfilled-request", True),
        ("different-image-set", True),
        ("missing-result-set", True),
    ],
)
def test_is_result_set_stale(test_dir_path, test_case, expected):
    root = test_dir_path(f"fixtures/result-set-stale-detection/{test_case}")

    request_images = [
        "docker.io/anchore/test_images:grype-quality-node-d89207b@sha256:f56164678054e5eb59ab838367373a49df723b324617b1ba6de775749d7f91d4",
        "docker.io/anchore/test_images:vulnerabilities-alpine-3.11-d5be50d@sha256:01c78cee3fe398bf1f77566177770b07f1d2af01753c2434cb0735bd43a078b6",
        "docker.io/anchore/test_images:vulnerabilities-alpine-3.14-d5be50d@sha256:fe242a3a63699425317fba0a749253bceb700fb3d63e7a0f6497f53a587e38c5",
    ]

    is_stale = validate._is_result_set_stale(request_images=request_images, result_set="result-set", yardstick_root_dir=root)

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
                "current F1 score is lower than the latest release F1 score: current=0.53 latest=1.00 image=docker.io/oraclelinux@sha256:a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495",
                "current false negatives is greater than the latest release false negatives: current=9 latest=0 image=docker.io/oraclelinux@sha256:a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495",
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
                "current F1 score is lower than the latest release F1 score: current=0.53 latest=1.00 image=docker.io/oraclelinux@sha256:a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495"
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

    gate = validate.validate_image(
        cfg=yardstick_cfg,
        descriptions=result_set_obj.descriptions,
        label_entries=label_entries,
        store_root=yardstick_root,
    )

    assert gate
    assert gate.passed() == expected_pass
    assert gate.reasons == expected_reasons
