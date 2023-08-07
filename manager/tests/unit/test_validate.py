import pytest

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
    ]

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


class TestValidate:

    def __init__(self):
        pass