import os
import shutil

import pytest


@pytest.fixture
def top_level_fixture():
    def fn(case: str) -> str:
        path = os.path.join(os.path.dirname(__file__), "fixtures", case)
        if not os.path.exists(path):
            raise ValueError(f"invalid case {case}")
        return path

    return fn


@pytest.fixture
def top_level_fixture_copy(top_level_fixture, tmp_path):
    def fn(case: str) -> str:
        path = top_level_fixture(case=case)

        # recursively copy the directory to a temporary location
        tmp_case_path = os.path.join(tmp_path, case)
        shutil.copytree(path, tmp_case_path)

        return tmp_case_path

    return fn


@pytest.fixture
def test_dir(request):
    """
    Returns the path of a file relative to the current test file.

    Given the following setup:

        test/unit/providers/centos/
        ├── test-fixtures
        │   ├── mock_data_1
        │   └── mock_data_2
        └── test_centos.py

    The call `test_dir` will return the absolute path to test/unit/providers/centos/
    """
    current_test_filepath = os.path.realpath(request.module.__file__)
    parent = os.path.realpath(os.path.dirname(current_test_filepath))
    return parent


@pytest.fixture
def test_dir_path(request):
    def fn(path: str) -> str:
        """
        Returns the path of a file relative to the current test file.

        Given the following setup:

            test/unit/providers/centos/
            ├── test-fixtures
            │   ├── mock_data_1
            │   └── mock_data_2
            └── test_centos.py

        The call `test_dir_path("test-fixtures/mock_data_1")` will return the absolute path to
        the mock data file relative to test_centos.py
        """
        current_test_filepath = os.path.realpath(request.module.__file__)
        parent = os.path.realpath(os.path.dirname(current_test_filepath))
        return os.path.join(parent, path)

    return fn
