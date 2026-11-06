import os
import pathlib

import pytest

from grype_db_manager import utils


def _make_executable(path: pathlib.Path) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


class TestToolPath:
    @pytest.mark.parametrize(
        ("name", "env_var"),
        [
            ("yardstick", "YARDSTICK_EXECUTABLE_PATH"),
            ("grype", "GRYPE_EXECUTABLE_PATH"),
        ],
    )
    def test_executable_path_override(self, tmp_path: pathlib.Path, mocker, name: str, env_var: str):
        """Test tool_path uses <NAME>_EXECUTABLE_PATH without needing a git repo or .tool dir."""
        binary = _make_executable(tmp_path / "bin" / name)
        mocker.patch.dict(os.environ, {env_var: str(binary)})
        mock_repo_root = mocker.patch("grype_db_manager.utils.repo_root", side_effect=OSError("not a git repository"))

        assert utils.tool_path(name) == str(binary)
        mock_repo_root.assert_not_called()

    def test_executable_path_override_resolves_from_path(self, tmp_path: pathlib.Path, mocker):
        """Test tool_path resolves a bare command name in <NAME>_EXECUTABLE_PATH via PATH."""
        binary = _make_executable(tmp_path / "bin" / "yardstick")
        mocker.patch.dict(os.environ, {"YARDSTICK_EXECUTABLE_PATH": "yardstick", "PATH": str(binary.parent)})
        mocker.patch("grype_db_manager.utils.repo_root", side_effect=OSError("not a git repository"))

        assert utils.tool_path("yardstick") == str(binary)

    def test_invalid_executable_path_falls_back_to_tool_dir(self, tmp_path: pathlib.Path, mocker):
        """Test tool_path warns and uses .tool/<name> when <NAME>_EXECUTABLE_PATH is not executable."""
        binary = _make_executable(tmp_path / ".tool" / "yardstick")
        mocker.patch.dict(os.environ, {"YARDSTICK_EXECUTABLE_PATH": str(tmp_path / "nonexistent")})
        mocker.patch("grype_db_manager.utils.repo_root", return_value=str(tmp_path))
        mock_warning = mocker.patch("grype_db_manager.utils.logging.warning")

        assert utils.tool_path("yardstick") == str(binary)
        mock_warning.assert_called_once()

    def test_tool_dir_without_override(self, tmp_path: pathlib.Path, mocker):
        """Test tool_path uses .tool/<name> when no override is set."""
        binary = _make_executable(tmp_path / ".tool" / "grype")
        mocker.patch.dict(os.environ, {}, clear=True)
        mocker.patch("grype_db_manager.utils.repo_root", return_value=str(tmp_path))

        assert utils.tool_path("grype") == str(binary)

    def test_missing_tool_raises(self, tmp_path: pathlib.Path, mocker):
        """Test tool_path raises when there is no override and no .tool/<name>."""
        mocker.patch.dict(os.environ, {}, clear=True)
        mocker.patch("grype_db_manager.utils.repo_root", return_value=str(tmp_path))

        with pytest.raises(FileNotFoundError, match="make bootstrap-tools"):
            utils.tool_path("yardstick")
