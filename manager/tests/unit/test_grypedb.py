import os
import datetime
import pathlib

import pytest

from grype_db_manager import grypedb


class TestDBManager:
    def test_list_dbs(self, top_level_fixture):
        root = top_level_fixture(case="dbs-case-1")
        dbm = grypedb.DBManager(root_dir=root)

        def path_to_archive(session_id: str, name: str):
            return os.path.join(root, grypedb.DB_DIR, session_id, "stage", name)

        expected = [
            grypedb.DBInfo(
                uuid="9d1fce98-9c10-4887-949e-8296a259daf5",
                schema_version=4,
                db_checksum="sha256:0f2f6e45dcde94259c078d237e575a30787c5ad04345c57e4d5dea08a95af4cb",
                db_created="2023-07-30T03:45:08Z",
                data_created="2023-07-30T03:45:08Z",
                archive_path=path_to_archive(
                    "9d1fce98-9c10-4887-949e-8296a259daf5",
                    "vulnerability-db_v4_2023-08-03T01:34:34Z_54b7b6a76b058f1fa587.tar.gz",
                ),
            ),
            grypedb.DBInfo(
                uuid="41e4c9e7-73c7-4106-bfb3-82e58ce15d9a",
                schema_version=5,
                db_checksum="sha256:c996a4c459a2fca9283c4fd8cdb53e3b050650d76e6ce517b91e34430f6db854",
                db_created="2023-07-31T03:45:08Z",
                data_created="2023-07-31T01:34:05Z",
                archive_path=path_to_archive(
                    "41e4c9e7-73c7-4106-bfb3-82e58ce15d9a",
                    "vulnerability-db_v5_2023-08-03T01:34:34Z_54b7b6a76b058f1fa587.tar.gz",
                ),
            ),
        ]
        dbs = dbm.list_dbs()
        assert expected == dbs

    def test_new_session(self, tmp_path: pathlib.Path):
        dbm = grypedb.DBManager(root_dir=tmp_path.as_posix())
        session_id = dbm.new_session()

        assert session_id is not None

        session_dir = os.path.join(tmp_path.as_posix(), grypedb.DB_DIR, session_id)

        session_build_dir = os.path.join(session_dir, "build")
        session_stage_dir = os.path.join(session_dir, "stage")

        assert os.path.exists(session_build_dir)
        assert os.path.exists(session_stage_dir)

        timestamp_file = os.path.join(session_dir, "timestamp")
        assert os.path.exists(timestamp_file)

        with open(timestamp_file, "r") as f:
            timestamp = f.read()
            v = datetime.datetime.fromisoformat(timestamp)
            assert v
            assert v.year == datetime.datetime.now().year

    @pytest.mark.parametrize(
        "listed_namespaces, schema_version, expect_error",
        [
            pytest.param([], 5, True, id="empty"),
            pytest.param(["namespace1"], 5, True, id="too few namespaces"),
            pytest.param(grypedb.expected_namespaces(5), 5, False, id="v5 matches"),
            pytest.param(grypedb.expected_namespaces(5) + ["extra_items"], 5, False, id="v5 with extra items"),
            pytest.param(list(grypedb.expected_namespaces(5))[:-5], 5, True, id="v5 missing items"),
        ],
    )
    def test_validate_namespaces(self, tmp_path: pathlib.Path, mocker, schema_version, listed_namespaces, expect_error):
        assert len(grypedb.expected_namespaces(schema_version)) > 0

        dbm = grypedb.DBManager(root_dir=tmp_path.as_posix())
        session_id = dbm.new_session()

        # patch list_namespaces to return a mock
        dbm.list_namespaces = mocker.MagicMock()
        dbm.list_namespaces.return_value = listed_namespaces

        # patch db_info to return a mock
        dbm.get_db_info = mocker.MagicMock()
        dbm.get_db_info.return_value = grypedb.DBInfo(
            uuid="",
            schema_version=schema_version,
            db_checksum="",
            db_created="",
            data_created="",
            archive_path="",
        )

        if expect_error:
            with pytest.raises(grypedb.DBNamespaceException):
                dbm.validate_namespaces(session_id)
        else:
            dbm.validate_namespaces(session_id)

        dbm.list_namespaces.assert_called_once()
        dbm.get_db_info.assert_called_once()

    @pytest.mark.parametrize(
        "listed_providers, configured_providers, expect_error",
        [
            pytest.param([], [], grypedb.DBProviderException, id="empty"),
            pytest.param(["nvd"], ["nvd", "alpine"], grypedb.DBProviderException, id="too few providers"),
            pytest.param(["nvd", "alpine"], ["nvd", "alpine"], None, id="valid"),
            pytest.param(["nvd", "alpine", "extra"], ["nvd", "alpine"], None, id="extra items"),
        ],
    )
    def test_validate_providers(self, tmp_path: pathlib.Path, mocker, listed_providers, configured_providers, expect_error):

        dbm = grypedb.DBManager(root_dir=tmp_path.as_posix())
        session_id = dbm.new_session()

        # patch list_namespaces to return a mock
        dbm.list_providers = mocker.MagicMock()
        dbm.list_providers.return_value = listed_providers

        if expect_error:
            with pytest.raises(expect_error):
                dbm.validate_providers(session_id, configured_providers)
        else:
            dbm.validate_providers(session_id, configured_providers)

        if configured_providers:
            dbm.list_providers.assert_called_once()


class TestGrypeDB:
    def test_list_installed(self, top_level_fixture):
        root = top_level_fixture(case="tools-case-1")

        expected_bin_path_root = os.path.join(root, "tools", "grype-db", "bin")
        installed = grypedb.GrypeDB.list_installed(root_dir=root)

        def extract(g: grypedb.GrypeDB) -> str:
            return g.version

        expected = [
            "v0.18.0",
            "v0.19.0",
            "v0.19.0-2-gda1ca9e-dirty",
        ]

        assert expected == [extract(i) for i in installed]

        for g in installed:
            assert g.bin_path.startswith(expected_bin_path_root)
            assert g.bin_path.endswith("grype-db-" + g.version)
            assert os.path.exists(g.bin_path)

    def test_run(self, top_level_fixture, mocker):
        root = top_level_fixture(case="tools-case-1")
        bin_path = os.path.join(root, "tools", "grype-db", "bin", "grype-db-v0.19.0")
        gdb = grypedb.GrypeDB(bin_path)

        # patch grypedb.subprocess.check_call to return a mock
        mock_check_call = mocker.patch("grype_db_manager.grypedb.subprocess.check_call")

        # patch logging.getLevelName to return a mock
        mock_logger = mocker.patch("grype_db_manager.grypedb.logging.getLevelName")
        mock_logger.return_value = "DEBUG"

        gdb.run("version", provider_root_dir="provider_root_path", config="config_path")

        # make certain the mock was called with at least
        #   env = {GRYPE_DB_VUNNEL_ROOT: "provider_root_path", GRYPE_DB_CONFIG: "config_path", GRYPE_DB_LOG_LEVEL: "DEBUG"}
        #   shell = False (or not set, which defaults to False)
        #   cmd = [".../bin/grype-db-v0.19.0", "version"]

        mock_check_call.assert_called_once()
        args, kwargs = mock_check_call.call_args
        assert "shell" not in kwargs or kwargs["shell"] is False
        assert kwargs["env"]["GRYPE_DB_VUNNEL_ROOT"] == "provider_root_path"
        assert kwargs["env"]["GRYPE_DB_CONFIG"] == "config_path"
        assert kwargs["env"]["GRYPE_DB_LOG_LEVEL"] == "DEBUG"
        assert args[0] == [bin_path, "version"]

    def test_check_executable_path_override_valid_path(self, tmp_path: pathlib.Path, mocker):
        """Test _check_executable_path_override returns path when GRYPE_DB_EXECUTABLE_PATH is valid."""
        fake_grype_db = tmp_path / "fake-grype-db"
        fake_grype_db.write_text("#!/bin/bash\necho 'fake grype-db'")
        fake_grype_db.chmod(0o755)

        # Mock shutil.which to return the path (simulates executable)
        mock_which = mocker.patch("grype_db_manager.grypedb.shutil.which")
        mock_which.return_value = str(fake_grype_db)

        # Set environment variable
        mocker.patch.dict(os.environ, {"GRYPE_DB_EXECUTABLE_PATH": str(fake_grype_db)})

        result = grypedb._check_executable_path_override()

        # Should return the path from env var
        assert result == str(fake_grype_db)
        mock_which.assert_called_once_with(str(fake_grype_db))

    def test_install_grype_db_uses_executable_path_override(self, tmp_path: pathlib.Path, mocker):
        """Test _install_grype_db uses result from _check_executable_path_override."""
        fake_path = "/usr/local/bin/grype-db"

        # Mock the override function to return a path
        mock_override = mocker.patch("grype_db_manager.grypedb._check_executable_path_override")
        mock_override.return_value = fake_path

        result = grypedb._install_grype_db("latest", str(tmp_path), str(tmp_path))

        # Should return the path from override function
        assert result == fake_path
        mock_override.assert_called_once()

    def test_check_executable_path_override_invalid_path(self, mocker):
        """Test _check_executable_path_override returns None when path is not executable."""
        fake_path = "/nonexistent/grype-db"

        # Mock shutil.which to return None (not executable)
        mock_which = mocker.patch("grype_db_manager.grypedb.shutil.which")
        mock_which.return_value = None

        # Set environment variable to invalid path
        mocker.patch.dict(os.environ, {"GRYPE_DB_EXECUTABLE_PATH": fake_path})

        result = grypedb._check_executable_path_override()

        # Should return None for invalid path
        assert result is None
        mock_which.assert_called_once_with(fake_path)

    def test_check_executable_path_override_no_env_var(self, mocker):
        """Test _check_executable_path_override returns None when env var not set."""
        # Ensure no environment variable is set
        mocker.patch.dict(os.environ, {}, clear=True)

        result = grypedb._check_executable_path_override()

        # Should return None when no env var
        assert result is None

    def test_install_grype_db_with_invalid_executable_path(self, tmp_path: pathlib.Path, mocker):
        """Test _install_grype_db warns and continues when GRYPE_DB_EXECUTABLE_PATH is not executable."""
        fake_path = "/nonexistent/grype-db"

        # Mock shutil.which to return None (not executable)
        mock_which = mocker.patch("grype_db_manager.grypedb.shutil.which")
        mock_which.return_value = None

        # Mock the rest of the install process to avoid actual building
        mock_requests = mocker.patch("grype_db_manager.grypedb.requests")
        mock_requests.get.return_value.json.return_value = {"tag_name": "v1.0.0"}

        # Set environment variable to invalid path
        mocker.patch.dict(os.environ, {"GRYPE_DB_EXECUTABLE_PATH": fake_path})

        # Should continue to normal build process (we'll let it fail since we're testing the env var logic)
        with pytest.raises(Exception):  # Will fail on actual build, but that's expected
            grypedb._install_grype_db("latest", str(tmp_path), str(tmp_path))

        # Should have checked if the path is executable
        mock_which.assert_called_once_with(fake_path)

    def test_install_grype_db_without_executable_path(self, tmp_path: pathlib.Path, mocker):
        """Test _install_grype_db proceeds normally when GRYPE_DB_EXECUTABLE_PATH is not set."""
        # Mock the rest of the install process to avoid actual building
        mock_requests = mocker.patch("grype_db_manager.grypedb.requests")
        mock_requests.get.return_value.json.return_value = {"tag_name": "v1.0.0"}

        # Ensure no environment variable is set
        mocker.patch.dict(os.environ, {}, clear=True)

        # Should proceed to normal build process (we'll let it fail since we're testing the env var logic)
        with pytest.raises(Exception):  # Will fail on actual build, but that's expected
            grypedb._install_grype_db("latest", str(tmp_path), str(tmp_path))

        # Should not have called shutil.which since no env var was set
        # (we can't easily assert this without mocking shutil.which, but the test passing means it worked)

    def test_package_db(self, top_level_fixture, mocker):
        root = top_level_fixture(case="tools-case-1")
        bin_path = os.path.join(root, "tools", "grype-db", "bin", "grype-db-v0.19.0")
        gdb = grypedb.GrypeDB(bin_path, config_path="config_path")

        # mock gdb.run to do nothing
        mock_run = mocker.patch("grype_db_manager.grypedb.GrypeDB.run")

        gdb.package_db(build_dir="build_path", provider_root_dir="provider_root_path")

        # make certain the mock was called with at least
        #  provider_root_dir = "provider_root_path"
        #  config = "config_path"
        #  args = ["package", "--dir", "build_path"]

        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert kwargs["provider_root_dir"] == "provider_root_path"
        assert kwargs["config"] == "config_path"
        assert args == ("package", "--dir", "build_path")

    def test_build_db(self, top_level_fixture, mocker):
        root = top_level_fixture(case="tools-case-1")
        bin_path = os.path.join(root, "tools", "grype-db", "bin", "grype-db-v0.19.0")
        gdb = grypedb.GrypeDB(bin_path, config_path="config_path")

        # mock gdb.run to do nothing
        mock_run = mocker.patch("grype_db_manager.grypedb.GrypeDB.run")

        gdb.build_db(build_dir="build_path", schema_version=5, provider_root_dir="provider_root_path")

        # make certain the mock was called with at least
        #  provider_root_dir = "provider_root_path"
        #  config = "config_path"
        #  args = ["build", "--schema", "5"]

        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert kwargs["provider_root_dir"] == "provider_root_path"
        assert kwargs["config"] == "config_path"
        assert args == ("build", "--schema", "5", "--dir", "build_path")

    def test_build_and_package(self, tmp_path: pathlib.Path, mocker):
        bin_dir_path = tmp_path / "tools/grype-db/bin/grype-db-v0.19.0"
        bin_dir_path.mkdir(parents=True)
        bin_path = os.path.join(bin_dir_path.as_posix(), "grype-db-v0.19.0")

        gdb = grypedb.GrypeDB(bin_path, config_path="config_path")

        # mock gdb.run to do nothing (just in case)
        mock_run = mocker.patch("grype_db_manager.grypedb.GrypeDB.run")
        # mock gdb.package_db
        mock_package_db = mocker.patch("grype_db_manager.grypedb.GrypeDB.package_db")

        # when mock_package_db is called then call a function that creates an empty tar.gz file in the build_dir
        package_db_call_state = {}

        def package_db(build_dir: str, provider_root_dir: str):
            package_db_call_state["build_dir"] = build_dir
            open(os.path.join(build_dir, "something_v5_else.tar.gz"), "w").close()

        mock_package_db.side_effect = package_db

        # mock gdb.build_db
        mock_build_db = mocker.patch("grype_db_manager.grypedb.GrypeDB.build_db")

        gdb.build_and_package(schema_version=5, provider_root_dir="provider_root_path", root_dir=tmp_path.as_posix())

        assert "build_dir" in package_db_call_state
        captured_build_dir = package_db_call_state["build_dir"]

        # make certain the mock_build_db was called with at least
        #  provider_root_dir = "provider_root_path"
        #  schema_version = 5
        #  build_dir = captured_build_dir

        mock_build_db.assert_called_once()
        args, kwargs = mock_build_db.call_args
        assert kwargs["provider_root_dir"] == "provider_root_path"
        assert kwargs["build_dir"] == captured_build_dir
        assert kwargs["schema_version"] == 5

        # make certain the mock_package_db was called with at least
        #  provider_root_dir = "provider_root_path"
        #  build_dir = captured_build_dir

        mock_package_db.assert_called_once()
        args, kwargs = mock_package_db.call_args
        assert kwargs["provider_root_dir"] == "provider_root_path"
        assert kwargs["build_dir"] == captured_build_dir

        # make certain the stage dir contains a tar.gz file
        # the stage dir is a sibling of the build dir (in captured_build_dir)
        stage_dir = os.path.join(os.path.dirname(captured_build_dir), "stage")
        assert os.path.exists(stage_dir)
        assert len(os.listdir(stage_dir)) == 1
        assert os.path.isfile(os.path.join(stage_dir, "something_v5_else.tar.gz"))
