import pytest

from grype_db_manager.sbom import Oras

class TestOras:

    def test_run(self):
        result = Oras.run("version")
        assert result.returncode == 0

    def test_run_failed(self):
        with pytest.raises(RuntimeError):
            Oras.run("not-a-real-command")
