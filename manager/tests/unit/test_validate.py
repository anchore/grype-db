
from grype_db_manager.validate import grype_version


def test_grype_version():
    assert "v0.7.0" == grype_version(1)
    assert "v0.12.1" == grype_version(2)
    assert "v0.40.1" == grype_version(3)
    assert "v0.50.2" == grype_version(4)
    assert "main" == grype_version(5)
