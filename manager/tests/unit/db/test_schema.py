from grype_db_manager.db import schema


def test_grype_version():
    # str type
    assert "v0.7.0" == schema.grype_version("1")

    # all values
    assert "v0.7.0" == schema.grype_version(1)
    assert "v0.12.1" == schema.grype_version(2)
    assert "v0.40.1" == schema.grype_version(3)
    assert "v0.50.2" == schema.grype_version(4)
    assert "v0.87.0" == schema.grype_version(5)
    assert "main" == schema.grype_version(6)


def test_supported_schema_versions():
    assert schema.supported_schema_versions() == [5, 6]
