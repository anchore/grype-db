from grype_db_manager.db import metadata


def test_to_and_from_json():

    subject = metadata.Metadata(
        built="2026-05-04T03:02:01Z",
        version=1,
    )

    expected_to = '{"built": "2026-05-04T03:02:01Z", "version": 1}'

    got_to = subject.to_json()

    assert expected_to == got_to

    got_from = metadata.Metadata.from_json(got_to)

    assert subject == got_from
