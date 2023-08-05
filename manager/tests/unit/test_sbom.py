import datetime
import os
import subprocess
import shutil

import pytest
import yardstick.store.result_set
from yardstick import artifact
from yardstick.cli import config as ycfg

from grype_db_manager import sbom


class TestOras:
    def test_run(self):
        result = sbom.Oras.run("version", stdout=subprocess.DEVNULL)
        assert result.returncode == 0

    def test_run_failed(self):
        with pytest.raises(RuntimeError):
            sbom.Oras.run("not-a-real-command", stderr=subprocess.DEVNULL)

        ret = sbom.Oras.run("not-a-real-command", fail_on_error=False, stderr=subprocess.DEVNULL)
        assert ret.returncode != 0

    def test_run_cd(self, tmp_path, mocker):
        # check if tempdir exists as a dir
        assert tmp_path.is_dir()

        # mock subprocess.run within sbom package
        sub_mock = mocker.patch("grype_db_manager.sbom.subprocess.run")

        def check_cwd(*args, **kwargs):
            assert os.getcwd() == tmp_path.as_posix()

            return subprocess.CompletedProcess(args=[], returncode=0)

        sub_mock.side_effect = check_cwd

        sbom.Oras.run("version", cd=tmp_path.as_posix())

        sub_mock.assert_called_once()


def test_download(top_level_fixture_copy, mocker):
    root = top_level_fixture_copy(case="yardstick-sbom-result-set")

    oci_ref = "ghcr.io/anchore/vml-sbom/docker.io/ubuntu:sha256-aa6c2c047467afc828e77e306041b7fa4a65734fe3449a54aa9c280822b0d87d"
    scan_config = artifact.ScanConfiguration(
        ID="3ae4d03d-f04b-43eb-982c-8c2e1f966bad",
        image_repo="docker.io/ubuntu",
        image_tag="22.04",
        image_digest="sha256:aa6c2c047467afc828e77e306041b7fa4a65734fe3449a54aa9c280822b0d87d",
        tool_name="syft",
        tool_version="v0.74.1",
        timestamp=datetime.datetime.fromisoformat("2023-06-30T12:57:59.354289+00:00"),
    )

    # mock _download_sbom_results to return a known result
    mock_download_sbom_results = mocker.patch("grype_db_manager.sbom._download_sbom_results")
    mock_download_sbom_results.return_value = oci_ref, scan_config

    result_set = "test-set"
    yardstick_cfg = ycfg.Application(
        store_root=root,
        result_sets={
            result_set: ycfg.ResultSet(
                description="compare the latest published OSS DB with the latest (local) built DB",
                matrix=ycfg.ScanMatrix(
                    images=[
                        "docker.io/ubuntu:22.04@sha256:aa6c2c047467afc828e77e306041b7fa4a65734fe3449a54aa9c280822b0d87d",
                    ],
                    tools=[
                        ycfg.Tool(
                            name="syft",
                            produces="SBOM",
                            refresh=False,
                            version="v0.74.1",
                        ),
                        ycfg.Tool(
                            name="grype",
                            takes="SBOM",
                            version=f"latest+import-db=./some/custom/path.tar.gz",
                        ),
                        ycfg.Tool(
                            name="grype",
                            takes="SBOM",
                            version="latest",
                        ),
                    ],
                ),
            ),
        },
    )

    sbom.download(cfg=yardstick_cfg, result_set=result_set)

    # assert that we can get the downloaded SBOMs from the result set (via scan configs)
    result_set_obj = yardstick.store.result_set.load(name=result_set, store_root=root)

    result = result_set_obj.get(
        "syft@v0.74.1", "docker.io/ubuntu:22.04@sha256:aa6c2c047467afc828e77e306041b7fa4a65734fe3449a54aa9c280822b0d87d"
    )
    assert result
    assert result.config == scan_config


def test_download_sbom_results(top_level_fixture_copy, mocker):
    root = top_level_fixture_copy(case="yardstick-sbom-result-set")

    mock_oras_manifest_fetch = mocker.patch("grype_db_manager.sbom.Oras.manifest_fetch")
    mock_oras_manifest_fetch.return_value = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.unknown.config.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:b5c4364b060edc3cc9b244597cd1694153d5609d362e24e354b2fd6de91640b6","size":510,"annotations":{"org.opencontainers.image.title":"metadata.json"}},{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:597573c9bca53681b8c2a7b36072baf2d31aec35688c936c6527c5ab883a4447","size":1479471,"annotations":{"org.opencontainers.image.title":"data.json"}}],"annotations":{"io.anchore.yardstick.timestamp":"2023-06-30T12:57:59.354289+00:00","org.opencontainers.image.created":"2023-08-04T12:08:07Z","org.opencontainers.image.description":"sbom for docker.io/ubuntu@sha256:aa6c2c047467afc828e77e306041b7fa4a65734fe3449a54aa9c280822b0d87d captured with yardstick","org.opencontainers.image.licenses":"CC0-1.0","org.opencontainers.image.source":"https://github.com/anchore/vulnerability-match-labels"}}',
    )

    mock_pull = mocker.patch("grype_db_manager.sbom.Oras.pull")

    def side_effect(*args, **kwargs):
        # copy root/effect to root/result/store
        shutil.copytree(
            os.path.join(
                root,
                "effect",
                "docker.io+ubuntu@sha256:aa6c2c047467afc828e77e306041b7fa4a65734fe3449a54aa9c280822b0d87d",
            ),
            os.path.join(
                root,
                "result",
                "store",
                "docker.io+ubuntu@sha256:aa6c2c047467afc828e77e306041b7fa4a65734fe3449a54aa9c280822b0d87d",
            ),
            dirs_exist_ok=True,
        )

    mock_pull.side_effect = side_effect

    request = artifact.ScanRequest(
        image="docker.io/ubuntu:22.04@sha256:aa6c2c047467afc828e77e306041b7fa4a65734fe3449a54aa9c280822b0d87d",
        tool="syft@v0.74.1",
    )

    oci_ref, scan_config = sbom._download_sbom_results(request, store_root=root)

    assert (
        oci_ref
        == "ghcr.io/anchore/vml-sbom/docker.io/ubuntu:sha256-aa6c2c047467afc828e77e306041b7fa4a65734fe3449a54aa9c280822b0d87d"
    )
    assert scan_config == artifact.ScanConfiguration(
        ID="3ae4d03d-f04b-43eb-982c-8c2e1f966bad",
        image_repo="docker.io/ubuntu",
        image_tag="22.04",
        image_digest="sha256:aa6c2c047467afc828e77e306041b7fa4a65734fe3449a54aa9c280822b0d87d",
        tool_name="syft",
        tool_version="v0.74.1",
        timestamp=datetime.datetime.fromisoformat("2023-06-30T12:57:59.354289+00:00"),
    )
