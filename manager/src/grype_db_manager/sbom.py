from __future__ import annotations

import os
import subprocess
import pathlib
import contextlib
import json
import datetime
import logging

import yardstick
from yardstick import store

SBOM_IMAGE_PREFIX = "ghcr.io/anchore/vml-sbom"
DEFAULT_RESULT_SET = "sboms"
TIMESTAMP_OCI_ANNOTATION_KEY = "io.anchore.yardstick.timestamp"
SOURCE_REPO = "https://github.com/anchore/vulnerability-match-labels"
DATA_LICENSE = "CC0-1.0"


def download(cfg: yardstick.cli.config.Application, result_set: str):
    # 1. derive a set of all images to operate on from the "sbom" result set
    result_set_config = cfg.result_sets.get(result_set, None)
    if not result_set_config:
        raise RuntimeError(f"no result set found for {result_set}")
    
    # 2. download all SBOM blobs from the OCI registry
    scan_requests = result_set_config.scan_requests()
    scan_config_by_oci_ref = {}
    idx = 0
    sbom_scan_requests = [r for r in scan_requests if r.tool.lower().startswith("syft")]
    
    logging.info(f"found {len(sbom_scan_requests)} configurations for SBOMs")
    for idx, r in enumerate(sbom_scan_requests):
        exists = store.scan_result.find(by_tool=r.tool, by_image=r.image)
        if exists:
            logging.info(f"skipping SBOM {idx+1} (already exists): {r.image} ")
            continue
        oci_ref, scan_config = _download_sbom_results(r)
        if oci_ref and scan_config:
            logging.info(f"downloading SBOM {idx+1}: {r.image}")
            scan_config_by_oci_ref[oci_ref] = scan_config
        else:
            logging.warning(f"failed to download SBOM {idx+1}: {r.image}")

    # 3. update the existing result set with the new downloaded references
    existing_result_set = None
    if yardstick.store.result_set.exists(name=result_set):
        existing_result_set = yardstick.store.result_set.load(result_set)
    else:
        existing_result_set = yardstick.artifact.ResultSet(name=result_set)
        for r in cfg.result_sets[result_set].scan_requests():
            existing_result_set.add(request=r, scan_config=None)

    for state in existing_result_set.state:
        oci_ref = oci_sbom_reference_from_image(state.request.image)
        if oci_ref in scan_config_by_oci_ref:
            state.config = scan_config_by_oci_ref[oci_ref]

    yardstick.store.result_set.save(results=existing_result_set)


def _download_sbom_results(request: yardstick.artifact.ScanRequest):
    oci_ref = oci_sbom_reference_from_image(request.image)
    proc = Oras.manifest_fetch(target=oci_ref, capture_output=True, fail_on_error=False)
    if proc.returncode != 0:
        return None, None
    
    manifest = json.loads(proc.stdout)
    annotations = manifest.get("annotations", {})
    timestamp_rfc3339 = annotations.get(TIMESTAMP_OCI_ANNOTATION_KEY, None)
    timestamp = datetime.datetime.fromisoformat(timestamp_rfc3339)

    if not timestamp:
        raise RuntimeError(f"no timestamp found for {oci_ref}")
    
    synthesized_config = yardstick.artifact.ScanConfiguration.new(image=request.image, tool=request.tool, timestamp=timestamp)
    data, _ = yardstick.store.scan_result.store_paths(config=synthesized_config)
    parent_dir = os.path.dirname(data)

    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir)

    try:
        Oras.pull(target=oci_ref, destination=parent_dir)
    except RuntimeError:
        return None, None

    scan_config = yardstick.store.scan_result.find_one(by_description=synthesized_config.path)
    if not scan_config:
        raise RuntimeError(f"no scan config found for {synthesized_config.path}")

    return oci_ref, scan_config


def oci_sbom_reference_from_image(image: str) -> str:
    img = yardstick.artifact.Image(image)
    # note: we need to keep the docker.io references for stable lookups
    return f"{SBOM_IMAGE_PREFIX}/{img.repository}:sha256-{img.digest.removeprefix('sha256:')}"


# why not use the python oras client? 
# The python oras client is not efficient with detecting existing large files (unlike the oras CLI)
class Oras:

    @classmethod
    def pull(cls, target: str, destination: str, **kwargs) -> subprocess.CompletedProcess:
        return cls.run("pull", target, **kwargs, cd=destination)

    @classmethod
    def push(cls, target: str, files: list[str], annotations: dict[str, str], **kwargs) -> subprocess.CompletedProcess:
        an = []
        for k, v in annotations.items():
            an.append("--annotation")
            an.append(f"{k}={v}")
        return cls.run("push", target, *files, *an, **kwargs)

    @classmethod
    def manifest_fetch(cls, target: str, **kwargs) -> subprocess.CompletedProcess:
        return cls.run("manifest", "fetch", target, **kwargs)


    @classmethod
    def run(cls, *args, cd: str | None = None, fail_on_error: bool = True, **kwargs) -> subprocess.CompletedProcess:
        def call():
            proc = subprocess.run([f"oras", *args], env=os.environ.copy(), **kwargs)

            if fail_on_error and proc.returncode != 0:
                raise RuntimeError(f"return code: {proc.returncode}")

            return proc

        if cd:
            with set_directory(cd):
                return call()
        return call()


@contextlib.contextmanager
def set_directory(path: pathlib.Path):
    origin = pathlib.Path().absolute()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(origin)

