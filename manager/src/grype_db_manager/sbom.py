from __future__ import annotations

import datetime
import json
import logging
import os
import subprocess
from typing import TYPE_CHECKING

import yardstick
from yardstick import artifact, store

from grype_db_manager import utils

if TYPE_CHECKING:
    from yardstick.cli import config as ycfg

SBOM_IMAGE_PREFIX = "ghcr.io/anchore/vml-sbom"
TIMESTAMP_OCI_ANNOTATION_KEY = "io.anchore.yardstick.timestamp"


def download(cfg: ycfg.Application, result_set: str, store_root: str | None = None):
    # derive a set of all images to operate on from the "sbom" result set. This should always be based on the
    # input configuration, no past results.
    result_set_config = cfg.result_sets.get(result_set, None)
    if not result_set_config:
        raise RuntimeError(f"no result set found for {result_set}")

    scan_requests = result_set_config.scan_requests()
    sbom_scan_requests = [r for r in scan_requests if r.tool.lower().startswith("syft")]

    existing_result_set = _get_or_create_result_set(cfg, result_set, store_root=store_root)

    logging.info(f"found {len(sbom_scan_requests)} configurations for SBOMs")
    for idx, r in enumerate(sbom_scan_requests):
        # check to see if we already have the SBOM, if not download it
        exists = store.scan_result.find(by_tool=r.tool, by_image=r.image)
        if exists:
            if len(exists) > 1:
                print(exists)
                raise RuntimeError(f"multiple results found for {r.image} with tool {r.tool}")
            scan_config = exists[0]
            logging.info(f"skipping SBOM {idx+1}/{len(sbom_scan_requests)} (already exists): {r.image} ")
        else:
            logging.info(f"downloading SBOM {idx+1}/{len(sbom_scan_requests)}: {r.image}")

            oci_ref, scan_config = _download_sbom_results(r, store_root=store_root)
            if not oci_ref or not scan_config:
                logging.warning(f"failed to download SBOM {idx+1}: {r.image}")
                continue

        # make certain that the latest scan config is in place for the result set (update it if not)
        _update_sbom_scan_config(existing_result_set=existing_result_set, sbom_scan_config=scan_config, sbom_scan_request=r)

    yardstick.store.result_set.save(results=existing_result_set, store_root=store_root)


def _update_sbom_scan_config(
    existing_result_set: artifact.ResultSet,
    sbom_scan_config: artifact.ScanConfiguration,
    sbom_scan_request: artifact.ScanRequest,
):
    for state in existing_result_set.state:
        if state.request and not state.request.tool.lower().startswith("syft"):
            continue

        if state.request.image == sbom_scan_config.full_image:
            # update an existing scan config
            state.config = sbom_scan_config
            return

    # this did not exist already... add the request and config
    existing_result_set.add(request=sbom_scan_request, scan_config=sbom_scan_config)


def _get_or_create_result_set(cfg: ycfg.Application, result_set: str, store_root: str | None = None) -> artifact.ResultSet:
    if yardstick.store.result_set.exists(name=result_set, store_root=store_root):
        existing_result_set = yardstick.store.result_set.load(result_set, store_root=store_root)
    else:
        existing_result_set = yardstick.artifact.ResultSet(name=result_set)
        for r in cfg.result_sets[result_set].scan_requests():
            existing_result_set.add(request=r, scan_config=None)
    return existing_result_set


def _download_sbom_results(request: yardstick.artifact.ScanRequest, store_root: str | None = None):
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
    data, _ = yardstick.store.scan_result.store_paths(config=synthesized_config, store_root=store_root)
    parent_dir = os.path.dirname(data)

    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir)

    try:
        Oras.pull(target=oci_ref, destination=parent_dir)
    except RuntimeError:
        return None, None

    scan_config = yardstick.store.scan_result.find_one(by_description=synthesized_config.path, store_root=store_root)
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
    def manifest_fetch(cls, target: str, **kwargs) -> subprocess.CompletedProcess:
        return cls.run("manifest", "fetch", target, **kwargs)

    @classmethod
    def run(cls, *args, cd: str | None = None, fail_on_error: bool = True, **kwargs) -> subprocess.CompletedProcess:
        def call():
            proc = subprocess.run(["oras", *args], env=os.environ.copy(), **kwargs)  # noqa: S603, S607

            if fail_on_error and proc.returncode != 0:
                raise RuntimeError(f"return code: {proc.returncode}")

            return proc

        if cd:
            with utils.set_directory(cd):
                return call()
        return call()


