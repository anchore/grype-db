#!/usr/bin/env python3 -u

import os
import sys
import json
import subprocess
import functools
import glob
from typing import Dict, List, Any

import click
from tabulate import tabulate

import yardstick
from publisher.utils.builder import GrypeDbBuilder

# filter results to only consider years before and at this year (inclusive)
MAX_YEAR = 2021
MAX_ALLOWED_DROPPED_UNIQUE_MATCHES = 10
MAX_ALLOWED_UNIQUE_MATCHES = 70
RESULT_SET_NAME = "acceptance-test"

TEST_IMAGES = [
    "anchore/test_images:vulnerabilities-alpine-3.11-d5be50d@sha256:01c78cee3fe398bf1f77566177770b07f1d2af01753c2434cb0735bd43a078b6",
    "anchore/test_images:vulnerabilities-alpine-3.12-d5be50d@sha256:55c9ba4e24e15c0467a071d93fead0990b8f04bb60b359b4056a997598aa56a1",
    "anchore/test_images:vulnerabilities-alpine-3.13-d5be50d@sha256:6749b1509fc4dd3f2b4e8688325fc5d447751bc9ae3be10c0f1fb92ec062b798",
    "anchore/test_images:vulnerabilities-alpine-3.14-d5be50d@sha256:fe242a3a63699425317fba0a749253bceb700fb3d63e7a0f6497f53a587e38c5",
    "anchore/test_images:vulnerabilities-alpine-3.15-d5be50d@sha256:7790691e5efae8bfe9cf4a4447312318d8daaf05ffd5f265ae913edf660f4653",
    "anchore/test_images:vulnerabilities-alpine-3.6-d5be50d@sha256:58637f273108e3e9eb4df4d73f7b6b1da303cbbf64f65e65fb7762482f2de63d",
    "anchore/test_images:vulnerabilities-alpine-3.8-d5be50d@sha256:a287a0ff98ac343aa710f4f4258d7198e240e9d416d5c7274663564202f832fb",
    "anchore/test_images:vulnerabilities-amazonlinux-2-5c26ce9@sha256:cf742eca189b02902a0a7926ac3fbb423e799937bf4358b0d2acc6cc36ab82aa",
    "anchore/test_images:vulnerabilities-centos@sha256:746d31247006cc06434ce91ccf3523b2c230ff6c378ffed7ca1c60bbb48ea86f",
    "anchore/test_images:vulnerabilities-debian@sha256:88e3684e2284fd61531cafd61a5fe3ce1258bcad2b7d4038bc0116abe59cb358",
    "anchore/test_images:vulnerabilities-no-distro-6bde59e@sha256:347fba6fbfa15d4e11217f9d49bf70a5a6eef35c6c642dc8c5db89115912d0c1",
    "anchore/test_images:vulnerabilities-oraclelinux-7-5c26ce9@sha256:4b28f61016b9d4ad0c0198343e4cc2bd51029f4a1733ed2c4bcc3e2d0dd71bbc",
    "anchore/test_images:vulnerabilities-ubuntu-16.04-d5be50d@sha256:05a70ba6d55e6d59b06ce8329bdd9540813e3d155ee7f41fe6044117caf81991",
    "anchore/test_images:vulnerabilities-ubuntu-18.04-5c26ce9@sha256:835483c1a36f6cf50bbf84dcef135b4640ea7d8eb9cf15b9edc4f1734f8335d4",
    "anchore/test_images:vulnerabilities-package-name-normalization-984794b@sha256:92f1981518e92bf3712ff95cf342f7f4d5fc83fb93a30a36d7d1204e64342199",
    "anchore/test_images:vulnerabilities-centos-stream9-ebc653b@sha256:3fa6909fa6f9a8ca8b7f9ba783af8cf84773c14084154073f1f331058ab646cb",
    "anchore/test_images:appstreams-centos-stream-8-1a287dd@sha256:808f6cf3cf4473eb39ff9bb47ead639d2ed71255b75b9b140162b58c6102bcc9",
    "anchore/test_images:appstreams-oraclelinux-8-1a287dd@sha256:c8d664b0e728d52f57eeb98ed1899c16d3b265f02ddfb41303d7a16c31e0b0f1",
    "anchore/test_images:appstreams-rhel-8-1a287dd@sha256:524ff8a75f21fd886ec7ed82387766df386671e8b77e898d05786118d5b7880b",
]


@functools.lru_cache(maxsize=1)
def repo_root() -> str:
    """ returns the absolute path of the repository root """
    try:
        base = subprocess.check_output('git rev-parse --show-toplevel', shell=True)
    except subprocess.CalledProcessError:
        raise IOError('Current working directory is not a git repository')
    return base.decode('utf-8').strip()


def grype_schema_version_mappings() -> Dict[str, str]:
    """ returns the mapping of schema versions to grype version that supports that schema version """
    with open(os.path.join(repo_root(), "grype-schema-version-mapping.json")) as fh:
        return json.load(fh)


@click.group()
def cli():
    yardstick.store.config.set_values(store_root=os.path.join(repo_root(), "test", "acceptance", "test-fixtures"))


@cli.command()
@click.pass_context
def test_all(ctx):
    print(f"testing all schema version: {list(grype_schema_version_mappings().keys())}")
    for schema_version in grype_schema_version_mappings().keys():
        ctx.invoke(generate, schema_version=schema_version)
        ctx.invoke(test, schema_version=schema_version)


@cli.command()
@click.option('--schema-version', '-s', required=True, help='The DB schema version to generate')
def generate(schema_version: str):
    build_dir = db_dir(schema_version=schema_version)
    cache_dir = os.path.join(repo_root(), "test", "acceptance", "cache")

    GrypeDbBuilder.build_db(build_dir=build_dir, schema_version=schema_version, cache_dir=cache_dir)
    GrypeDbBuilder.package_db(build_dir=build_dir, cache_dir=cache_dir)


@cli.command()
@click.option('--schema-version', '-s', required=True, help='The DB schema version to test')
@click.option('--images', '-i', default=None, help='The images to use as a test subject')
def test(schema_version: str, images: str):
    if not images:
        images = TEST_IMAGES

    print(f"testing schema-version={schema_version!r} against test-fixtures for images={images!r}")

    grype_version = grype_schema_version_mappings()[schema_version]
    db_archive_path = db_archive(schema_version)
    tool = get_tool(grype_version, db_import_path=db_archive_path)
    tool_request_name_version = f"grype@{grype_version}"

    # for label CVE lookups
    yardstick.utils.grype_db.raise_on_failure(False)
    yardstick.utils.grype_db.use(tool.db_root)

    result_set = yardstick.store.result_set.load(name=RESULT_SET_NAME)

    for image in images:
        print(f"testing image {image!r} schema-version={schema_version!r}")
        # get test fixture results relative to the request of the result set

        state = result_set.get(tool=tool_request_name_version, image=image)
        if not state:
            raise RuntimeError(f"could not find result set state for tool={tool_request_name_version} image={image}")
        fixture_config = state.config
        fixture_results = yardstick.store.scan_result.load(fixture_config, year_max_limit=MAX_YEAR)

        # get results with test DB
        test_tool_version = f"{grype_version}-test-DB"
        test_tool = f"grype@{test_tool_version}"
        test_config = yardstick.artifact.ScanConfiguration.new(image=image, tool=test_tool)
        actual_results, _ = yardstick.capture.run_scan(test_config, tool=tool)
        test_config.tool_version = test_tool_version

        actual_results = yardstick.store.scan_result.filter_by_year([actual_results], year_max_limit=MAX_YEAR)[0]

        # compare
        comparison = yardstick.comparison.ByPreservedMatch([actual_results, fixture_results])
        show_comparison(comparison)

        yesterdays_unique_matches = []
        todays_unique_matches = []
        for result_id, matches in comparison.unique.items():
            if result_id == fixture_results.ID:
                yesterdays_unique_matches = matches
            elif result_id == actual_results.ID:
                todays_unique_matches = matches
            else:
                raise RuntimeError(f"unknown results found: {result_id}")

        failed = False

        print(f"Quality Gates:")
        if len(yesterdays_unique_matches) > (len(todays_unique_matches) + MAX_ALLOWED_DROPPED_UNIQUE_MATCHES):
            print(f"   - unique matches quality gate: FAILED! Number of expected matches dropped relative to test fixture: test-fixture={len(yesterdays_unique_matches)} with-test-db={len(todays_unique_matches)}")
            failed = True
        else:
            print(f"   - unique matches quality gate: Passed")

        if len(todays_unique_matches) > MAX_ALLOWED_UNIQUE_MATCHES:
            print(f"   - max allowable matches quality gate: FAILED. Max allowable unique matches with test DB reached: limit={MAX_ALLOWED_UNIQUE_MATCHES} with-test-db={len(todays_unique_matches)}")
            failed = True
        else:
            print(f"   - max allowable matches quality gate: Passed")

        if failed:
            sys.exit(1)
        print()
        print("="*80)

    print()
    print(f"comparison passed!")


@cli.command()
@click.option('--schema-version', '-s', 'schema_versions', default=None, multiple=True, help='The DB schema versions to test')
@click.option('--image', '-i', 'images', default=None, multiple=True, help='The images to use as a test subject')
def capture_test_fixtures(schema_versions: List[str], images: List[str]):

    result_set = yardstick.artifact.ResultSet(name=RESULT_SET_NAME)

    if not images and not schema_versions:
        yardstick.store.scan_result.clear()

    if not schema_versions:
        schema_versions = grype_schema_version_mappings().keys()

    if not images:
        images = TEST_IMAGES

    for schema_version in schema_versions:
        print(f"capturing test fixture for schema-version={schema_version} images={images!r}")
        grype_version = grype_schema_version_mappings()[schema_version]

        for image in images:
            scan_config = yardstick.artifact.ScanConfiguration.new(image=image, tool=f"grype@{grype_version}")
            results, raw_json = yardstick.capture.run_scan(scan_config)
            yardstick.store.scan_result.save(raw_json, results)

            request = yardstick.artifact.ScanRequest(image=image, tool=f"grype@{grype_version}")
            result_set.add(request=request, scan_config=scan_config)

    yardstick.store.result_set.save(result_set)


def show_comparison(comparison):
    all_rows: List[List[Any]] = []
    for result in comparison.results:
        for unique_match in comparison.unique[result.ID]:
            all_rows.append(
                [
                    f"{result.config.tool_name}@{result.config.tool_version}-only",
                    unique_match.package.name,
                    unique_match.package.version,
                    unique_match.vulnerability.id,
                ]
            )

    all_rows = sorted(all_rows)
    print(tabulate(all_rows, tablefmt="plain"))
    print()
    print(comparison.summary)
    print()


def get_tool(version: str, **kwargs):
    config = yardstick.artifact.ScanConfiguration(image_repo="",
                                                  image_digest="",
                                                  image_tag="",
                                                  tool_name="grype",
                                                  tool_version=version)
    install_path = yardstick.store.tool.install_path(config=config)
    return yardstick.tool.Grype.install(version=version, path=install_path, **kwargs)


def db_dir(schema_version: str) -> str:
    build_dir = os.path.join(repo_root(), "test", "acceptance", "build")
    return os.path.join(build_dir, "v" + schema_version)


def db_archive(schema_version: str) -> str:
    pattern = db_dir(schema_version=schema_version) + f"/*_v{schema_version}_*.tar.*"
    matching = glob.glob(pattern)
    print(f"discovered DB archives: {matching}")
    return matching[0]


def setup_logging():
    import logging.config

    log_level = "INFO"

    logging.config.dictConfig(
        {
            "version": 1,
            "formatters": {
                "standard": {
                    # [%(module)s.%(funcName)s]
                    "format": "%(asctime)s [%(levelname)s] %(message)s",
                    "datefmt": "",
                },
            },
            "handlers": {
                "default": {
                    "level": log_level,
                    "formatter": "standard",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                },
            },
            "loggers": {
                "": {  # root logger
                    "handlers": ["default"],
                    "level": log_level,
                },
            },
        }
    )


if __name__ == '__main__':
    setup_logging()
    cli()
