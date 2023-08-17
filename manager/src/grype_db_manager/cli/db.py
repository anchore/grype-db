import logging
import os
import shutil
import sys

import click
import yardstick
from tabulate import tabulate
from yardstick.cli import config as ycfg
from yardstick.tool.syft import Syft

from grype_db_manager import db, s3utils
from grype_db_manager.cli import config
from grype_db_manager.db.format import Format
from grype_db_manager.grypedb import DB_DIR, DBManager, GrypeDB

# 1 year
DEFAULT_TTL_SECONDS = 31536000


@click.group(name="db", help="manage local grype database builds")
@click.pass_obj
def group(_: config.Application) -> None:
    pass


@group.command(name="list", help="list databases")
@click.pass_obj
def list_dbs(cfg: config.Application) -> None:
    db_manager = DBManager(root_dir=cfg.data.root)

    dbs = sorted(db_manager.list_dbs(), key=lambda x: x.db_created)

    if not dbs:
        click.echo("no databases found")
        return

    rows = []
    for info in dbs:
        row = [info.uuid, info.schema_version, info.db_created]
        rows.append(row)

    headers = ["DB Session ID", "Schema", "Created"]
    click.echo_via_pager(tabulate(rows, headers=headers, tablefmt="plain"))


@group.command(name="clear", help="delete all databases")
@click.pass_obj
def clear_dbs(cfg: config.Application) -> None:
    db_dir = os.path.join(cfg.data.root, DB_DIR)
    if os.path.exists(db_dir):
        shutil.rmtree(db_dir)
        click.echo("databases deleted")
    else:
        click.echo("no databases to clear")


@group.command(name="build", help="build and validate a grype database")
@click.option("--schema-version", "-s", required=True, help="the DB schema version to build")
@click.pass_obj
def build_db(cfg: config.Application, schema_version: int) -> str:
    logging.info(f"building DB (schema v{schema_version})")

    grypedb = GrypeDB.install(version=cfg.grype_db.version, root_dir=cfg.data.root, config_path=cfg.grype_db.config)
    db_uuid = grypedb.build_and_package(
        schema_version=schema_version,
        provider_root_dir=cfg.data.vunnel_root,
        root_dir=cfg.data.root,
    )
    click.echo(db_uuid)
    return db_uuid


@group.command(name="show", help="show info about a specific grype database")
@click.argument("db-uuid")
@click.pass_obj
def show_db(cfg: config.Application, db_uuid: str) -> None:
    db_manager = DBManager(root_dir=cfg.root)
    db_info = db_manager.get_db_info(db_uuid=db_uuid)

    d = db_info.__dict__
    for k, v in sorted(d.items()):
        print(f"{k:20s} {v}")


@group.command(name="validate", help="validate a grype database")
@click.option(
    "--image",
    "-i",
    "images",
    multiple=True,
    help="the image (or images) to validate with (default is to use all configured images)",
)
@click.option("--verbose", "-v", "verbosity", count=True, help="show details of all comparisons")
@click.option("--recapture", "-r", is_flag=True, help="recapture grype results (even if not stale)")
@click.argument("db-uuid")
@click.pass_obj
def validate_db(cfg: config.Application, db_uuid: str, images: list[str], verbosity: int, recapture: bool) -> None:
    logging.info(f"validating DB {db_uuid}")

    if not images:
        images = cfg.validate.db.images

    db_manager = DBManager(root_dir=cfg.data.root)
    db_info = db_manager.get_db_info(db_uuid=db_uuid)

    if not db_info:
        click.echo(f"no database found with session id {db_uuid}")
        return

    # resolve tool versions and install them
    yardstick.store.config.set_values(store_root=cfg.data.yardstick_root)

    # we do this to resolve to a specific version of each tool in the request configuration
    syft_version = cfg.validate.db.syft.version
    if cfg.validate.db.syft.version == "latest":
        syft_version = Syft.latest_version_from_github()

    grype_version = db.schema.grype_version(db_info.schema_version)

    result_set = "db-validation"

    yardstick_cfg = ycfg.Application(
        store_root=cfg.data.yardstick_root,
        default_max_year=cfg.validate.db.default_max_year,
        result_sets={
            result_set: ycfg.ResultSet(
                description="compare the latest published OSS DB with the latest (local) built DB",
                matrix=ycfg.ScanMatrix(
                    images=images,
                    tools=[
                        ycfg.Tool(
                            name="syft",
                            produces="SBOM",
                            refresh=False,
                            version=syft_version,
                        ),
                        ycfg.Tool(
                            label="custom-db",
                            name="grype",
                            takes="SBOM",
                            version=grype_version + f"+import-db={db_info.archive_path}",
                        ),
                        ycfg.Tool(
                            name="grype",
                            takes="SBOM",
                            version=grype_version,
                        ),
                    ],
                ),
            ),
        },
    )

    gates = db.validate(
        cfg=yardstick_cfg,
        result_set=result_set,
        db_uuid=db_uuid,
        verbosity=verbosity,
        recapture=recapture,
        root_dir=cfg.data.root,
    )

    failure = not all(gate.passed() for gate in gates)
    if failure:
        click.echo(f"{Format.BOLD}{Format.FAIL}Validation failed{Format.RESET}")
        click.echo("Reasons for quality gate failure:")

        for gate in gates:
            for reason in gate.reasons:
                click.echo(f"   - {reason}")

        sys.exit(1)

    click.echo(f"{Format.BOLD}{Format.OKGREEN}Validation passed{Format.RESET}")


@group.command(name="upload", help="upload a grype database")
@click.option("--ttl-seconds", "-t", default=DEFAULT_TTL_SECONDS, help="the TTL for the uploaded DB (should be relatively high)")
@click.argument("db-uuid")
@click.pass_obj
def upload_db(cfg: config.Application, db_uuid: str, ttl_seconds: int) -> None:
    s3_bucket = cfg.distribution.s3_bucket
    s3_path = cfg.distribution.s3_path

    db_manager = DBManager(root_dir=cfg.data.root)
    db_info = db_manager.get_db_info(db_uuid=db_uuid)

    key = f"{s3_path}/{os.path.basename(db_info.archive_path)}"

    s3utils.upload_file(
        bucket=s3_bucket,
        key=key,
        path=db_info.archive_path,
        CacheControl=f"public,max-age={ttl_seconds}",
    )

    click.echo(f"DB {db_uuid!r} uploaded to s3://{s3_bucket}/{s3_path}")


@group.command(name="build-and-upload", help="upload a grype database")
@click.option("--schema-version", "-s", required=True, help="the DB schema version to build, validate, and upload")
@click.option("--dry-run", "-d", is_flag=True, help="do not upload the DB to S3")
@click.option("--skip-validate", is_flag=True, help="skip validation of the DB")
@click.option("--verbose", "-v", "verbosity", count=True, help="show details of all comparisons")
@click.pass_context
def build_and_upload_db(
    ctx: click.core.Context,
    schema_version: str,
    skip_validate: bool,
    dry_run: bool,
    verbosity: bool,
) -> None:
    if skip_validate:
        click.echo(f"{Format.ITALIC}Dry run! Will skip uploading the listing file to S3{Format.RESET}")

    click.echo(f"{Format.BOLD}Building DB for schema v{schema_version}{Format.RESET}")
    db_uuid = ctx.invoke(build_db, schema_version=schema_version)

    click.echo(f"{Format.BOLD}Validating DB {db_uuid!r}{Format.RESET}")
    ctx.invoke(validate_db, db_uuid=db_uuid, verbosity=verbosity)

    if not dry_run:
        click.echo(f"{Format.BOLD}Uploading DB {db_uuid!r}{Format.RESET}")
        ctx.invoke(upload_db, db_uuid=db_uuid)
    else:
        click.echo(f"{Format.ITALIC}Dry run! Skipping the upload of the DB to S3{Format.RESET}")
