import logging
import os
import shutil

import click
import yardstick
from tabulate import tabulate
from yardstick.cli import config as ycfg
from yardstick.cli.validate import validate as yardstick_validate

from grype_db_manager import db, grypedb, s3utils
from grype_db_manager.cli import config, error
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


def remove_db(cfg: config.Application, db_uuid: str) -> None:
    db_manager = DBManager(root_dir=cfg.data.root)
    if db_manager.remove_db(db_uuid=db_uuid):
        click.echo(f"database {db_uuid!r} removed")
    click.echo(f"no database found with session id {db_uuid}")


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
    db_manager = DBManager(root_dir=cfg.data.root)
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
@click.option("--recapture", "-r", is_flag=True, help="recapture grype results (even if not stale)")
@click.option(
    "--skip-namespace-check",
    "skip_namespace_check",
    is_flag=True,
    help="do not ensure the minimum expected namespaces are present (for v6+ this is a providers-based check)",
)
@click.option("--force", "-f", is_flag=True, help="force validation even if disabled for the schema version")
@click.argument("db-uuid")
@click.pass_obj
@click.pass_context
def validate_db(
    ctx: click.Context,
    cfg: config.Application,
    db_uuid: str,
    images: list[str],
    recapture: bool,
    skip_namespace_check: bool,
    force: bool,
) -> None:
    logging.info(f"validating DB {db_uuid}")

    db_manager = DBManager(root_dir=cfg.data.root)
    db_info = db_manager.get_db_info(db_uuid=db_uuid)

    if not db_info:
        click.echo(f"no database found with session id {db_uuid}")
        return

    if not skip_namespace_check:
        if db_info.schema_version < 6:
            # ensure the minimum number of namespaces are present
            db_manager.validate_namespaces(db_uuid=db_uuid)
        else:
            # ensure the minimum number of namespaces are present
            db_manager.validate_providers(db_uuid=db_uuid, expected=cfg.validate.expected_providers)

    _validate_db(ctx, cfg, db_info, images, db_uuid, recapture, force=force)

    if db_info.schema_version >= 6:
        validations_enabled = db.schema.validations_enabled(db_info.schema_version)
        if not validations_enabled and not force:
            click.echo(f"{Format.BOLD}{Format.OKGREEN}Validation disabled, skipping{Format.RESET}")
            return

        _validate_latest(cfg, db_info.latest_path, db_info.archive_path)

    click.echo(f"{Format.BOLD}{Format.OKGREEN}Validation passed{Format.RESET}")


def _validate_db(
    ctx: click.Context,
    cfg: config.Application,
    db_info: grypedb.DBInfo,
    images: list[str],
    db_uuid: str,
    recapture: bool,
    force: bool = False,
) -> None:
    # resolve tool versions and install them
    yardstick.store.config.set_values(store_root=cfg.data.yardstick_root)

    validations_enabled = db.schema.validations_enabled(db_info.schema_version)
    if not validations_enabled and not force:
        click.echo(f"{Format.BOLD}{Format.OKGREEN}Validation disabled, skipping{Format.RESET}")
        return

    grype_version = db.schema.grype_version(db_info.schema_version)
    basis_grype_version = grype_version

    yardstick_profile_data = ycfg.Profiles()
    profile_name = None
    # this is a good example of how to add a custom profile configuration by a profile when working on a new schema version
    # if db_info.schema_version >= 6:
    #     profile_name = f"v{db_info.schema_version}"
    #     yardstick_profile_data = ycfg.Profiles(
    #         data={
    #             "grype[custom-db]": {
    #                 profile_name: {"config_path": f"./.grype-v{db_info.schema_version}.yaml"},
    #             },
    #         },
    #     )

    result_sets = {}
    for idx, rs in enumerate(cfg.validate.gates):
        if images:
            logging.info(f"filtering images for gate {idx}")
            rs.images = [i for i in rs.images if i in images]

        if not rs.images:
            logging.info(f"no images found for gate {idx}")
            continue

        if db_info.schema_version in rs.allow_empty_results_for_schemas:
            rs.gate.fail_on_empty_match_set = False

        logging.info(f"writing config for result set result_set_{idx}")

        result_sets[f"result_set_{idx}"] = ycfg.ResultSet(
            description=f"generated result set for gate {idx}",
            validations=[rs.gate],
            matrix=ycfg.ScanMatrix(
                images=rs.images,
                tools=[
                    ycfg.Tool(
                        label="custom-db",
                        name="grype",
                        version=grype_version + f"+import-db={db_info.archive_path}",
                        profile=profile_name,
                    ),
                    ycfg.Tool(
                        name="grype",
                        version=basis_grype_version,
                    ),
                ],
            ),
        )

    yardstick_cfg = ycfg.Application(
        profiles=yardstick_profile_data,
        store_root=cfg.data.yardstick_root,
        default_max_year=cfg.validate.default_max_year,
        result_sets=result_sets,
    )

    for r in result_sets:
        # workaround for test setup issues
        os.environ["GRYPE_DB_VALIDATE_BY_HASH_ON_START"] = "true"
        db.capture_results(
            cfg=yardstick_cfg,
            db_uuid=db_uuid,
            result_set=r,
            recapture=recapture,
            root_dir=cfg.data.root,
        )

    ctx.obj = yardstick_cfg

    try:
        ctx.invoke(
            yardstick_validate,
            always_run_label_comparison=False,
            breakdown_by_ecosystem=False,
            verbosity=cfg.verbosity,
            result_sets=[],
            all_result_sets=True,
        )
    except:
        if not validations_enabled and not force:
            click.echo(f"{Format.BOLD}{Format.OKGREEN}Validation disabled, ignoring failure{Format.RESET}")
            return
        raise


def _validate_latest(cfg: config.Application, latest_file: str, archive_path: str) -> None:
    with open(latest_file) as f:
        latest_obj = db.Latest.from_json(f.read())

    if not cfg.validate.listing.image:
        msg = "no image specified to validate against"
        raise ValueError(msg)

    if not cfg.validate.listing.minimum_packages:
        msg = "minimum packages must be specified"
        raise ValueError(msg)

    if not cfg.validate.listing.minimum_vulnerabilities:
        msg = "minimum vulnerabilities must be specified"
        raise ValueError(msg)

    logging.debug(f"validating latest.json with {cfg.validate.listing.image}")

    db.latest.smoke_test(
        latest_obj,
        archive_path,
        image=cfg.validate.listing.image,
        minimum_packages=cfg.validate.listing.minimum_packages,
        minimum_vulnerabilities=cfg.validate.listing.minimum_vulnerabilities,
    )


@group.command(name="upload", help="upload a grype database")
@click.option("--ttl-seconds", "-t", default=DEFAULT_TTL_SECONDS, help="the TTL for the uploaded DB (should be relatively high)")
@click.argument("db-uuid")
@click.pass_obj
@error.handle_exception(handle=(ValueError, s3utils.CredentialsError))
def upload_db(cfg: config.Application, db_uuid: str, ttl_seconds: int) -> None:
    if cfg.assert_aws_credentials:
        s3utils.check_credentials()

    s3_bucket = cfg.distribution.s3_bucket
    s3_path = cfg.distribution.s3_path

    db_manager = DBManager(root_dir=cfg.data.root)
    db_info = db_manager.get_db_info(db_uuid=db_uuid)

    if db_info.schema_version >= 6:
        if not os.path.exists(db_info.archive_path):
            msg = f"latest.json file not found for DB {db_uuid!r}"
            raise ValueError(msg)

        # /databases -> /databases/v6 , and is dynamic based on the schema version
        s3_path = f"{s3_path}/v{db_info.schema_version}"

    db_key = f"{s3_path}/{os.path.basename(db_info.archive_path)}"
    latest_key = f"{s3_path}/latest.json"

    s3utils.upload_file(
        bucket=s3_bucket,
        key=db_key,
        path=db_info.archive_path,
        CacheControl=f"public,max-age={ttl_seconds}",
    )

    click.echo(f"DB archive {db_uuid!r} uploaded to s3://{s3_bucket}/{s3_path}")

    if db_info.schema_version >= 6:
        s3utils.upload_file(
            bucket=s3_bucket,
            key=latest_key,
            path=db_info.latest_path,
            CacheControl="public,max-age=300",  # 5 minutes
        )

        click.echo(f"DB latest.json {db_uuid!r} uploaded to s3://{s3_bucket}/{s3_path}")


@group.command(name="build-and-upload", help="upload a grype database")
@click.option("--schema-version", "-s", required=True, help="the DB schema version to build, validate, and upload")
@click.option("--dry-run", "-d", is_flag=True, help="do not upload the DB to S3")
@click.option("--skip-validate", is_flag=True, help="skip validation of the DB")
@click.option(
    "--skip-namespace-check",
    "skip_namespace_check",
    is_flag=True,
    help="do not ensure the minimum expected namespaces are present (for v6+ this is a providers-based check)",
)
@click.pass_obj
@click.pass_context
@error.handle_exception(handle=(ValueError, s3utils.CredentialsError))
def build_and_upload_db(
    ctx: click.core.Context,
    cfg: config.Application,
    schema_version: str,
    skip_validate: bool,
    skip_namespace_check: bool,
    dry_run: bool,
) -> None:
    if dry_run:
        click.echo(f"{Format.ITALIC}Dry run! Will skip uploading the listing file to S3{Format.RESET}")
    elif cfg.assert_aws_credentials:
        s3utils.check_credentials()

    click.echo(f"{Format.BOLD}Building DB for schema v{schema_version}{Format.RESET}")
    db_uuid = ctx.invoke(build_db, schema_version=schema_version)

    if skip_validate:
        click.echo(f"{Format.ITALIC}Skipping validation of DB {db_uuid!r}{Format.RESET}")
    else:
        click.echo(f"{Format.BOLD}Validating DB {db_uuid!r}{Format.RESET}")
        ctx.invoke(validate_db, db_uuid=db_uuid, skip_namespace_check=skip_namespace_check)

    if not dry_run:
        click.echo(f"{Format.BOLD}Uploading DB {db_uuid!r}{Format.RESET}")
        ctx.invoke(upload_db, db_uuid=db_uuid)
    else:
        click.echo(f"{Format.ITALIC}Dry run! Skipping the upload of the DB to S3{Format.RESET}")
