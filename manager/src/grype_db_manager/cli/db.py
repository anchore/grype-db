import logging
import os
import shutil
import sys

import click
import yardstick
from tabulate import tabulate
from yardstick import store
from yardstick.cli import config as ycfg
from yardstick.tool.grype import Grype
from yardstick.tool.syft import Syft

from grype_db_manager.cli import config
from grype_db_manager.format import Format
from grype_db_manager.grypedb import DB_DIR, DBManager, GrypeDB
from grype_db_manager.validate import validate


@click.group(name="db", help="manage local grype database builds")
@click.pass_obj
def group(_: config.Application):
    pass


@group.command(name="list", help="list databases")
@click.pass_obj
def list_dbs(cfg: config.Application):
    db_manager = DBManager(root_dir=cfg.root)

    dbs = sorted(db_manager.list_dbs(), key=lambda x: x.db_created)

    if not dbs:
        click.echo("no databases found")
        return

    rows = []
    for info in dbs:
        row = [info.session_id, info.schema_version, info.db_created]
        rows.append(row)

    headers = ["DB Session ID", "Schema", "Created"]
    click.echo_via_pager(tabulate(rows, headers=headers, tablefmt="plain"))


@group.command(name="clear", help="delete all databases")
@click.pass_obj
def clear_dbs(cfg: config.Application):
    db_dir = os.path.join(cfg.root, DB_DIR)
    if os.path.exists(db_dir):
        shutil.rmtree(db_dir)
        click.echo("databases deleted")
    else:
        click.echo("no databases to clear")


@group.command(name="build", help="build and validate a grype database")
@click.option("--schema-version", "-s", required=True, help="the DB schema version to build")
@click.pass_obj
def build_db(cfg: config.Application, schema_version: int) -> None:
    logging.info(f"build DB (schema v{schema_version})")

    grypedb = GrypeDB.install(version=cfg.grype_db.version, root_dir=cfg.root, config_path=cfg.grype_db.config)
    db_session_id = grypedb.build_and_package(schema_version=schema_version, provider_root_dir=cfg.vunnel_root, root_dir=cfg.root)
    print(db_session_id)


@group.command(name="show", help="show info about a specific grype database")
@click.argument("session-id")
@click.pass_obj
def show_db(cfg: config.Application, session_id: str) -> None:
    db_manager = DBManager(root_dir=cfg.root)
    db_info = db_manager.get_db_info(session_id=session_id)

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
@click.argument("session-id")
@click.pass_obj
def validate_db(cfg: config.Application, session_id: str, images: list[str], verbosity: int, recapture: bool) -> None:
    logging.info(f"validate DB (session id {session_id})")

    if not images:
        images = cfg.validate.images

    db_manager = DBManager(root_dir=cfg.root)
    db_info = db_manager.get_db_info(session_id=session_id)

    if not db_info:
        click.echo(f"no database found with session id {session_id}")
        return

    # resolve tool versions and install them
    yardstick.store.config.set_values(store_root=cfg.yardstick_root)

    # we do this to resolve to a specific version of each tool in the request configuation
    syft = Syft.install(version=cfg.validate.syft.version, within_path=store.tool.install_base(name="syft"))
    grype = Grype.install(version=cfg.validate.grype.version, within_path=store.tool.install_base(name="grype"))

    result_set = "db-validation"

    yardstick_cfg = ycfg.Application(
        store_root=cfg.yardstick_root,
        default_max_year=cfg.validate.default_max_year,
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
                            version=syft.version_detail,
                        ),
                        ycfg.Tool(
                            label="custom-db",
                            name="grype",
                            takes="SBOM",
                            version=grype.version_detail + f"+import-db={db_info.archive_path}",
                        ),
                        ycfg.Tool(
                            name="grype",
                            takes="SBOM",
                            version=grype.version_detail,
                        ),
                    ],
                ),
            ),
        },
    )

    gates = validate(
        cfg=yardstick_cfg,
        result_set=result_set,
        db_uuid=session_id,
        verbosity=verbosity,
        recapture=recapture,
        root_dir=cfg.root,
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
