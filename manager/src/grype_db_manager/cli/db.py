import click

import os
import shutil
import logging
import time

import yardstick
from tabulate import tabulate
from yardstick.cli import config as ycfg
from yardstick import store, artifact
from yardstick.tool.syft import Syft
from yardstick.tool.grype import Grype

from grype_db_manager.cli import config
from grype_db_manager.grypedb import GrypeDB, DBManager, DB_DIR
from grype_db_manager.validate import validate, RESULT_SET


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
def list_dbs(cfg: config.Application):
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
@click.option("--image", "-i", "images", multiple=True, help="the image (or images) to validate with (default is to use all configured images)")
@click.argument("session-id")
@click.pass_obj
def validate_db(cfg: config.Application, session_id: str, images: list[str]) -> None:
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

    syft = Syft.install(version=cfg.validate.syft.version, within_path=store.tool.install_base(name="syft"))
    grype = Grype.install(version=cfg.validate.grype.version, within_path=store.tool.install_base(name="grype"))

    yardstick_cfg = ycfg.Application(
        store_root=cfg.yardstick_root,
        result_sets={
            RESULT_SET: ycfg.ResultSet(
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
                )
            )
        }
    )

    validate(cfg=yardstick_cfg, db_uuid=session_id, root_dir=cfg.root)

    
