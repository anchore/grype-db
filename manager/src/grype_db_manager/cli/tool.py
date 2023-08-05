import os
import shutil

import click
from tabulate import tabulate

from grype_db_manager.cli import config
from grype_db_manager.grypedb import TOOLS_DIR, GrypeDB


@click.group(name="tool", help="manage local grype-db installations")
@click.pass_obj
def group(_: config.Application):
    pass


@group.command(name="list", help="list grype-db installations")
@click.pass_obj
def list_installed(cfg: config.Application):
    all_installations = GrypeDB.list_installed(root_dir=cfg.root)
    if not all_installations:
        click.echo("no grype-db installations found")
        return

    rows = []
    for installation in all_installations:
        row = [installation.version]
        rows.append(row)

    click.echo_via_pager(tabulate(rows, tablefmt="plain"))


@group.command(name="install", help="install grype-db at the configured version")
@click.pass_obj
def install(cfg: config.Application):
    GrypeDB.install(version=cfg.grype_db.version, root_dir=cfg.root)


@group.command(name="clear", help="delete all tools")
@click.pass_obj
def clear(cfg: config.Application):
    # recursively delete the tools dir
    tools_dir = os.path.join(cfg.root, TOOLS_DIR)
    if os.path.exists(tools_dir):
        shutil.rmtree(tools_dir)
        click.echo("tools deleted")
    else:
        click.echo("no tools to clear")
