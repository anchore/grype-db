from __future__ import annotations

import datetime
import time
from typing import Any

import click

from grype_db_manager import __name__ as package_name
from grype_db_manager.cli import config, db, listing, tool
from grype_db_manager.db.format import Format


@click.option("--verbose", "-v", "verbosity", count=True, help="show details of all comparisons")
@click.option("--config", "-c", "config_path", default=None, help="config file path (required for subcommands)")
@click.group(help="A tool for publishing validated grype databases to S3 for distribution.")
@click.version_option(package_name=package_name, message="%(prog)s %(version)s")
@click.pass_context
def cli(ctx: click.core.Context, verbosity: int, config_path: str | None) -> None:
    # imported here to avoid configuring logging when this package is used as a library;
    # logging setup should only occur when the CLI is the entry point
    import logging.config  # noqa: PLC0415

    import colorlog  # noqa: PLC0415

    # config is required for subcommands, but not for --help or --version
    if ctx.invoked_subcommand is not None:
        if not config_path:
            msg = "missing required option: -c/--config"
            raise click.UsageError(msg)
        ctx.obj = config.load(path=config_path)
        ctx.obj.verbosity = verbosity
    elif config_path:
        # allow loading config even without subcommand (e.g., for future use)
        ctx.obj = config.load(path=config_path)
        ctx.obj.verbosity = verbosity

    class DeltaTimeFormatter(colorlog.ColoredFormatter):
        def __init__(self, *args: Any, **kwargs: Any):
            self.start_time = time.time()
            super().__init__(*args, **kwargs)

        def format(self, record: logging.LogRecord) -> str:  # noqa: A003
            elapsed_seconds = record.created - self.start_time
            elapsed = datetime.timedelta(seconds=elapsed_seconds)
            record.delta = f"{int(elapsed.total_seconds()):04d}"
            return super().format(record)

    log_level = ctx.obj.log.level
    if verbosity == 1:
        log_level = "DEBUG"
    elif verbosity >= 2:
        log_level = "TRACE"

    logging.config.dictConfig(
        {
            "version": 1,
            "formatters": {
                "standard": {
                    "()": DeltaTimeFormatter,
                    "format": f"{Format.GREY}%(delta)s{Format.RESET} %(log_color)s%(message)s",
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                    "log_colors": {
                        "TRACE": "purple",
                        "DEBUG": "cyan",
                        "INFO": "reset",
                        "BANNER": "blue",
                        "WARNING": "yellow",
                        "ERROR": "red",
                        "CRITICAL": "red,bg_white",
                    },
                },
            },
            "handlers": {
                "default": {
                    "level": log_level,
                    "formatter": "standard",
                    "class": "colorlog.StreamHandler",
                    "stream": "ext://sys.stderr",
                },
            },
            "loggers": {
                "": {  # root logger
                    "handlers": ["default"],
                    "level": log_level,
                },
            },
        },
    )


@cli.command(name="config", help="show the application config")
@click.pass_obj
def show_config(cfg: config.Application) -> None:
    # click.echo_via_pager(cfg.to_yaml())
    click.echo(cfg.to_yaml())


cli.add_command(db.group)
cli.add_command(tool.group)
cli.add_command(listing.group)
