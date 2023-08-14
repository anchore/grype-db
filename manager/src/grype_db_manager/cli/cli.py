from __future__ import annotations

import dataclasses
import datetime
import enum
import time
from typing import Any

import click
import yaml

from grype_db_manager import __name__ as package_name
from grype_db_manager.cli import config, db, listing, tool
from grype_db_manager.db.format import Format


@click.option("--verbose", "-v", default=False, help="show more verbose logging", count=True)
@click.option("--config", "-c", "config_path", default=None, help="override config path")
@click.group(help="A tool for publishing validated grype databases to S3 for distribution.")
@click.version_option(package_name=package_name, message="%(prog)s %(version)s")
@click.pass_context
def cli(ctx: click.core.Context, verbose: bool, config_path: str | None) -> None:
    import logging.config

    import colorlog

    ctx.obj = config.load(path=config_path)

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
    if verbose == 1:
        log_level = "DEBUG"
    elif verbose >= 2:
        log_level = "TRACE"

    logging.config.dictConfig(
        {
            "version": 1,
            "formatters": {
                "standard": {
                    "()": DeltaTimeFormatter,
                    # "format": "%(log_color)s[%(delta)s] %(levelname)5s %(message)s",
                    # "format": f"{ansi_grey}%(levelname)-5s{ansi_reset} %(log_color)s%(message)s",
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
    # noqa
    class IndentDumper(yaml.Dumper):
        def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:  # noqa: ARG002
            return super().increase_indent(flow, False)

    def enum_asdict_factory(data: list[tuple[str, Any]]) -> dict[Any, Any]:
        # prevents showing oddities such as
        #
        #   wolfi:
        #       request_timeout: 125
        #       runtime:
        #       existing_input: !!python/object/apply:vunnel.provider.InputStatePolicy
        #           - keep
        #       existing_results: !!python/object/apply:vunnel.provider.ResultStatePolicy
        #           - delete-before-write
        #       on_error:
        #           action: !!python/object/apply:vunnel.provider.OnErrorAction
        #           - fail
        #           input: !!python/object/apply:vunnel.provider.InputStatePolicy
        #           - keep
        #           results: !!python/object/apply:vunnel.provider.ResultStatePolicy
        #           - keep
        #           retry_count: 3
        #           retry_delay: 5
        #       result_store: !!python/object/apply:vunnel.result.StoreStrategy
        #           - flat-file
        #
        # and instead preferring:
        #
        #   wolfi:
        #       request_timeout: 125
        #       runtime:
        #       existing_input: keep
        #       existing_results: delete-before-write
        #       on_error:
        #           action: fail
        #           input: keep
        #           results: keep
        #           retry_count: 3
        #           retry_delay: 5
        #       result_store: flat-file

        def convert_value(obj: Any) -> Any:
            if isinstance(obj, enum.Enum):
                return obj.value
            return obj

        return {k: convert_value(v) for k, v in data}

    cfg_dict = dataclasses.asdict(cfg, dict_factory=enum_asdict_factory)
    print(yaml.dump(cfg_dict, Dumper=IndentDumper, default_flow_style=False))


cli.add_command(db.group)
cli.add_command(tool.group)
cli.add_command(listing.group)
