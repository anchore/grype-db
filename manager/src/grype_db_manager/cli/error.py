from __future__ import annotations

from functools import partial, wraps
from typing import Any

import click


class CLIError(click.ClickException):
    def format_message(self) -> str:
        return click.style(self.message, fg="red")


def handle_exception(func: callable = None, *, handle: Any | tuple[Any, ...]) -> callable:  # noqa: RUF013
    if not func:
        return partial(handle_exception, handle=handle)

    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        try:
            return func(*args, **kwargs)
        except handle as e:
            raise CLIError(e) from e

    return wrapper
