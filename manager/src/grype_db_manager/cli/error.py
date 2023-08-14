from functools import partial, wraps

import click


class CLIError(click.ClickException):
    def format_message(self) -> str:
        return click.style(self.message, fg="red")


def handle_exception(func=None, *, handle):
    if not func:
        return partial(handle_exception, handle=handle)

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except handle as e:
            raise CLIError(e) from e

    return wrapper
