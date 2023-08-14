from __future__ import annotations

import contextlib
import functools
import os
import pathlib
import subprocess


@functools.lru_cache(maxsize=1)
def repo_root() -> str:
    try:
        base = subprocess.check_output("git rev-parse --show-toplevel", shell=True)  # noqa: S607, S602
    except subprocess.CalledProcessError as e:
        msg = "Current working directory is not a git repository"
        raise OSError(msg) from e
    return base.decode("utf-8").strip()


@contextlib.contextmanager
def set_directory(path: pathlib.Path | str):
    origin = pathlib.Path().absolute()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(origin)
