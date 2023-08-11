from __future__ import annotations

import subprocess
import functools
import pathlib
import contextlib
import os


@functools.lru_cache(maxsize=1)
def repo_root() -> str:
    """returns the absolute path of the repository root"""
    try:
        base = subprocess.check_output("git rev-parse --show-toplevel", shell=True)
    except subprocess.CalledProcessError:
        raise IOError("Current working directory is not a git repository")
    return base.decode("utf-8").strip()


@contextlib.contextmanager
def set_directory(path: pathlib.Path | str):
    origin = pathlib.Path().absolute()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(origin)
