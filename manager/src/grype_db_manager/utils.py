from __future__ import annotations

import contextlib
import functools
import logging
import os
import pathlib
import shutil
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable


@functools.lru_cache(maxsize=1)
def repo_root() -> str:
    try:
        base = subprocess.check_output("git rev-parse --show-toplevel", shell=True)  # noqa: S607, S602
    except subprocess.CalledProcessError as e:
        msg = "Current working directory is not a git repository"
        raise OSError(msg) from e
    return base.decode("utf-8").strip()


def tool_path(name: str) -> str:
    """
    the path to a tool installed by binny (see .binny.yaml)

    If an environment variable <NAME>_EXECUTABLE_PATH (e.g. YARDSTICK_EXECUTABLE_PATH or GRYPE_EXECUTABLE_PATH) is set
    and points to an executable, that binary is used instead. This allows running from an installed package, outside
    a checkout of this repo.
    """
    env_var = f"{name.upper()}_EXECUTABLE_PATH"
    if override := os.getenv(env_var):
        if resolved := shutil.which(override):
            logging.info(f"using {name} from {env_var}: {resolved}")
            return resolved
        logging.warning(f"{env_var} points to non-executable: {override}")

    path = os.path.join(repo_root(), ".tool", name)
    if not os.path.exists(path):
        msg = f"{path} does not exist (run 'make bootstrap-tools' from the repo root)"
        raise FileNotFoundError(msg)
    return path


@contextlib.contextmanager
def set_directory(path: pathlib.Path | str) -> Iterable[None]:
    origin = pathlib.Path().absolute()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(origin)
