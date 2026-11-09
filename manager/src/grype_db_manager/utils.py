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


def _override_env_var(name: str) -> str:
    # dashes can't appear in a shell-exported name (grype-db -> GRYPE_DB_EXECUTABLE_PATH)
    return f"{name.upper().replace('-', '_')}_EXECUTABLE_PATH"


def _executable_override(name: str) -> str | None:
    """the absolute path of the binary set by <NAME>_EXECUTABLE_PATH, or None when unset"""
    env_var = _override_env_var(name)
    override = os.getenv(env_var)
    if not override:
        return None
    resolved = shutil.which(os.path.expanduser(override))
    if not resolved:
        # an explicit override that can't be honored must not silently run a different binary
        msg = f"{env_var}={override!r} is not an executable file"
        raise FileNotFoundError(msg)
    logging.info(f"using {name} from {env_var}: {resolved}")
    return os.path.abspath(resolved)


def tool_path(name: str) -> str:
    """
    the path to a tool installed by binny (see .binny.yaml), unless overridden by <NAME>_EXECUTABLE_PATH
    (e.g. YARDSTICK_EXECUTABLE_PATH, or GRYPE_EXECUTABLE_PATH which only applies to grype main). The override
    allows running from an installed package, outside a checkout of this repo.
    """
    if override := _executable_override(name):
        return override

    hint = f"set {_override_env_var(name)} or run 'make bootstrap-tools' in a grype-db checkout"
    try:
        root = repo_root()
    except OSError as e:
        msg = f"{name} not found: {hint}"
        raise FileNotFoundError(msg) from e

    path = os.path.join(root, ".tool", name)
    if not os.path.exists(path):
        msg = f"{path} does not exist ({hint})"
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
