import subprocess
import functools


@functools.lru_cache(maxsize=1)
def repo_root() -> str:
    """returns the absolute path of the repository root"""
    try:
        base = subprocess.check_output("git rev-parse --show-toplevel", shell=True)
    except subprocess.CalledProcessError:
        raise IOError("Current working directory is not a git repository")
    return base.decode("utf-8").strip()
