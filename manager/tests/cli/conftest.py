import os
import shlex
import subprocess
import pytest
import logging
from enum import Enum
from pathlib import Path
from contextlib import contextmanager
from tempfile import TemporaryDirectory


class Format(Enum):
    RESET = "\033[0m"
    GREEN = "\033[1;32m"
    RED = "\033[1;31m"
    GREY = "\033[0;37m"
    PURPLE = "\033[1;35m"
    ORANGE_BOLD = "\033[1;33m"
    ITALIC = "\033[3m"
    BOLD = "\033[1m"

    def render(self, text: str) -> str:
        return f"{self.value}{text}{Format.RESET.value}"


class CustomLogger(logging.Logger):

    def __init__(self, name, level=logging.NOTSET):
        super().__init__(name, level)
        self.test_function = None  # Placeholder for test-specific context

    def step(self, message: str):
        if self.test_function:
            message = f"[{self.test_function}] {message}"
        self.info(Format.GREEN.render(message))


@pytest.fixture(scope="function")
def logger(request):
    logging.setLoggerClass(CustomLogger)
    logger = logging.getLogger(f"test_logger_{id(object())}")
    logger.setLevel(logging.DEBUG)

    # set the test function name dynamically
    logger.test_function = request.node.name

    return logger


@pytest.fixture(scope="function", autouse=True)
def change_to_cli_dir(request):
    """
    Automatically change the working directory to the directory containing the test file
    if it's not already set, and revert back after the test.
    """
    # the directory of the current test file (which is in manage/tests/cli)
    cli_dir = request.fspath.dirname
    original_dir = os.getcwd()

    # bail if already in the target directory
    if os.path.samefile(original_dir, cli_dir):
        yield  # run the test
        return

    # change to the target directory
    if not os.path.isdir(cli_dir):
        raise FileNotFoundError(f"Expected directory '{cli_dir}' does not exist.")

    os.chdir(cli_dir)
    try:
        yield  # run the test
    finally:
        os.chdir(original_dir)  # revert to the original directory


@pytest.fixture(scope="session")
def temporary_dir() -> str:
    with TemporaryDirectory() as tmp_dir:
        yield tmp_dir


@pytest.fixture(scope="session")
def cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PATH"] = f"{os.path.abspath('bin')}:{env['PATH']}"  # add `bin` to PATH
    return env


class CommandHelper:

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def run(self, command: str, env=None, expect_fail=False, use_shell=True, **kwargs) -> tuple[str, str]:
        self.logger.info(Format.ITALIC.render(f"{command}"))

        process = subprocess.run(
            command if use_shell else shlex.split(command),
            shell=use_shell,  # use shell expansion if requested
            capture_output=True,
            text=True,
            env=env,
            **kwargs,
        )

        # log stdout and stderr when an error occurs
        if process.returncode != 0 and not expect_fail:
            self.logger.error(Format.RED.render("└── command failed unexpectedly"))
            log_lines(process.stdout, "    ", self.logger.error, Format.RED.render)
            log_lines(process.stderr, "    ", self.logger.error, Format.RED.render)
            raise AssertionError("command failed unexpectedly")
        elif process.returncode == 0 and expect_fail:
            self.logger.error(Format.RED.render("└── expected failure, but command succeeded"))
            log_lines(process.stdout, "    ", self.logger.error, Format.RED.render)
            log_lines(process.stderr, "    ", self.logger.error, Format.RED.render)
            raise AssertionError("command succeeded but was expected to fail")

        # log success
        self.logger.debug(Format.GREY.render("└── command succeeded"))
        return process.stdout.strip(), process.stderr.strip()

    @contextmanager
    def pushd(self, path, logger):
        """Temporarily change directory."""
        prev_dir = os.getcwd()
        logger.info(f"pushd {path}")
        os.chdir(path)
        try:
            yield
        finally:
            logger.info(f"popd # {prev_dir}")
            os.chdir(prev_dir)


def log_lines(text: str, prefix: str, lgr, renderer=None):
    for line in text.splitlines():
        msg = f"{prefix}{line}"
        if renderer:
            msg = renderer(msg)
        lgr(msg)


@pytest.fixture
def command(logger) -> CommandHelper:
    return CommandHelper(logger)


class GrypeHelper:
    def __init__(self, bin_dir: str | Path | None = None):
        if bin_dir:
            self.bin_dir = Path(bin_dir)
        else:
            self.bin_dir = None
        self.command = CommandHelper(logging.getLogger("grype"))

    def run(self, cmd: str, env: dict[str, str] | None = None, **kwargs) -> tuple[str, str]:
        return self.command.run(f"{self.bin_dir}/grype {cmd}", env=env, **kwargs)

    def install(self, branch_or_version: str, bin_dir: str | None = None, env: dict[str, str] | None = None) -> "GrypeHelper":
        """
        Install Grype either by building from a feature branch or downloading a prebuilt binary.
        """
        if not bin_dir and not self.bin_dir:
            raise ValueError("bin_dir is required for Grype installation")

        if bin_dir:
            bin_dir = Path(bin_dir)
        else:
            bin_dir = self.bin_dir

        grype_binary = Path(bin_dir) / "grype"

        if branch_or_version.startswith("v"):
            self.command.run(
                f"curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b {bin_dir} {branch_or_version}",
                use_shell=True,
                env=env,
            )

            if not grype_binary.exists():
                raise RuntimeError("Grype binary installation failed via install.sh")

        else:
            with TemporaryDirectory() as temp_dir:
                self.command.run(
                    f"git clone --branch {branch_or_version} https://github.com/anchore/grype.git {temp_dir}",
                    check=True,
                    env=env,
                )
                self.command.run(
                    f"go build -o {grype_binary} -ldflags '-X github.com/anchore/grype-db/pkg/grypedb.Version={branch_or_version}' ./cmd/grype",
                    cwd=temp_dir,
                    check=True,
                    env=env,
                )

            if not grype_binary.exists():
                raise RuntimeError("Grype binary build failed from feature branch")

        return GrypeHelper(bin_dir)


@pytest.fixture(scope="session")
def grype():
    return GrypeHelper()
