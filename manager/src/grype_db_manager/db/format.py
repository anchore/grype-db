import enum
import os


class Format(enum.Enum):
    HEADER = "\033[1m"  # noqa: PIE796
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    GREY = "\033[90m"
    FAIL = "\033[91m"
    BOLD = "\033[1m"  # noqa: PIE796
    UNDERLINE = "\033[4m"
    ITALIC = "\033[3m"
    RESET = "\033[0m"

    def __init__(self, value: str):
        if os.environ.get("NO_COLOR", None):
            self._value = ""
        else:
            self._value = value

    def __str__(self):
        return self._value
