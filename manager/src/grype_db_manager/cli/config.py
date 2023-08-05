from __future__ import annotations

import os
from dataclasses import dataclass, field

import mergedeep
import yaml
from dataclass_wizard import asdict, fromdict

DEFAULT_CONFIGS = (
    ".grype-db-manager.yaml",
    "grype-db-manager.yaml",
)

@dataclass
class Log:
    level: str = os.environ.get("GRYPE_DB_MANAGER_LOG_LEVEL", default="INFO")

    def __post_init__(self) -> None:
        self.level = self.level.upper()

@dataclass
class GrypeDB:
    version: str = os.environ.get("GRYPE_DB_MANAGER_GRYPE_DB_VERSION", default="latest")
    config: str = os.environ.get("GRYPE_DB_MANAGER_GRYPE_DB_CONFIG", default="")

@dataclass
class Grype:
    version: str = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_GRYPE_VERSION", default="latest")
    config: str = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_GRYPE_CONFIG", default="")

@dataclass
class Syft:
    version: str = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_SYFT_VERSION", default="latest")
    config: str = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_SYFT_CONFIG", default="")

@dataclass()
class Validate:
    images: list[str] = field(default_factory=list)
    grype: Grype = field(default_factory=Grype)
    syft: Syft = field(default_factory=Syft)
    default_max_year: int = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_DEFAULT_MAX_YEAR", default=2021)

    def __post_init__(self):
        # flatten elements in images (in case yaml anchors are used)
        images = []
        for image in self.images:
            if isinstance(image, list):
                images += image
            if image.startswith("["):
                # technically yaml anchors to lists of lists are interpreted as strings... which is terrible
                images += yaml.safe_load(image)
            else:
                images += [image]
        self.images = images

@dataclass
class Application:
    root: str = os.environ.get("GRYPE_DB_MANAGER_ROOT", default=".grype-db-manager")
    vunnel_root: str = os.environ.get("GRYPE_DB_VUNNEL_ROOT", default="data/vunnel")
    yardstick_root: str = os.environ.get("GRYPE_DB_YARDSTICK_ROOT", default="data/yardstick")
    log: Log = field(default_factory=Log)

    grype_db: GrypeDB = field(default_factory=GrypeDB)
    validate: Validate = field(default_factory=Validate)


def load(path: None | str | list[str] | tuple[str] = DEFAULT_CONFIGS) -> Application:
    cfg: Application | None = None
    try:
        if not path:
            path = DEFAULT_CONFIGS
        elif isinstance(path, str):
            if path == "":
                path = DEFAULT_CONFIGS
            else:
                cfg = _load(path)

        if not cfg:
            if isinstance(path, (list, tuple)):
                for p in path:
                    try:
                        cfg = _load(p)
                        break
                    except FileNotFoundError:
                        pass
            else:
                raise ValueError(f"invalid path type {type(path)}")
    except FileNotFoundError:
        cfg = Application()

    if not cfg:
        raise FileNotFoundError("no config found")


    return cfg

def _load(path: str) -> Application:
    try:
        with open(path, encoding="utf-8") as f:
            app_object = yaml.safe_load(f.read()) or {}
            # we need a full default application config first then merge the loaded config on top.
            # Why? dataclass_wizard.fromdict() will create instances from the dataclass default
            # and NOT the field definition from the container. So it is possible to specify a
            # single field in the config and all other fields would be set to the default value
            # based on the dataclass definition and not any field(default_factory=...) hints
            # from the containing class.
            instance = asdict(Application())

            mergedeep.merge(instance, app_object)
            cfg = fromdict(
                Application,
                instance,
            )
            if cfg is None:
                raise FileNotFoundError("parsed empty config")
    except FileNotFoundError:
        cfg = Application()

    return cfg
