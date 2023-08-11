from __future__ import annotations

import os
from dataclasses import dataclass, field

import mergedeep
import yaml
from dataclass_wizard import asdict, fromdict

from grype_db_manager import db

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
    version: str = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_DB_GRYPE_VERSION", default="latest")
    config: str = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_DB_GRYPE_CONFIG", default="")


@dataclass
class Syft:
    version: str = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_DB_SYFT_VERSION", default="latest")
    config: str = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_DB_SYFT_CONFIG", default="")


@dataclass
class ValidateDB:
    images: list[str] = field(default_factory=list)
    grype: Grype = field(default_factory=Grype)
    syft: Syft = field(default_factory=Syft)
    default_max_year: int = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_DB_DEFAULT_MAX_YEAR", default=2021)
    gate: db.validation.GateConfig = field(default_factory=db.validation.GateConfig)

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
class ValidateListing:
    image: str | None = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_LISTING_IMAGE", default=None)
    minimum_packages: int | None = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_LISTING_MINIMUM_PACKAGES", default=None)
    minimum_vulnerabilities: int | None = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_LISTING_MINIMUM_VULNERABILITIES", default=None)
    override_grype_version: str | None = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_LISTING_OVERRIDE_GRYPE_VERSION", default=None)
    override_db_schema_version: int | None = os.environ.get("GRYPE_DB_MANAGER_VALIDATE_LISTING_OVERRIDE_DB_SCHEMA_VERSION", default=None)


@dataclass()
class Validate:
    db: ValidateDB = field(default_factory=ValidateDB)
    listing: ValidateListing = field(default_factory=ValidateListing)


@dataclass()
class Distribution:
    listing_file_name: str = os.environ.get("GRYPE_DB_MANAGER_DISTRIBUTION_LISTING_FILE_NAME", default="listing.json")
    s3_path: str | None = os.environ.get("GRYPE_DB_MANAGER_DISTRIBUTION_S3_PATH", None)
    s3_bucket: str | None = os.environ.get("GRYPE_DB_MANAGER_DISTRIBUTION_S3_BUCKET", None)


@dataclass
class Application:
    root: str = os.environ.get("GRYPE_DB_MANAGER_ROOT", default=".grype-db-manager")
    vunnel_root: str = os.environ.get("GRYPE_DB_VUNNEL_ROOT", default="data/vunnel")
    yardstick_root: str = os.environ.get("GRYPE_DB_YARDSTICK_ROOT", default="data/yardstick")
    log: Log = field(default_factory=Log)

    grype_db: GrypeDB = field(default_factory=GrypeDB)
    validate: Validate = field(default_factory=Validate)
    distribution: Distribution = field(default_factory=Distribution)


def load(path: None | str | list[str] | tuple[str] = DEFAULT_CONFIGS) -> Application:
    cfg: Application | None = None
    try:
        cfg = _load_paths(path)
    except FileNotFoundError:
        cfg = Application()

    if not cfg:
        raise FileNotFoundError("no config found")

    return cfg


def _load_paths(path: None | str | list[str] | tuple[str] = DEFAULT_CONFIGS) -> Application | None:
    if not path:
        path = DEFAULT_CONFIGS
    elif isinstance(path, str):
        if path == "":
            path = DEFAULT_CONFIGS
        else:
            return _load(path)

    if isinstance(path, (list, tuple)):
        for p in path:
            try:
                return _load(p)
            except FileNotFoundError:
                return None
    raise ValueError(f"invalid path type {type(path)}")


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

    # wire up the gate configuration so any gates created will use values from the application config
    db.validation.Gate.set_default_config(cfg.validate.db.gate)
    gate_instance = db.validation.Gate(None, None)
    if gate_instance.config != cfg.validate.db.gate:
        raise ValueError("failed to set default gate config")

    return cfg
