from __future__ import annotations

import enum
import os
import sys
from dataclasses import dataclass, field
from typing import Any

import mergedeep
import yaml
from dataclass_wizard import asdict, fromdict

from grype_db_manager import db, s3utils

DEFAULT_CONFIGS = (
    ".grype-db-manager.yaml",
    "grype-db-manager.yaml",
)


def env_lookup(key: str, default: Any) -> callable:
    def _env_factory() -> Any:
        return os.environ.get(key, default)

    return _env_factory


@dataclass
class Log:
    level: str = field(default_factory=env_lookup("GRYPE_DB_MANAGER_LOG_LEVEL", default="INFO"))

    def __post_init__(self) -> None:
        self.level = self.level.upper()


@dataclass
class GrypeDB:
    version: str = field(default_factory=env_lookup("GRYPE_DB_MANAGER_GRYPE_DB_VERSION", default="latest"))
    config: str = field(default_factory=env_lookup("GRYPE_DB_MANAGER_GRYPE_DB_CONFIG", default=""))


@dataclass
class Grype:
    version: str = field(default_factory=env_lookup("GRYPE_DB_MANAGER_VALIDATE_DB_GRYPE_VERSION", default="latest"))
    config: str = field(default_factory=env_lookup("GRYPE_DB_MANAGER_VALIDATE_DB_GRYPE_CONFIG", default=""))


@dataclass
class Syft:
    version: str = field(default_factory=env_lookup("GRYPE_DB_MANAGER_VALIDATE_DB_SYFT_VERSION", default="latest"))
    config: str = field(default_factory=env_lookup("GRYPE_DB_MANAGER_VALIDATE_DB_SYFT_CONFIG", default=""))


@dataclass
class ValidateDB:
    images: list[str] = field(default_factory=list)
    grype: Grype = field(default_factory=Grype)
    syft: Syft = field(default_factory=Syft)
    default_max_year: int = field(default_factory=env_lookup("GRYPE_DB_MANAGER_VALIDATE_DB_DEFAULT_MAX_YEAR", default=2021))
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
    image: str | None = field(default_factory=env_lookup("GRYPE_DB_MANAGER_VALIDATE_LISTING_IMAGE", default=None))
    minimum_packages: int | None = field(
        default_factory=env_lookup("GRYPE_DB_MANAGER_VALIDATE_LISTING_MINIMUM_PACKAGES", default=None),
    )
    minimum_vulnerabilities: int | None = field(
        default_factory=env_lookup(
            "GRYPE_DB_MANAGER_VALIDATE_LISTING_MINIMUM_VULNERABILITIES",
            default=None,
        ),
    )
    override_grype_version: str | None = field(
        default_factory=env_lookup("GRYPE_DB_MANAGER_VALIDATE_LISTING_OVERRIDE_GRYPE_VERSION", default=None),
    )
    override_db_schema_version: int | None = field(
        default_factory=env_lookup(
            "GRYPE_DB_MANAGER_VALIDATE_LISTING_OVERRIDE_DB_SCHEMA_VERSION",
            default=None,
        ),
    )


@dataclass()
class Validate:
    db: ValidateDB = field(default_factory=ValidateDB)
    listing: ValidateListing = field(default_factory=ValidateListing)


@dataclass()
class Distribution:
    listing_file_name: str = field(
        default_factory=env_lookup("GRYPE_DB_MANAGER_DISTRIBUTION_LISTING_FILE_NAME", default="listing.json"),
    )
    s3_path: str | None = field(default_factory=env_lookup("GRYPE_DB_MANAGER_DISTRIBUTION_S3_PATH", None))
    s3_bucket: str | None = field(default_factory=env_lookup("GRYPE_DB_MANAGER_DISTRIBUTION_S3_BUCKET", None))
    s3_endpoint_url: str | None = field(default_factory=env_lookup("GRYPE_DB_MANAGER_DISTRIBUTION_S3_ENDPOINT_URL", None))
    aws_region: str | None = field(default_factory=env_lookup("GRYPE_DB_MANAGER_DISTRIBUTION_AWS_REGION", None))


@dataclass
class Application:
    root: str = field(default_factory=env_lookup("GRYPE_DB_MANAGER_ROOT", default=".grype-db-manager"))
    vunnel_root: str = field(default_factory=env_lookup("GRYPE_DB_VUNNEL_ROOT", default="data/vunnel"))
    yardstick_root: str = field(default_factory=env_lookup("GRYPE_DB_YARDSTICK_ROOT", default="data/yardstick"))
    log: Log = field(default_factory=Log)

    grype_db: GrypeDB = field(default_factory=GrypeDB)
    validate: Validate = field(default_factory=Validate)
    distribution: Distribution = field(default_factory=Distribution)

    def to_yaml(self) -> str:
        # noqa
        class IndentDumper(yaml.Dumper):
            def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:  # noqa: ARG002
                return super().increase_indent(flow, False)

        def enum_asdict_factory(data: list[tuple[str, Any]]) -> dict[Any, Any]:
            # prevents showing oddities such as
            #
            #   wolfi:
            #       request_timeout: 125
            #       runtime:
            #       existing_input: !!python/object/apply:vunnel.provider.InputStatePolicy
            #           - keep
            #       existing_results: !!python/object/apply:vunnel.provider.ResultStatePolicy
            #           - delete-before-write
            #       on_error:
            #           action: !!python/object/apply:vunnel.provider.OnErrorAction
            #           - fail
            #           input: !!python/object/apply:vunnel.provider.InputStatePolicy
            #           - keep
            #           results: !!python/object/apply:vunnel.provider.ResultStatePolicy
            #           - keep
            #           retry_count: 3
            #           retry_delay: 5
            #       result_store: !!python/object/apply:vunnel.result.StoreStrategy
            #           - flat-file
            #
            # and instead preferring:
            #
            #   wolfi:
            #       request_timeout: 125
            #       runtime:
            #       existing_input: keep
            #       existing_results: delete-before-write
            #       on_error:
            #           action: fail
            #           input: keep
            #           results: keep
            #           retry_count: 3
            #           retry_delay: 5
            #       result_store: flat-file

            def convert_value(obj: Any) -> Any:
                if isinstance(obj, enum.Enum):
                    return obj.value
                return obj

            return {k: convert_value(v) for k, v in data}

        cfg_dict = asdict(self, dict_factory=enum_asdict_factory)
        return yaml.dump(cfg_dict, Dumper=IndentDumper, default_flow_style=False)


def load(path: None | str | list[str] | tuple[str] = DEFAULT_CONFIGS, wire_values: bool = True) -> Application:
    cfg: Application | None = None
    try:
        cfg = _load_paths(path, wire_values=wire_values)
    except FileNotFoundError:
        cfg = Application()

    if not cfg:
        msg = "no config found"
        raise FileNotFoundError(msg)

    return cfg


def _load_paths(path: None | str | list[str] | tuple[str] = DEFAULT_CONFIGS, wire_values: bool = True) -> Application | None:
    if not path:
        path = DEFAULT_CONFIGS
    elif isinstance(path, str):
        if path == "":
            path = DEFAULT_CONFIGS
        else:
            return _load(path, wire_values=wire_values)

    if isinstance(path, (list, tuple)):
        for p in path:
            try:
                return _load(p, wire_values=wire_values)
            except FileNotFoundError:
                return None
    msg = f"invalid path type {type(path)}"
    raise ValueError(msg)


def _load(path: str, wire_values: bool = True) -> Application:
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
                # the "with open()" above will not raise an exception if the file does not exist, but if we
                # read the file and also get an empty config, we want to treat these two cases as the same
                # thing (as if a file was not found). The linter doesn't understand this dual usage of the
                # exception so this rule has been suppressed here.
                msg = "parsed empty config"
                raise FileNotFoundError(msg)  # noqa: TRY301
    except FileNotFoundError:
        cfg = Application()

    if wire_values:
        # wire up the gate configuration so any gates created will use values from the application config
        db.validation.Gate.set_default_config(cfg.validate.db.gate)
        gate_instance = db.validation.Gate(None, None)
        if gate_instance.config != cfg.validate.db.gate:
            msg = "failed to set default gate config"
            raise ValueError(msg)

        # setup the endpoint url and region for all s3 calls
        if cfg.distribution.s3_endpoint_url:
            sys.stderr.write(f"Overriding S3 endpoint URL: {cfg.distribution.s3_endpoint_url}\n")
            s3utils.ClientFactory.set_endpoint_url(cfg.distribution.s3_endpoint_url)
        else:
            # in case this is used back-to-back with a grype-db-manager run, reset the endpoint url
            s3utils.ClientFactory.set_endpoint_url(None)

        if cfg.distribution.aws_region:
            s3utils.ClientFactory.set_region_name(cfg.distribution.aws_region)
        else:
            # in case this is used back-to-back with a grype-db-manager run, reset the region
            s3utils.ClientFactory.set_region_name(None)

    return cfg
