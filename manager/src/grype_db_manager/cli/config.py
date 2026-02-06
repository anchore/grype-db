from __future__ import annotations

import enum
import os
import sys
from dataclasses import dataclass, field, is_dataclass
from typing import TYPE_CHECKING, Any

import mergedeep
import yaml
import yaml_include  # pyyaml-include >= 2.x
from dataclass_wizard import asdict, fromdict
from yardstick.cli.config import Validation

from grype_db_manager import db, s3utils

if TYPE_CHECKING:
    from collections.abc import Mapping

# enable !include statements (legacy semantics: resolve relative to current CWD)
yaml.add_constructor("!include", yaml_include.Constructor(base_dir=os.getcwd()), Loader=yaml.SafeLoader)


@dataclass
class Log:
    level: str = "INFO"

    def __post_init__(self) -> None:
        self.level = self.level.upper()


@dataclass
class GrypeDB:
    version: str = ""
    config: str = ""


@dataclass
class Grype:
    config: str = ""


@dataclass
class ValidateDB:
    images: list[str] = field(default_factory=list)
    grype: Grype = field(default_factory=Grype)
    gate: Validation = field(default_factory=Validation)
    allow_empty_results_for_schemas: list[int] = field(default_factory=list)

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
    image: str | None = None
    minimum_packages: int | None = None
    minimum_vulnerabilities: int | None = None
    override_grype_version: str | None = None
    override_db_schema_version: int | None = None


@dataclass()
class Validate:
    default_max_year: int = 0
    gates: list[ValidateDB] = field(default_factory=list)
    listing: ValidateListing = field(default_factory=ValidateListing)
    expected_providers: list[str] = field(default_factory=list)


@dataclass()
class ListingReplica:
    listing_file_name: str = "listing.json"
    s3_path: str | None = None
    s3_bucket: str | None = None
    aws_region: str | None = None


@dataclass()
class Distribution:
    listing_file_name: str = "listing.json"
    s3_path: str | None = None
    s3_bucket: str | None = None
    s3_endpoint_url: str | None = None
    s3_always_suffix_schema_version: bool = False
    download_url_prefix: str | None = None
    aws_region: str | None = None
    listing_replicas: list[ListingReplica] = field(default_factory=list)


@dataclass
class Data:
    root: str = ""
    vunnel_root: str = ""
    yardstick_root: str = ""


@dataclass
class Application:
    verbosity: int = 0
    data: Data = field(default_factory=Data)
    log: Log = field(default_factory=Log)
    schema_mapping_file: str = ""  # default is to use built-in schema mapping
    grype_db: GrypeDB = field(default_factory=GrypeDB)
    validate: Validate = field(default_factory=Validate)
    distribution: Distribution = field(default_factory=Distribution)
    assert_aws_credentials: bool = True

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


def load(
    path: str,
    wire_values: bool = True,
    env: Mapping | None = None,
) -> Application:
    if not path:
        msg = "config path is required (use -c/--config)"
        raise ValueError(msg)

    return _load(path, wire_values=wire_values, env=env)


def _load(path: str, wire_values: bool = True, env: Mapping | None = None) -> Application:
    with open(path, encoding="utf-8") as f:
        app_object = yaml.load(f.read(), yaml.SafeLoader) or {}  # noqa: S506 (since our loader is using the safe loader)
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

    # 12 factor rules: env var > config file
    override_from_environment(cfg, prefix="GRYPE_DB_MANAGER", env=env)

    if wire_values:
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

        # ensure we're using the correct schema mapping file
        if cfg.schema_mapping_file:
            db.schema.register_mapping(cfg.schema_mapping_file)

    return cfg


def override_from_environment(obj: Any, prefix: str = "", path: str = "", env: Mapping | None = None) -> None:
    if env is None:
        env = os.environ

    for field_name, field_value in obj.__dict__.items():
        if is_dataclass(field_value):
            override_from_environment(
                field_value,
                prefix=prefix,
                path=f"{path}.{field_name}" if path else field_name,
                env=env,
            )

        else:
            full_path = f"{prefix}_{path.upper()}".replace(".", "_")
            env_var_name = f"{full_path}_{field_name.upper()}"
            env_value = env.get(env_var_name, None)
            if env_value is not None:
                setattr(obj, field_name, env_value)
