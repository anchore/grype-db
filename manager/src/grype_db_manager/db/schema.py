from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from dataclasses import dataclass, field

import mergedeep
from dataclass_wizard import asdict, fromdict


@dataclass
class SchemaEntry:
    schema: str
    grype_version: str
    supported: bool


@dataclass
class SchemaMapping:
    Available: list[SchemaEntry] = field(default_factory=list)

    def grype_version(self, schema_version: int) -> str | None:
        schema_version = str(schema_version)
        for entry in self.Available:
            if entry.schema == schema_version:
                return entry.grype_version

    def supported_schema_versions(self) -> list[int]:
        supported = []
        for entry in self.Available:
            if entry.supported:
                supported.append(int(entry.schema))
        return supported


@lru_cache
def _load() -> SchemaMapping:
    content = files("grype_db_manager.data").joinpath("schema-info.json").read_text()
    mapping_object = json.loads(content)

    # we need a full default application config first then merge the loaded config on top.
    # Why? dataclass_wizard.fromdict() will create instances from the dataclass default
    # and NOT the field definition from the container. So it is possible to specify a
    # single field in the config and all other fields would be set to the default value
    # based on the dataclass definition and not any field(default_factory=...) hints
    # from the containing class.
    instance = asdict(SchemaMapping())

    mergedeep.merge(instance, mapping_object)
    cfg = fromdict(
        SchemaMapping,
        instance,
    )
    if cfg is None:
        raise RuntimeError("cannot find schema mapping file")

    return cfg


def grype_version(schema_version: int) -> str:
    return _load().grype_version(schema_version)


def supported_schema_versions() -> list[int]:
    return _load().supported_schema_versions()
