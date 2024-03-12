from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from typing import Any

import mergedeep
from dataclass_wizard import asdict, fromdict

_mapping_file_content = None


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
        return None

    def supported_schema_versions(self) -> list[int]:
        supported = []
        for entry in self.Available:
            if entry.supported:
                supported.append(int(entry.schema))
        return supported


def register_mapping(file: str) -> None:
    with open(file) as f:
        global _mapping_file_content  # noqa: PLW0603
        _mapping_file_content = f.read()


@lru_cache
def _mapping() -> dict[str, Any]:
    content = (
        files("grype_db_manager.data").joinpath("schema-info.json").read_text()
        if _mapping_file_content is None
        else _mapping_file_content
    )
    return json.loads(content)


def _load() -> SchemaMapping:
    mapping_object = _mapping()

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
        msg = "cannot find schema mapping file"
        raise RuntimeError(msg)

    return cfg


def grype_version(schema_version: int) -> str:
    return _load().grype_version(schema_version)


def supported_schema_versions() -> list[int]:
    return _load().supported_schema_versions()
