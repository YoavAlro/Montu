"""montu.toml loading — the consuming repo's declaration of its monitoring contract.

The engine is deliberately vocabulary-neutral: it knows nothing about any observability
vendor, deployment tool, or framework, and nothing about how a particular repo models
its services. Every name it matches on, every path it resolves, and every field it
requires is declared by the consuming repo.

Concepts, all generic:
  unit        a deployable thing whose name appears in the telemetry backend
  owner       whatever a single spec covers (a service, an app, a worker)
  inventory   an optional file listing the owners a profile should cover
  variant     an optional per-owner mode recorded in the inventory
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field


class ConfigError(Exception):
    pass


@dataclass
class KindSpec:
    """One alert kind a profile allows, beyond the built-in `custom`."""

    name: str
    required: tuple[str, ...] = ()
    tokens: tuple[str, ...] = ()


@dataclass
class Inventory:
    """A file enumerating the owners a profile should cover."""

    glob: str
    entry_pattern: str
    default_variant: str = ""


@dataclass
class PathRule:
    """Assert a spec field matches an ancestor directory of the spec file."""

    spec_field: str
    ancestor: int = 0
    prefix: str = ""


@dataclass
class Profile:
    name: str
    spec_glob: str
    kinds: dict[str, KindSpec] = field(default_factory=dict)
    unit_suffix: str = ""
    required_fields: tuple[str, ...] = ()
    file_ref_fields: tuple[str, ...] = ()
    inventory: Inventory | None = None
    path_rules: tuple[PathRule, ...] = ()
    field_rules: dict[str, str] = field(default_factory=dict)
    variant_values: dict[str, str] = field(default_factory=dict)


@dataclass
class Config:
    root: str
    unit_sources_glob: str
    unit_pattern: str
    source_globs: tuple[str, ...]
    query_identifier_patterns: tuple[str, ...]
    custom_query_field: str
    id_field: str
    unit_field: str
    env: str
    profiles: dict[str, Profile]


def load_config(root: str, path: str | None = None) -> Config:
    config_path = path or os.path.join(root, "montu.toml")
    if not os.path.isfile(config_path):
        raise ConfigError(f"montu.toml not found at {config_path}")
    with open(config_path, "rb") as handle:
        raw = tomllib.load(handle)

    engine = raw.get("engine") or {}
    profiles_raw = raw.get("profiles") or {}
    if not profiles_raw:
        raise ConfigError("montu.toml defines no [profiles.*]")

    profiles: dict[str, Profile] = {}
    for name, prof in profiles_raw.items():
        profiles[name] = _load_profile(name, prof)

    return Config(
        root=root,
        unit_sources_glob=engine.get("unit_sources_glob", ""),
        unit_pattern=engine.get("unit_pattern", ""),
        source_globs=tuple(engine.get("source_globs") or ()),
        query_identifier_patterns=tuple(engine.get("query_identifier_patterns") or ()),
        custom_query_field=engine.get("custom_query_field", "query"),
        id_field=engine.get("id_field", "id"),
        unit_field=engine.get("unit_field", "unit"),
        env=engine.get("env", "production"),
        profiles=profiles,
    )


def _load_profile(name: str, prof: dict) -> Profile:
    spec_glob = prof.get("spec_glob")
    if not spec_glob:
        raise ConfigError(f"profile {name!r} has no spec_glob")

    inventory = None
    inv = prof.get("inventory")
    if inv:
        if not inv.get("glob") or not inv.get("entry_pattern"):
            raise ConfigError(
                f"profile {name!r} inventory needs both glob and entry_pattern "
                "(a regex whose group 1 is the owner id and optional group 2 the variant)"
            )
        inventory = Inventory(
            glob=inv["glob"],
            entry_pattern=inv["entry_pattern"],
            default_variant=inv.get("default_variant", ""),
        )

    path_rules = []
    for rule in prof.get("path_rules") or []:
        if not rule.get("field"):
            raise ConfigError(f"profile {name!r} has a path_rule with no field")
        path_rules.append(
            PathRule(
                spec_field=rule["field"],
                ancestor=int(rule.get("ancestor", 0)),
                prefix=rule.get("prefix", ""),
            )
        )

    kinds = {
        kind_name: KindSpec(
            name=kind_name,
            required=tuple(kind.get("required") or ()),
            tokens=tuple(kind.get("tokens") or ()),
        )
        for kind_name, kind in (prof.get("kinds") or {}).items()
    }

    return Profile(
        name=name,
        spec_glob=spec_glob,
        kinds=kinds,
        unit_suffix=prof.get("unit_suffix", ""),
        required_fields=tuple(prof.get("required_fields") or ()),
        file_ref_fields=tuple(prof.get("file_ref_fields") or ()),
        inventory=inventory,
        path_rules=tuple(path_rules),
        field_rules=dict(prof.get("field_rules") or {}),
        variant_values=dict(prof.get("variant_values") or {}),
    )
