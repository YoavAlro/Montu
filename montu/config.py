"""montu.toml loading — the consuming repo's declaration of its monitoring contract.

The engine is provider-agnostic: it knows nothing about any observability vendor's query
language, deployment tooling, or naming. Everything provider- or repo-specific — where
specs live, how subsystems are derived, which tokens queries grep for, what the raw-query
field is called — is declared here by the consuming repo.
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
class Profile:
    name: str
    spec_glob: str
    kinds: dict[str, KindSpec] = field(default_factory=dict)
    subsystem_suffix: str = ""
    registry_glob: str = ""
    registry_entry_pattern: str = ""
    registry_default_routing: str = ""
    path_tenant_package_prefix: str = ""
    requires_tenant: bool = False
    requires_queue: bool = False
    queue_suffix: dict[str, str] = field(default_factory=dict)
    file_ref_fields: tuple[str, ...] = ()


@dataclass
class Config:
    root: str
    subsystem_sources_glob: str
    subsystem_pattern: str
    token_search_globs: tuple[str, ...]
    query_token_patterns: tuple[str, ...]
    custom_query_field: str
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
        spec_glob = prof.get("spec_glob")
        if not spec_glob:
            raise ConfigError(f"profile {name!r} has no spec_glob")
        if prof.get("registry_glob") and not prof.get("registry_entry_pattern"):
            raise ConfigError(
                f"profile {name!r} sets registry_glob without registry_entry_pattern "
                "(a regex whose group 1 is the app slug and optional group 2 the routing)"
            )
        kinds = {
            kind_name: KindSpec(
                name=kind_name,
                required=tuple(kind.get("required") or ()),
                tokens=tuple(kind.get("tokens") or ()),
            )
            for kind_name, kind in (prof.get("kinds") or {}).items()
        }
        profiles[name] = Profile(
            name=name,
            spec_glob=spec_glob,
            kinds=kinds,
            subsystem_suffix=prof.get("subsystem_suffix", ""),
            registry_glob=prof.get("registry_glob", ""),
            registry_entry_pattern=prof.get("registry_entry_pattern", ""),
            registry_default_routing=prof.get("registry_default_routing", ""),
            path_tenant_package_prefix=prof.get("path_tenant_package_prefix", ""),
            requires_tenant=bool(prof.get("requires_tenant", False)),
            requires_queue=bool(prof.get("requires_queue", False)),
            queue_suffix=dict(prof.get("queue_suffix") or {}),
            file_ref_fields=tuple(prof.get("file_ref_fields") or ()),
        )

    return Config(
        root=root,
        subsystem_sources_glob=engine.get("subsystem_sources_glob", ""),
        subsystem_pattern=engine.get("subsystem_pattern", ""),
        token_search_globs=tuple(engine.get("token_search_globs") or ()),
        query_token_patterns=tuple(engine.get("query_token_patterns") or ()),
        custom_query_field=engine.get("custom_query_field", "query"),
        env=engine.get("env", "production"),
        profiles=profiles,
    )
