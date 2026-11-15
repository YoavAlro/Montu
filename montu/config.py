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
from typing import Any

VALID_FIELD_TYPES = frozenset(
    {
        "bool",
        "str",
        "str_or_empty",
        "str_list",
        "pos_int",
        "nonneg_int",
        "int",
        "number",
        "hhmm",
    }
)


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class FieldTypeRule:
    """Type and numeric-bound constraint on a spec or alert field path."""

    kind: str
    gt: float | None = None
    gte: float | None = None
    lt: float | None = None
    lte: float | None = None
    lte_field: str | None = None


@dataclass
class ValueRule:
    """Fields an alert must carry when one of its fields holds a value or is set."""

    spec_field: str
    equals: str | None = None
    present: bool = False
    require: tuple[str, ...] = ()


@dataclass
class KindSpec:
    """One alert kind a profile allows, including the built-in `custom`.

    `required` is unconditional. `optional` declares extra permitted fields when
    closed-world `strict_keys` checking is enabled. `allowed_values` constrains a
    field's value (or list elements) when present; `field_types` constrains scalar/list
    types and numeric bounds; `requires_when` makes other fields mandatory for a given
    value or block presence.
    """

    name: str
    required: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()
    tokens: tuple[str, ...] = ()
    allowed_values: dict[str, tuple[str, ...]] = field(default_factory=dict)
    field_types: dict[str, FieldTypeRule] = field(default_factory=dict)
    requires_when: tuple[ValueRule, ...] = ()
    providers: dict[str, dict[str, Any]] = field(default_factory=dict)


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
    spec_globs: tuple[str, ...]
    kinds: dict[str, KindSpec] = field(default_factory=dict)
    unit_suffix: str = ""
    required_fields: tuple[str, ...] = ()
    file_ref_fields: tuple[str, ...] = ()
    name_template: str = ""
    common_alert_fields: tuple[str, ...] = ()
    common_allowed_values: dict[str, tuple[str, ...]] = field(default_factory=dict)
    common_requires_when: tuple[ValueRule, ...] = ()
    field_types: dict[str, FieldTypeRule] = field(default_factory=dict)
    inventory: Inventory | None = None
    path_rules: tuple[PathRule, ...] = ()
    field_rules: dict[str, str] = field(default_factory=dict)
    variant_values: dict[str, str] = field(default_factory=dict)
    providers: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def spec_glob(self) -> str:
        return self.spec_globs[0]


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
    strict_keys: bool = False
    spec_fields: tuple[str, ...] = ()
    spec_field_types: dict[str, FieldTypeRule] = field(default_factory=dict)
    providers: dict[str, dict[str, Any]] = field(default_factory=dict)


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

    providers_raw = raw.get("providers") or {}
    if not isinstance(providers_raw, dict):
        raise ConfigError("[providers] must be a table")

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
        strict_keys=bool(engine.get("strict_keys", False)),
        spec_fields=tuple(engine.get("spec_fields") or ()),
        spec_field_types=_load_field_types("engine.spec_field_types", engine.get("spec_field_types")),
        providers={str(k): dict(v) for k, v in providers_raw.items() if isinstance(v, dict)},
    )


def _load_spec_globs(profile_name: str, raw_glob: Any) -> tuple[str, ...]:
    if isinstance(raw_glob, str) and raw_glob.strip():
        return (raw_glob.strip(),)
    if (
        isinstance(raw_glob, list)
        and raw_glob
        and all(isinstance(item, str) and item.strip() for item in raw_glob)
    ):
        return tuple(item.strip() for item in raw_glob)
    raise ConfigError(f"profile {profile_name!r} needs a non-empty spec_glob string or list")


def _load_profile(name: str, prof: dict[str, Any]) -> Profile:
    spec_globs = _load_spec_globs(name, prof.get("spec_glob"))

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

    common_allowed = _load_allowed_values(f"profile {name!r}", prof.get("common_allowed_values"))
    common_rules = _load_value_rules(f"profile {name!r}", prof.get("common_requires_when"))
    prof_field_types = _load_field_types(f"profile {name!r}", prof.get("field_types"))

    kinds = {
        kind_name: _load_kind(f"{name}.{kind_name}", kind)
        for kind_name, kind in (prof.get("kinds") or {}).items()
    }

    prof_providers = prof.get("providers") or {}
    return Profile(
        name=name,
        spec_globs=spec_globs,
        kinds=kinds,
        unit_suffix=prof.get("unit_suffix", ""),
        required_fields=tuple(prof.get("required_fields") or ()),
        file_ref_fields=tuple(prof.get("file_ref_fields") or ()),
        name_template=str(prof.get("name_template") or ""),
        common_alert_fields=tuple(prof.get("common_alert_fields") or ()),
        common_allowed_values=common_allowed,
        common_requires_when=common_rules,
        field_types=prof_field_types,
        inventory=inventory,
        path_rules=tuple(path_rules),
        field_rules=dict(prof.get("field_rules") or {}),
        variant_values=dict(prof.get("variant_values") or {}),
        providers={str(k): dict(v) for k, v in prof_providers.items() if isinstance(v, dict)},
    )


def _load_value_rules(label: str, raw_rules: Any) -> tuple[ValueRule, ...]:
    rules = []
    for rule in raw_rules or []:
        has_equals = rule.get("equals") is not None
        has_present = bool(rule.get("present"))
        if not rule.get("field") or has_equals == has_present:
            raise ConfigError(
                f"{label} has a requires_when entry without field and exactly one "
                "of equals or present"
            )
        rules.append(
            ValueRule(
                spec_field=rule["field"],
                equals=str(rule["equals"]) if has_equals else None,
                present=has_present,
                require=tuple(rule.get("require") or ()),
            )
        )
    return tuple(rules)


def _load_allowed_values(label: str, raw_allowed: Any) -> dict[str, tuple[str, ...]]:
    allowed: dict[str, tuple[str, ...]] = {}
    for spec_field, values in (raw_allowed or {}).items():
        if not values:
            raise ConfigError(f"{label} declares allowed_values.{spec_field} as empty")
        allowed[spec_field] = tuple(str(value) for value in values)
    return allowed


def _load_field_types(label: str, raw_types: Any) -> dict[str, FieldTypeRule]:
    parsed: dict[str, FieldTypeRule] = {}
    for spec_field, spec in (raw_types or {}).items():
        if isinstance(spec, str):
            if spec not in VALID_FIELD_TYPES:
                raise ConfigError(
                    f"{label} field_types.{spec_field} {spec!r} not in {sorted(VALID_FIELD_TYPES)}"
                )
            parsed[spec_field] = FieldTypeRule(kind=spec)
        elif isinstance(spec, dict):
            kind = str(spec.get("type") or "")
            if kind not in VALID_FIELD_TYPES:
                raise ConfigError(
                    f"{label} field_types.{spec_field}.type {kind!r} not in {sorted(VALID_FIELD_TYPES)}"
                )
            unknown = set(spec) - {"type", "gt", "gte", "lt", "lte", "lte_field"}
            if unknown:
                raise ConfigError(
                    f"{label} field_types.{spec_field} has unknown constraint(s): {sorted(unknown)}"
                )
            parsed[spec_field] = FieldTypeRule(
                kind=kind,
                gt=float(spec["gt"]) if spec.get("gt") is not None else None,
                gte=float(spec["gte"]) if spec.get("gte") is not None else None,
                lt=float(spec["lt"]) if spec.get("lt") is not None else None,
                lte=float(spec["lte"]) if spec.get("lte") is not None else None,
                lte_field=str(spec["lte_field"]) if spec.get("lte_field") else None,
            )
        else:
            raise ConfigError(f"{label} field_types.{spec_field} must be a string or table")
    return parsed


def _load_kind(label: str, kind: dict[str, Any]) -> KindSpec:
    kind_providers = kind.get("providers") or {}
    return KindSpec(
        name=label.rpartition(".")[2],
        required=tuple(kind.get("required") or ()),
        optional=tuple(kind.get("optional") or ()),
        tokens=tuple(kind.get("tokens") or ()),
        allowed_values=_load_allowed_values(f"kind {label!r}", kind.get("allowed_values")),
        field_types=_load_field_types(f"kind {label!r}", kind.get("field_types")),
        requires_when=_load_value_rules(f"kind {label!r}", kind.get("requires_when")),
        providers={str(k): dict(v) for k, v in kind_providers.items() if isinstance(v, dict)},
    )
