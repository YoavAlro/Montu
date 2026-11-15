"""The lint engine: validate every spec against the code it pins.

Always validates ALL specs a profile's glob discovers — never fix-on-touch — because
drift is usually caused by code changes (a unit rename, a variant flip, a renamed log
identifier) while the spec itself sits untouched.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import yaml

from montu.config import Config, KindSpec, Profile
from montu.repo import discover, extract_units, identifier_exists, read_inventory


@dataclass
class Finding:
    path: str
    code: str
    message: str
    is_error: bool = True

    def render(self) -> str:
        kind = "error" if self.is_error else "warning"
        return f"{self.path}:1: {kind} {self.code}: {self.message}"


class Linter:
    def __init__(self, config: Config):
        self.config = config
        self._units: set[str] | None = None

    def lint(self, only_paths: list[str] | None = None) -> tuple[list[Finding], int]:
        """Lint every discovered spec (or `only_paths`); returns (findings, spec count)."""
        findings: list[Finding] = []
        total = 0
        for profile in self.config.profiles.values():
            spec_rels = discover(self.config.root, profile.spec_glob)
            if only_paths is not None:
                spec_rels = [rel for rel in spec_rels if rel in only_paths]
            total += len(spec_rels)
            for rel in spec_rels:
                findings.extend(self._lint_spec(rel, profile))
            findings.extend(self._uncovered(profile, spec_rels))
        return findings, total

    # --- per-spec checks -------------------------------------------------------

    def _lint_spec(self, rel: str, profile: Profile) -> list[Finding]:
        abs_path = os.path.join(self.config.root, rel)
        try:
            with open(abs_path, encoding="utf-8") as handle:
                spec = yaml.safe_load(handle)
        except yaml.YAMLError as exc:
            return [Finding(rel, "E-YAML", f"unparseable: {exc}")]
        if not isinstance(spec, dict):
            return [Finding(rel, "E-YAML", "top level must be a mapping")]

        app = spec.get("app") or {}
        findings = self._check_schema(spec, app, rel, profile)
        findings.extend(self._check_paths(app, abs_path, rel, profile))
        findings.extend(self._check_inventory_and_fields(app, abs_path, rel, profile))
        findings.extend(self._check_unit(app, rel, profile))
        findings.extend(self._check_identifiers(spec, rel, profile))
        findings.extend(self._check_file_refs(spec, abs_path, rel, profile))
        return findings

    def _check_schema(self, spec: dict, app: dict, rel: str, profile: Profile) -> list[Finding]:
        findings: list[Finding] = []

        def err(msg: str) -> None:
            findings.append(Finding(rel, "E-SCHEMA", msg))

        if spec.get("version") != 1:
            err("version must be 1")
        required = {self.config.id_field, self.config.unit_field, *profile.required_fields}
        for field_name in sorted(required):
            if not isinstance(app.get(field_name), str) or not app.get(field_name):
                err(f"app.{field_name} is required and must be a non-empty string")
        if spec.get("env") != self.config.env:
            err(f"env must be {self.config.env!r} — the contract supports no other environment")
        if "slack_channel" not in spec:
            err("slack_channel is required (empty string until the webhook exists)")

        alerts = spec.get("alerts")
        if not isinstance(alerts, list) or not alerts:
            err("alerts must be a non-empty list")
            return findings
        valid_kinds = set(profile.kinds) | {"custom"}
        builtin_custom = ("name", self.config.custom_query_field, "condition")
        for i, alert in enumerate(alerts):
            if not isinstance(alert, dict):
                err(f"alerts[{i}] must be a mapping")
                continue
            kind = alert.get("kind")
            if kind not in valid_kinds:
                err(f"alerts[{i}].kind {kind!r} not in {sorted(valid_kinds)} for profile {profile.name!r}")
                continue
            declared = profile.kinds.get(kind)
            required = declared.required if declared else ()
            if kind == "custom":
                # The built-in fields are a floor a declared `custom` kind adds to, never
                # replaces — otherwise declaring one to add a field would silently drop them.
                required = tuple(dict.fromkeys(builtin_custom + required))
            reported_prefixes: set[str] = set()
            for field_name in required:
                if _ancestor_reported(field_name, reported_prefixes):
                    continue
                value, type_err = _resolve_field(alert, field_name)
                if type_err is not None:
                    prefix = type_err.split(" ", 1)[0]
                    if prefix not in reported_prefixes:
                        err(f"alerts[{i}] ({kind}) {type_err}")
                        reported_prefixes.add(prefix)
                elif value is None:
                    err(f"alerts[{i}] ({kind}) requires {field_name}")
                    reported_prefixes.add(field_name)
            if declared is not None:
                findings.extend(
                    self._check_values(alert, i, kind, declared, rel, reported_prefixes)
                )
            if not (alert.get("runbook") or "").strip():
                findings.append(
                    Finding(
                        rel,
                        "W-NO-RUNBOOK",
                        f"alerts[{i}] ({kind}) has no runbook — when it fires, the alert "
                        "description carries no triage instructions",
                        is_error=False,
                    )
                )
        return findings

    def _check_values(
        self,
        alert: dict,
        index: int,
        kind: str,
        declared: KindSpec,
        rel: str,
        reported_prefixes: set[str],
    ) -> list[Finding]:
        """A field's permitted values, and the fields another field obliges.

        Lets a repo say "this value (or presence) of that field obliges these other
        fields" — including dotted paths into structured blocks — without the engine
        learning what any of them mean.
        """
        findings: list[Finding] = []

        def schema_err(prefix: str, msg: str) -> None:
            if prefix not in reported_prefixes:
                findings.append(Finding(rel, "E-SCHEMA", f"alerts[{index}] ({kind}) {msg}"))
                reported_prefixes.add(prefix)

        for spec_field, allowed in declared.allowed_values.items():
            if _ancestor_reported(spec_field, reported_prefixes):
                continue
            value, type_err = _resolve_field(alert, spec_field)
            if type_err is not None:
                schema_err(type_err.split(" ", 1)[0], type_err)
                continue
            if value is None:
                continue  # presence is `required`'s job, not this check's
            if str(value) not in allowed:
                findings.append(
                    Finding(
                        rel,
                        "E-VALUE",
                        f"alerts[{index}] ({kind}) {spec_field} {value!r} is not one of "
                        f"{list(allowed)}",
                    )
                )
        for rule in declared.requires_when:
            if _ancestor_reported(rule.spec_field, reported_prefixes):
                continue
            gate_val, type_err = _resolve_field(alert, rule.spec_field)
            if type_err is not None:
                schema_err(type_err.split(" ", 1)[0], type_err)
                continue
            if rule.present:
                triggered = gate_val is not None
            else:
                triggered = gate_val is not None and str(gate_val) == rule.equals
            if not triggered:
                continue
            why = (
                f"when {rule.spec_field} is set"
                if rule.present
                else f"when {rule.spec_field} is {rule.equals!r}"
            )
            for spec_field in rule.require:
                if _ancestor_reported(spec_field, reported_prefixes):
                    continue
                req_val, req_type_err = _resolve_field(alert, spec_field)
                if req_type_err is not None:
                    schema_err(req_type_err.split(" ", 1)[0], req_type_err)
                elif req_val is None:
                    findings.append(
                        Finding(
                            rel,
                            "E-SCHEMA",
                            f"alerts[{index}] ({kind}) requires {spec_field} {why}",
                        )
                    )
                    reported_prefixes.add(spec_field)
        return findings

    def _check_paths(self, app: dict, abs_path: str, rel: str, profile: Profile) -> list[Finding]:
        """Spec fields that must agree with where the spec sits in the tree."""
        findings = []
        spec_dir = os.path.dirname(abs_path)
        for rule in profile.path_rules:
            value = app.get(rule.spec_field)
            if not value:
                continue
            directory = spec_dir
            for _ in range(rule.ancestor):
                directory = os.path.dirname(directory)
            actual = os.path.basename(directory)
            if actual != f"{rule.prefix}{value}":
                findings.append(
                    Finding(
                        rel,
                        "E-PATH",
                        f"app.{rule.spec_field} {value!r} disagrees with the directory "
                        f"{rule.ancestor} level(s) up ({actual!r}, expected "
                        f"{rule.prefix + str(value)!r})",
                    )
                )
        return findings

    def _check_inventory_and_fields(
        self, app: dict, abs_path: str, rel: str, profile: Profile
    ) -> list[Finding]:
        """Owner listed in the inventory, and fields derived from its id + variant."""
        if profile.inventory is None:
            return []
        findings: list[Finding] = []
        owner_id = app.get(self.config.id_field)
        inventory_path = self._inventory_for(abs_path, profile)
        entries = read_inventory(
            inventory_path, profile.inventory.entry_pattern, profile.inventory.default_variant
        )
        variant = entries.get(owner_id or "")
        if owner_id and variant is None:
            findings.append(
                Finding(
                    rel,
                    "E-INVENTORY",
                    f"{owner_id!r} has no entry in "
                    f"{os.path.relpath(inventory_path, self.config.root)}",
                )
            )
            return findings

        for spec_field, template in profile.field_rules.items():
            expected = template.format(
                id=owner_id, variant=profile.variant_values.get(variant or "", variant or "")
            )
            if app.get(spec_field) != expected:
                findings.append(
                    Finding(
                        rel,
                        "E-FIELD",
                        f"app.{spec_field} {app.get(spec_field)!r} != {expected!r} "
                        f"(inventory variant is {variant!r})",
                    )
                )
        return findings

    def _check_unit(self, app: dict, rel: str, profile: Profile) -> list[Finding]:
        unit = app.get(self.config.unit_field)
        if not unit or not self.config.unit_sources_glob:
            return []
        units = self._units
        if units is None:
            units = self._units = extract_units(
                self.config.root, self.config.unit_sources_glob, self.config.unit_pattern
            )
        if unit not in {name + profile.unit_suffix for name in units}:
            return [
                Finding(
                    rel,
                    "E-UNIT",
                    f"{unit!r} matches no name extracted from "
                    f"{self.config.unit_sources_glob} — renamed or removed",
                )
            ]
        return []

    def _check_identifiers(self, spec: dict, rel: str, profile: Profile) -> list[Finding]:
        """Every identifier an alert's query references must exist in tracked sources."""
        findings: list[Finding] = []
        for alert in spec.get("alerts") or []:
            kind = (alert or {}).get("kind")
            if kind == "custom":
                query = alert.get(self.config.custom_query_field) or ""
                identifiers: tuple[str, ...] = ()
                for pattern in self.config.query_identifier_patterns:
                    identifiers += tuple(re.findall(pattern, query))
            elif kind in profile.kinds:
                identifiers = profile.kinds[kind].tokens
            else:
                continue
            for identifier in identifiers:
                if not identifier_exists(self.config.root, identifier, self.config.source_globs):
                    findings.append(
                        Finding(
                            rel,
                            "E-TOKEN",
                            f"alert kind {kind!r} references '{identifier}' but no tracked "
                            "source defines it — renamed? Update the emitting code or the "
                            "spec (and re-apply)",
                        )
                    )
        return findings

    def _check_file_refs(
        self, spec: dict, abs_path: str, rel: str, profile: Profile
    ) -> list[Finding]:
        """Spec fields naming a sibling file (e.g. a dashboard model) must resolve."""
        findings = []
        spec_dir = os.path.dirname(abs_path)
        for field_name in profile.file_ref_fields:
            referenced = spec.get(field_name)
            if referenced and not os.path.isfile(os.path.join(spec_dir, referenced)):
                findings.append(
                    Finding(
                        rel,
                        "E-FILEREF",
                        f"{field_name}: {referenced!r} does not exist next to the spec",
                    )
                )
        return findings

    def _uncovered(self, profile: Profile, spec_rels: list[str]) -> list[Finding]:
        """Owners the inventory lists that no spec covers."""
        if profile.inventory is None:
            return []
        covered = {os.path.basename(os.path.dirname(rel)) for rel in spec_rels}
        findings = []
        for inventory_rel in discover(self.config.root, profile.inventory.glob):
            entries = read_inventory(
                os.path.join(self.config.root, inventory_rel),
                profile.inventory.entry_pattern,
                profile.inventory.default_variant,
            )
            for owner_id in entries:
                if owner_id not in covered:
                    findings.append(
                        Finding(
                            inventory_rel,
                            "W-UNMONITORED",
                            f"{owner_id!r} is in the inventory but has no spec",
                            is_error=False,
                        )
                    )
        return findings

    def _inventory_for(self, spec_abs_path: str, profile: Profile) -> str:
        """The inventory file governing this spec: the nearest match walking upward."""
        assert profile.inventory is not None
        candidates = {
            os.path.join(self.config.root, rel)
            for rel in discover(self.config.root, profile.inventory.glob)
        }
        directory = os.path.dirname(spec_abs_path)
        while True:
            for candidate in candidates:
                if os.path.dirname(candidate) == directory:
                    return candidate
            parent = os.path.dirname(directory)
            if parent == directory:
                return next(iter(sorted(candidates)), "")
            directory = parent


def _resolve_field(mapping: dict, field_path: str) -> tuple[object, str | None]:
    """Walk a dotted field path across nested mappings.

    Returns (value, type_error). When an intermediate segment is set to a scalar or
    list instead of a mapping, `type_error` names that segment so a prose string where
    a structured block was declared fails with E-SCHEMA instead of reading as absent.
    """
    current: object = mapping
    parts = field_path.split(".")
    for idx, part in enumerate(parts):
        if not isinstance(current, dict):
            prefix = ".".join(parts[:idx])
            return None, f"{prefix} must be a mapping, got {type(current).__name__}"
        if part not in current:
            return None, None
        current = current[part]
        if current is None:
            return None, None
    return current, None


def _ancestor_reported(field_path: str, reported: set[str]) -> bool:
    """True when an ancestor of `field_path` has already produced a schema finding."""
    parts = field_path.split(".")
    return any(".".join(parts[:i]) in reported for i in range(1, len(parts)))
