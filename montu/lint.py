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
            kind = (alert or {}).get("kind")
            if kind not in valid_kinds:
                err(f"alerts[{i}].kind {kind!r} not in {sorted(valid_kinds)} for profile {profile.name!r}")
                continue
            declared = profile.kinds.get(kind)
            required = declared.required if declared else ()
            if kind == "custom":
                # The built-in fields are a floor a declared `custom` kind adds to, never
                # replaces — otherwise declaring one to add a field would silently drop them.
                required = tuple(dict.fromkeys(builtin_custom + required))
            for field_name in required:
                if field_name not in alert or alert.get(field_name) is None:
                    err(f"alerts[{i}] ({kind}) requires {field_name}")
            if declared is not None:
                findings.extend(self._check_values(alert, i, kind, declared, rel))
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
        self, alert: dict, index: int, kind: str, declared: KindSpec, rel: str
    ) -> list[Finding]:
        """A field's permitted values, and the fields a given value makes mandatory.

        Lets a repo say "this value of that field obliges these other fields" without the
        engine learning what any of them mean.
        """
        findings: list[Finding] = []
        for spec_field, allowed in declared.allowed_values.items():
            value = alert.get(spec_field)
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
            if str(alert.get(rule.spec_field)) != rule.equals:
                continue
            for spec_field in rule.require:
                if alert.get(spec_field) is None:
                    findings.append(
                        Finding(
                            rel,
                            "E-SCHEMA",
                            f"alerts[{index}] ({kind}) requires {spec_field} when "
                            f"{rule.spec_field} is {rule.equals!r}",
                        )
                    )
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
