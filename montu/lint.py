"""The lint engine: validate every spec against the code it pins.

Always validates ALL specs a profile's glob discovers — never fix-on-touch — because
drift is usually caused by code changes (a deployment rename, a routing flip, a log-token
rename) while the spec itself sits untouched.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import yaml

from montu.config import Config, Profile
from montu.repo import discover_specs, extract_subsystems, registry_entries, token_exists


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
        self._subsystem_names: set[str] | None = None

    def lint(self, only_paths: list[str] | None = None) -> tuple[list[Finding], int]:
        """Lint every discovered spec (or `only_paths`); returns (findings, spec count)."""
        findings: list[Finding] = []
        total = 0
        for profile in self.config.profiles.values():
            spec_rels = discover_specs(self.config.root, profile.spec_glob)
            if only_paths is not None:
                spec_rels = [rel for rel in spec_rels if rel in only_paths]
            total += len(spec_rels)
            for rel in spec_rels:
                findings.extend(self._lint_spec(rel, profile))
            findings.extend(self._unmonitored(profile, spec_rels))
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

        findings = self._check_schema(spec, rel, profile)
        app = spec.get("app") or {}
        findings.extend(self._check_path(app, abs_path, rel, profile))
        findings.extend(self._check_registry_and_queue(app, abs_path, rel, profile))
        findings.extend(self._check_subsystem(app, rel, profile))
        findings.extend(self._check_tokens(spec, rel, profile))
        return findings

    def _check_schema(self, spec: dict, rel: str, profile: Profile) -> list[Finding]:
        findings: list[Finding] = []

        def err(msg: str) -> None:
            findings.append(Finding(rel, "E-SCHEMA", msg))

        if spec.get("version") != 1:
            err("version must be 1")
        app = spec.get("app") or {}
        required_app = ["slug", "subsystem"]
        if profile.requires_tenant:
            required_app.append("tenant")
        if profile.requires_queue:
            required_app.append("queue")
        for field_name in required_app:
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
        custom_required = ("name", self.config.custom_query_field, "condition")
        for i, alert in enumerate(alerts):
            kind = (alert or {}).get("kind")
            if kind not in valid_kinds:
                err(f"alerts[{i}].kind {kind!r} not in {sorted(valid_kinds)} for profile {profile.name!r}")
                continue
            required = custom_required if kind == "custom" else profile.kinds[kind].required
            for field_name in required:
                if field_name not in alert or alert.get(field_name) is None:
                    err(f"alerts[{i}] ({kind}) requires {field_name}")
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

    def _check_path(self, app: dict, abs_path: str, rel: str, profile: Profile) -> list[Finding]:
        findings: list[Finding] = []
        slug = app.get("slug")
        app_dir = os.path.dirname(abs_path)
        if slug and os.path.basename(app_dir) != slug:
            findings.append(
                Finding(rel, "E-PATH", f"app.slug {slug!r} != containing dir {os.path.basename(app_dir)!r}")
            )
        if profile.path_tenant_package_prefix and app.get("tenant"):
            tenant_pkg = os.path.basename(os.path.dirname(os.path.dirname(app_dir)))
            expected = f"{profile.path_tenant_package_prefix}{app['tenant']}"
            if tenant_pkg != expected:
                findings.append(
                    Finding(rel, "E-PATH", f"app.tenant {app['tenant']!r} != containing package {tenant_pkg!r}")
                )
        return findings

    def _check_registry_and_queue(
        self, app: dict, abs_path: str, rel: str, profile: Profile
    ) -> list[Finding]:
        if not profile.registry_glob:
            return []
        findings: list[Finding] = []
        slug = app.get("slug")
        registry_path = os.path.join(os.path.dirname(os.path.dirname(abs_path)), "registry.py")
        registry = registry_entries(
            registry_path, profile.registry_entry_pattern, profile.registry_default_routing
        )
        routing = registry.get(slug or "")
        if slug and routing is None:
            findings.append(
                Finding(rel, "E-REGISTRY", f"{slug!r} has no entry in the profile's registry ({os.path.relpath(registry_path, self.config.root)})")
            )
        elif slug and routing and profile.queue_suffix:
            suffix = profile.queue_suffix.get(routing)
            if suffix:
                expected_queue = f"{slug}.{suffix}"
                if app.get("queue") != expected_queue:
                    findings.append(
                        Finding(
                            rel,
                            "E-QUEUE",
                            f"app.queue {app.get('queue')!r} != {expected_queue!r} (registry routing is {routing!r})",
                        )
                    )
        return findings

    def _check_subsystem(self, app: dict, rel: str, profile: Profile) -> list[Finding]:
        subsystem = app.get("subsystem")
        if not subsystem or not self.config.subsystem_sources_glob:
            return []
        names = self._subsystem_names
        if names is None:
            names = self._subsystem_names = extract_subsystems(
                self.config.root, self.config.subsystem_sources_glob, self.config.subsystem_pattern
            )
        expected = {name + profile.subsystem_suffix for name in names}
        if subsystem not in expected:
            return [
                Finding(
                    rel,
                    "E-SUBSYSTEM",
                    f"{subsystem!r} matches no name extracted from {self.config.subsystem_sources_glob} "
                    "— deployment renamed or removed",
                )
            ]
        return []

    def _check_tokens(self, spec: dict, rel: str, profile: Profile) -> list[Finding]:
        findings: list[Finding] = []
        for alert in spec.get("alerts") or []:
            kind = (alert or {}).get("kind")
            if kind == "custom":
                query = alert.get(self.config.custom_query_field) or ""
                tokens: tuple[str, ...] = ()
                for pattern in self.config.query_token_patterns:
                    tokens += tuple(re.findall(pattern, query))
            elif kind in profile.kinds:
                tokens = profile.kinds[kind].tokens
            else:
                continue
            for token in tokens:
                if not token_exists(self.config.root, token, self.config.token_search_globs):
                    findings.append(
                        Finding(
                            rel,
                            "E-TOKEN",
                            f"alert kind {kind!r} references '{token}' but no tracked source "
                            "defines it — renamed? Update the emitting code or the spec (and re-apply)",
                        )
                    )
        return findings

    def _unmonitored(self, profile: Profile, spec_rels: list[str]) -> list[Finding]:
        if not profile.registry_glob:
            return []
        covered = {os.path.basename(os.path.dirname(rel)) for rel in spec_rels}
        findings = []
        for registry_rel in discover_specs(self.config.root, profile.registry_glob):
            entries = registry_entries(
                os.path.join(self.config.root, registry_rel),
                profile.registry_entry_pattern,
                profile.registry_default_routing,
            )
            for slug in entries:
                if slug not in covered:
                    findings.append(
                        Finding(
                            registry_rel,
                            "W-UNMONITORED",
                            f"registered app {slug!r} has no monitoring.yaml",
                            is_error=False,
                        )
                    )
        return findings
