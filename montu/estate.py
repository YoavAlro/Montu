"""The monitoring estate view — generated live from the tree, never a checked-in index."""

from __future__ import annotations

import os

import yaml

from montu.config import Config, Profile
from montu.repo import discover_specs, registry_apps


def print_estate(config: Config) -> int:
    for profile in config.profiles.values():
        print(f"profile: {profile.name}")
        spec_rels = discover_specs(config.root, profile.spec_glob)
        specs_by_slug = {os.path.basename(os.path.dirname(rel)): rel for rel in spec_rels}
        for slug in _owners(config, profile, specs_by_slug):
            rel = specs_by_slug.get(slug)
            if rel is None:
                print(f"  {slug}: UNMONITORED — no monitoring.yaml")
                continue
            _print_spec_line(config, slug, rel)
    return 0


def _owners(config: Config, profile: Profile, specs_by_slug: dict[str, str]) -> list[str]:
    """Everything this profile should cover: registry entries when a registry exists
    (so gaps show), otherwise just the specs that exist."""
    owners = set(specs_by_slug)
    if profile.registry_glob:
        for registry_rel in discover_specs(config.root, profile.registry_glob):
            owners.update(registry_apps(os.path.join(config.root, registry_rel)))
    return sorted(owners)


def _print_spec_line(config: Config, slug: str, rel: str) -> None:
    try:
        with open(os.path.join(config.root, rel), encoding="utf-8") as handle:
            spec = yaml.safe_load(handle) or {}
    except yaml.YAMLError:
        print(f"  {slug}: {rel} (UNPARSEABLE)")
        return
    alerts = spec.get("alerts") or []
    kinds = []
    with_runbook = 0
    for alert in alerts:
        kind = (alert or {}).get("kind", "?")
        kinds.append(alert.get("name") if kind == "custom" else kind)
        if (alert.get("runbook") or "").strip():
            with_runbook += 1
    dashboard = "dashboard" if spec.get("dashboard") else "no dashboard"
    print(f"  {slug}: {rel}")
    print(
        f"    alerts: {', '.join(str(k) for k in kinds) or 'none'} — "
        f"{with_runbook}/{len(alerts)} runbooks, {dashboard}"
    )
