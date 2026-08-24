"""The monitoring estate view — generated live from the tree, never a checked-in index."""

from __future__ import annotations

import os

import yaml

from montu.config import Config, Profile
from montu.repo import discover, read_inventory


def print_estate(config: Config) -> int:
    for profile in config.profiles.values():
        print(f"profile: {profile.name}")
        spec_rels = discover(config.root, profile.spec_glob)
        specs_by_owner = {os.path.basename(os.path.dirname(rel)): rel for rel in spec_rels}
        for owner in _owners(config, profile, specs_by_owner):
            rel = specs_by_owner.get(owner)
            if rel is None:
                print(f"  {owner}: UNMONITORED — no spec")
                continue
            _print_spec_line(config, owner, rel)
    return 0


def _owners(config: Config, profile: Profile, specs_by_owner: dict[str, str]) -> list[str]:
    """Everything this profile should cover: inventory entries when one exists (so gaps
    show), otherwise just the specs that exist."""
    owners = set(specs_by_owner)
    if profile.inventory is not None:
        for inventory_rel in discover(config.root, profile.inventory.glob):
            owners.update(
                read_inventory(
                    os.path.join(config.root, inventory_rel),
                    profile.inventory.entry_pattern,
                    profile.inventory.default_variant,
                )
            )
    return sorted(owners)


def _print_spec_line(config: Config, owner: str, rel: str) -> None:
    try:
        with open(os.path.join(config.root, rel), encoding="utf-8") as handle:
            spec = yaml.safe_load(handle) or {}
    except yaml.YAMLError:
        print(f"  {owner}: {rel} (UNPARSEABLE)")
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
    print(f"  {owner}: {rel}")
    print(
        f"    alerts: {', '.join(str(k) for k in kinds) or 'none'} — "
        f"{with_runbook}/{len(alerts)} runbooks, {dashboard}"
    )
