"""Read-only views of the consuming repo: subsystem sources, registries, token existence.

All extraction here is pattern-driven from montu.toml — nothing in this module knows any
particular deployment tooling, framework, or vendor.
"""

from __future__ import annotations

import glob
import os
import re
import subprocess


def discover_specs(root: str, spec_glob: str) -> list[str]:
    return sorted(
        os.path.relpath(p, root) for p in glob.glob(os.path.join(root, spec_glob))
    )


def extract_subsystems(root: str, sources_glob: str, pattern: str) -> set[str]:
    """Subsystem base names, extracted by regex from the files the glob discovers.

    Matched by content, not filename, so a renamed source file still resolves. The
    pattern's group 1 (or the whole match, if the pattern has no group) is one name.
    """
    compiled = re.compile(pattern, re.MULTILINE)
    names: set[str] = set()
    for source_path in glob.glob(os.path.join(root, sources_glob)):
        with open(source_path, encoding="utf-8") as handle:
            names.update(compiled.findall(handle.read()))
    return names


def registry_entries(registry_path: str, pattern: str, default_routing: str) -> dict[str, str]:
    """slug -> routing from a registry file, extracted by the profile's pattern.

    Group 1 is the slug; optional group 2 the routing (falls back to default_routing).
    """
    if not os.path.isfile(registry_path):
        return {}
    with open(registry_path, encoding="utf-8") as handle:
        source = handle.read()
    compiled = re.compile(pattern)
    entries: dict[str, str] = {}
    for match in compiled.finditer(source):
        slug = match.group(1)
        routing = match.group(2) if compiled.groups >= 2 and match.group(2) else default_routing
        entries[slug] = routing
    return entries


def token_exists(root: str, token: str, search_globs: tuple[str, ...]) -> bool:
    """True when the literal token appears in tracked sources matching the globs."""
    result = subprocess.run(
        ["git", "grep", "-q", "--fixed-strings", token, "--", *search_globs],
        cwd=root,
        capture_output=True,
    )
    return result.returncode == 0


def repo_root() -> str:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
    )
    return out.stdout.strip()
