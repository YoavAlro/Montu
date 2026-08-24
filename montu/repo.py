"""Read-only views of the consuming repo: unit names, inventories, identifier existence.

Every extraction here is pattern-driven from montu.toml. Nothing in this module knows
any deployment tool, framework, or vendor.
"""

from __future__ import annotations

import glob
import os
import re
import subprocess


def discover(root: str, pattern_glob: str) -> list[str]:
    """Repo-relative paths matching a glob, sorted."""
    return sorted(
        os.path.relpath(p, root) for p in glob.glob(os.path.join(root, pattern_glob))
    )


def extract_units(root: str, sources_glob: str, pattern: str) -> set[str]:
    """Deployable-unit names, extracted by regex from the files the glob discovers.

    Matched by content, not filename, so a renamed source file still resolves. The
    pattern's group 1 (or the whole match, if it has no group) is one name.
    """
    compiled = re.compile(pattern, re.MULTILINE)
    names: set[str] = set()
    for source_path in glob.glob(os.path.join(root, sources_glob)):
        with open(source_path, encoding="utf-8") as handle:
            names.update(compiled.findall(handle.read()))
    return names


def read_inventory(path: str, entry_pattern: str, default_variant: str) -> dict[str, str]:
    """owner id -> variant, extracted from an inventory file by the profile's pattern.

    Group 1 is the owner id; optional group 2 the variant (falling back to the
    profile's default_variant).
    """
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        source = handle.read()
    # MULTILINE so line-anchored patterns (^entry$) work — inventories are line-oriented.
    compiled = re.compile(entry_pattern, re.MULTILINE)
    entries: dict[str, str] = {}
    for match in compiled.finditer(source):
        variant = match.group(2) if compiled.groups >= 2 and match.group(2) else default_variant
        entries[match.group(1)] = variant
    return entries


def identifier_exists(root: str, identifier: str, source_globs: tuple[str, ...]) -> bool:
    """True when the literal identifier appears in tracked sources matching the globs."""
    result = subprocess.run(
        ["git", "grep", "-q", "--fixed-strings", identifier, "--", *source_globs],
        cwd=root,
        capture_output=True,
    )
    return result.returncode == 0


def repo_root() -> str:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
    )
    return out.stdout.strip()
