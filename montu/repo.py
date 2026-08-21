"""Read-only views of the consuming repo: helm names, registries, token existence."""

from __future__ import annotations

import glob
import os
import re
import subprocess

APP_NAME_RE = re.compile(r"^  name:\s*([A-Za-z0-9-]+)\s*$")
REGISTRY_APP_RE = re.compile(
    r"TelAppSpec\(\s*[\"']([a-z0-9_]+)[\"']\s*(?:,\s*(?:routing\s*=\s*)?[\"'](direct|broadcast)[\"'])?"
)


def discover_specs(root: str, spec_glob: str) -> list[str]:
    return sorted(
        os.path.relpath(p, root) for p in glob.glob(os.path.join(root, spec_glob))
    )


def helm_app_names(root: str, values_glob: str) -> set[str]:
    """Every helm values file's `app.name` — matched by content, not filename, so a
    decoupled release name or renamed values file still resolves."""
    names: set[str] = set()
    for values_path in glob.glob(os.path.join(root, values_glob)):
        in_app_block = False
        with open(values_path, encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("app:"):
                    in_app_block = True
                    continue
                if in_app_block:
                    if line.strip() and not line.startswith(" "):
                        break
                    match = APP_NAME_RE.match(line)
                    if match:
                        names.add(match.group(1))
                        break
    return names


def registry_apps(registry_path: str) -> dict[str, str]:
    """slug -> routing from a TelAppSpec registry module."""
    if not os.path.isfile(registry_path):
        return {}
    with open(registry_path, encoding="utf-8") as handle:
        source = handle.read()
    return {slug: routing or "direct" for slug, routing in REGISTRY_APP_RE.findall(source)}


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
