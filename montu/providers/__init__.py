"""Optional vendor provider backends (loaded only when `[providers.*]` is configured)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from montu.config import Config
    from montu.lint import Finding


def lint_providers(config: Config, only_paths: list[str] | None = None) -> list[Finding]:
    """Run offline compilation checks for every configured `[providers.*]` backend."""
    from montu.lint import Finding

    findings: list[Finding] = []
    for name in config.providers:
        if name == "coralogix":
            from montu.providers.coralogix.renderer import (
                SpecRenderError,
                render_estate,
            )

            try:
                render_estate(config, only_paths)
            except SpecRenderError as exc:
                findings.append(
                    Finding(exc.spec_path or "montu.toml", "E-COMPILE", str(exc))
                )
        else:
            findings.append(
                Finding("montu.toml", "E-SCHEMA", f"unknown provider {name!r} in [providers]")
            )
    return findings
