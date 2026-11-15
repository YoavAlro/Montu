"""montu CLI: `montu lint`, `montu map`, and optional provider `render` / `plan` / `apply`."""

from __future__ import annotations

import argparse
import os
import sys

from montu.config import Config, ConfigError, load_config
from montu.estate import print_estate
from montu.lint import Linter
from montu.repo import repo_root


def _require_coralogix(config: Config) -> bool:
    if "coralogix" not in config.providers:
        print(
            "montu: `render` / `plan` / `apply` require [providers.coralogix] in montu.toml",
            file=sys.stderr,
        )
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="montu", description=__doc__)
    parser.add_argument("--config", help="path to montu.toml (default: <repo root>/montu.toml)")
    sub = parser.add_subparsers(dest="command", required=True)

    lint_parser = sub.add_parser("lint", help="validate specs against the code they pin")
    lint_parser.add_argument("paths", nargs="*", help="specific spec paths (default: all)")

    sub.add_parser("map", help="print the monitoring estate")

    render_parser = sub.add_parser("render", help="print rendered provider alert definitions JSON")
    render_parser.add_argument("paths", nargs="*", help="specific spec paths (default: all)")

    plan_parser = sub.add_parser("plan", help="dry-run rendered specs against the live provider")
    plan_parser.add_argument(
        "--fail-on-drift",
        action="store_true",
        help="exit 3 when any CREATE / UPDATE / DISABLE is planned",
    )

    apply_parser = sub.add_parser("apply", help="reconcile live provider alerts to match specs")
    apply_parser.add_argument(
        "--allow-mass-disable",
        action="store_true",
        help="permit disabling more orphaned managed alerts than max_auto_disable",
    )

    args = parser.parse_args(argv)

    root = repo_root()
    try:
        config = load_config(root, args.config)
    except ConfigError as exc:
        print(f"montu: {exc}", file=sys.stderr)
        return 2

    if args.command == "map":
        return print_estate(config)

    if args.command in ("render", "plan", "apply"):
        if not _require_coralogix(config):
            return 2
        from montu.providers.coralogix.reconciler import run_apply, run_plan, run_render

        if args.command == "render":
            only_render = (
                [os.path.relpath(os.path.abspath(p), root) for p in args.paths]
                if args.paths
                else None
            )
            return run_render(config, only_render)
        if args.command == "plan":
            return run_plan(config, fail_on_drift=args.fail_on_drift)
        return run_apply(config, allow_mass_disable=args.allow_mass_disable)

    only = (
        [os.path.relpath(os.path.abspath(p), root) for p in args.paths] if args.paths else None
    )
    findings, total = Linter(config).lint(only)
    for finding in findings:
        print(finding.render())
    errors = [f for f in findings if f.is_error]
    print(
        f"montu lint: {total} spec(s), {len(errors)} error(s), "
        f"{len(findings) - len(errors)} warning(s)"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
