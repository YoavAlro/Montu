"""montu CLI: `montu lint [paths...]` and `montu map`."""

from __future__ import annotations

import argparse
import os
import sys

from montu.config import ConfigError, load_config
from montu.estate import print_estate
from montu.lint import Linter
from montu.repo import repo_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="montu", description=__doc__)
    parser.add_argument("--config", help="path to montu.toml (default: <repo root>/montu.toml)")
    sub = parser.add_subparsers(dest="command", required=True)
    lint_parser = sub.add_parser("lint", help="validate specs against the code they pin")
    lint_parser.add_argument("paths", nargs="*", help="specific spec paths (default: all)")
    sub.add_parser("map", help="print the monitoring estate")
    args = parser.parse_args(argv)

    root = repo_root()
    try:
        config = load_config(root, args.config)
    except ConfigError as exc:
        print(f"montu: {exc}", file=sys.stderr)
        return 2

    if args.command == "map":
        return print_estate(config)

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
