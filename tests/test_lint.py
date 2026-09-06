"""Engine tests against a synthetic consuming repo built in tmp_path.

The fixture deliberately models a stack montu has never seen — a made-up "cells"
inventory with `steady`/`burst` variants — so the tests prove the engine is driven
entirely by montu.toml and carries no assumptions about any real repo's conventions.
Identifier existence uses `git grep`, so the fixture is a real git repo.
"""

from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

from montu.config import load_config
from montu.estate import print_estate
from montu.lint import Linter

MONTU_TOML = textwrap.dedent(
    """
    version = 1

    [engine]
    unit_sources_glob = "deploy/*.yaml"
    unit_pattern = "^service: ([a-z0-9-]+)$"
    source_globs = ["src/**/*.py"]
    query_identifier_patterns = ["marker=[a-z0-9_]+", "code == '([A-Z0-9_]+)'"]
    custom_query_field = "query"
    id_field = "slug"
    unit_field = "unit"
    env = "production"

    [profiles.cell]
    spec_glob = "src/regions/region_*/cells/*/monitoring.yaml"
    unit_suffix = "-cell"
    required_fields = ["region", "channel"]

    [profiles.cell.inventory]
    glob = "src/regions/region_*/cells/inventory.txt"
    entry_pattern = "^cell ([a-z0-9_]+)(?: ([a-z]+))?$"
    default_variant = "steady"

    [[profiles.cell.path_rules]]
    field = "slug"

    [[profiles.cell.path_rules]]
    field = "region"
    ancestor = 2
    prefix = "region_"

    [profiles.cell.field_rules]
    channel = "{id}.{variant}"

    [profiles.cell.variant_values]
    steady = "stream"
    burst = "batch"

    [profiles.cell.kinds.failures]
    required = ["window_minutes", "threshold"]
    tokens = ["marker=cell_failed"]

    [profiles.cell.kinds.custom]
    required = ["tier"]
    allowed_values = { tier = ["gold", "silver"] }
    requires_when = [{ field = "tier", equals = "gold", require = ["owner"] }]

    [profiles.plain]
    spec_glob = "src/tools/*/monitoring.yaml"
    file_ref_fields = ["dashboard_model"]

    [[profiles.plain.path_rules]]
    field = "slug"

    [profiles.plain.kinds.error_rate]
    required = ["window_minutes", "threshold"]
    """
)

CELL_SPEC = textwrap.dedent(
    """
    version: 1
    app:
      region: north
      slug: alpha_cell
      unit: north-alpha-cell
      channel: alpha_cell.stream
    env: production
    slack_channel: "#alpha"
    alerts:
      - kind: failures
        window_minutes: 15
        threshold: 5
        runbook: check the cell
      - kind: custom
        name: latency
        query: "source logs | filter code == 'ALPHA_LATENCY'"
        condition: "count >= 1 in 15m"
        tier: silver
        runbook: check latency
    dashboard: true
    """
)

PLAIN_SPEC = textwrap.dedent(
    """
    version: 1
    app:
      slug: widget
      unit: widget-tool
    env: production
    slack_channel: "#widget"
    alerts:
      - kind: error_rate
        window_minutes: 15
        threshold: 10
        runbook: check widget errors
    dashboard: true
    """
)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    (tmp_path / "montu.toml").write_text(MONTU_TOML)
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "a.yaml").write_text("service: north-alpha\n")
    (tmp_path / "deploy" / "b.yaml").write_text("service: widget-tool\n")

    cells = tmp_path / "src" / "regions" / "region_north" / "cells"
    (cells / "alpha_cell").mkdir(parents=True)
    (cells / "alpha_cell" / "monitoring.yaml").write_text(CELL_SPEC)
    (cells / "inventory.txt").write_text("cell alpha_cell steady\ncell ghost_cell burst\n")

    src = tmp_path / "src" / "lib"
    src.mkdir(parents=True)
    (src / "emit.py").write_text('log("marker=cell_failed")\nALPHA_LATENCY = 1\n')

    tool = tmp_path / "src" / "tools" / "widget"
    tool.mkdir(parents=True)
    (tool / "monitoring.yaml").write_text(PLAIN_SPEC)

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    return tmp_path


def lint(repo_path: Path):
    return Linter(load_config(str(repo_path))).lint()


def codes(findings) -> set[str]:
    return {f.code for f in findings}


def restage(repo_path: Path) -> None:
    subprocess.run(["git", "add", "-A"], cwd=repo_path, check=True)


def test_clean_repo_has_only_the_uncovered_warning(repo: Path):
    findings, total = lint(repo)
    assert total == 2
    assert [f for f in findings if f.is_error] == []
    assert codes(findings) == {"W-UNMONITORED"}  # ghost_cell is inventoried, unspecced


def test_unit_rename_fails(repo: Path):
    (repo / "deploy" / "a.yaml").write_text("service: north-renamed\n")
    findings, _ = lint(repo)
    assert "E-UNIT" in codes(findings)


def test_derived_field_disagrees_with_variant(repo: Path):
    inv = repo / "src" / "regions" / "region_north" / "cells" / "inventory.txt"
    inv.write_text("cell alpha_cell burst\n")   # channel should become alpha_cell.batch
    restage(repo)
    findings, _ = lint(repo)
    assert "E-FIELD" in codes(findings)


def test_default_variant_applies_when_group_absent(repo: Path):
    inv = repo / "src" / "regions" / "region_north" / "cells" / "inventory.txt"
    inv.write_text("cell alpha_cell\n")          # no variant -> default steady -> .stream
    restage(repo)
    findings, _ = lint(repo)
    assert "E-FIELD" not in codes(findings)


def test_renamed_kind_token_fails(repo: Path):
    (repo / "src" / "lib" / "emit.py").write_text('log("marker=cell_broke")\nALPHA_LATENCY = 1\n')
    restage(repo)
    findings, _ = lint(repo)
    assert any("marker=cell_failed" in f.message for f in findings if f.code == "E-TOKEN")


def test_renamed_query_identifier_fails(repo: Path):
    (repo / "src" / "lib" / "emit.py").write_text('log("marker=cell_failed")\n')
    restage(repo)
    findings, _ = lint(repo)
    assert any("ALPHA_LATENCY" in f.message for f in findings if f.code == "E-TOKEN")


def test_ancestor_path_rule_fails(repo: Path):
    spec = repo / "src" / "regions" / "region_north" / "cells" / "alpha_cell" / "monitoring.yaml"
    spec.write_text(CELL_SPEC.replace("region: north", "region: south"))
    findings, _ = lint(repo)
    assert any("region" in f.message for f in findings if f.code == "E-PATH")


def test_wrong_env_and_missing_inventory_entry_fail(repo: Path):
    spec = repo / "src" / "regions" / "region_north" / "cells" / "alpha_cell" / "monitoring.yaml"
    spec.write_text(CELL_SPEC.replace("env: production", "env: staging"))
    inv = repo / "src" / "regions" / "region_north" / "cells" / "inventory.txt"
    inv.write_text("")
    restage(repo)
    findings, _ = lint(repo)
    assert {"E-SCHEMA", "E-INVENTORY"} <= codes(findings)


def test_required_fields_are_per_profile(repo: Path):
    """`region`/`channel` are required for cells; the plain profile must not need them."""
    spec = repo / "src" / "tools" / "widget" / "monitoring.yaml"
    findings, _ = lint(repo)
    assert not [f for f in findings if f.is_error and str(spec).endswith(f.path)]


def test_profile_rejects_another_profiles_kind(repo: Path):
    spec = repo / "src" / "tools" / "widget" / "monitoring.yaml"
    spec.write_text(PLAIN_SPEC.replace("kind: error_rate", "kind: failures"))
    findings, _ = lint(repo)
    assert any("failures" in f.message for f in findings if f.code == "E-SCHEMA")


def test_missing_runbook_warns_but_does_not_fail(repo: Path):
    spec = repo / "src" / "tools" / "widget" / "monitoring.yaml"
    stripped = PLAIN_SPEC.replace("    runbook: check widget errors\n", "")
    assert stripped != PLAIN_SPEC
    spec.write_text(stripped)
    findings, _ = lint(repo)
    runbook = [f for f in findings if f.code == "W-NO-RUNBOOK"]
    assert runbook and not any(f.is_error for f in runbook)


def test_missing_file_ref_fails(repo: Path):
    spec = repo / "src" / "tools" / "widget" / "monitoring.yaml"
    spec.write_text(PLAIN_SPEC + "dashboard_model: widget.dashboard.json\n")
    findings, _ = lint(repo)
    assert "E-FILEREF" in codes(findings)


def test_present_file_ref_passes(repo: Path):
    tool = repo / "src" / "tools" / "widget"
    (tool / "widget.dashboard.json").write_text('{"uid": "widget"}')
    (tool / "monitoring.yaml").write_text(PLAIN_SPEC + "dashboard_model: widget.dashboard.json\n")
    findings, _ = lint(repo)
    assert "E-FILEREF" not in codes(findings)


def test_declared_custom_kind_adds_required_fields(repo: Path):
    spec = repo / "src" / "regions" / "region_north" / "cells" / "alpha_cell" / "monitoring.yaml"
    spec.write_text(CELL_SPEC.replace("    tier: silver\n", ""))
    findings, _ = lint(repo)
    assert any("requires tier" in f.message for f in findings if f.code == "E-SCHEMA")


def test_declared_custom_kind_keeps_the_builtin_fields(repo: Path):
    """Declaring `custom` to add a field must not drop the fields the engine always needs."""
    spec = repo / "src" / "regions" / "region_north" / "cells" / "alpha_cell" / "monitoring.yaml"
    spec.write_text(CELL_SPEC.replace('    condition: "count >= 1 in 15m"\n', ""))
    findings, _ = lint(repo)
    assert any("requires condition" in f.message for f in findings if f.code == "E-SCHEMA")


def test_value_outside_allowed_values_fails(repo: Path):
    spec = repo / "src" / "regions" / "region_north" / "cells" / "alpha_cell" / "monitoring.yaml"
    spec.write_text(CELL_SPEC.replace("tier: silver", "tier: bronze"))
    findings, _ = lint(repo)
    assert any("bronze" in f.message for f in findings if f.code == "E-VALUE")


def test_conditional_requirement_fires_only_for_the_gating_value(repo: Path):
    spec = repo / "src" / "regions" / "region_north" / "cells" / "alpha_cell" / "monitoring.yaml"
    spec.write_text(CELL_SPEC.replace("tier: silver", "tier: gold"))
    findings, _ = lint(repo)
    assert any(
        "requires owner when tier is 'gold'" in f.message
        for f in findings
        if f.code == "E-SCHEMA"
    )
    spec.write_text(CELL_SPEC)  # the non-gating value obliges nothing
    findings, _ = lint(repo)
    assert [f for f in findings if f.is_error] == []


def test_gated_field_present_satisfies_the_rule(repo: Path):
    spec = repo / "src" / "regions" / "region_north" / "cells" / "alpha_cell" / "monitoring.yaml"
    spec.write_text(CELL_SPEC.replace("tier: silver", "tier: gold\n    owner: pager-a"))
    findings, _ = lint(repo)
    assert [f for f in findings if f.is_error] == []


def test_estate_map_prints_gaps_and_coverage(repo: Path, capsys):
    print_estate(load_config(str(repo)))
    out = capsys.readouterr().out
    assert "ghost_cell: UNMONITORED" in out
    assert "widget: src/tools/widget/monitoring.yaml" in out
    assert "1/1 runbooks" in out
