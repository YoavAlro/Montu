"""Engine tests against a synthetic consuming repo built in tmp_path.

The fixture repo mirrors the shape montu is configured for in production use: a
worker-profile app with a registry, a plain service-profile app, helm values files, and
tracked sources emitting the tokens/codeNames the specs reference. Token existence uses
`git grep`, so the fixture is a real git repo with tracked files.
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
    subsystem_sources_glob = "helm/*.yaml"
    subsystem_pattern = "^app:\\\\n  name: ([A-Za-z0-9-]+)$"
    token_search_globs = ["src/**/*.py"]
    query_token_patterns = [
        "event=tel_[a-z0-9_]+",
        "codeName == '([A-Z0-9_]+)'",
    ]
    env = "production"

    [profiles.worker]
    spec_glob = "src/tenants/tenant_*/apps/*/monitoring.yaml"
    subsystem_suffix = "-worker"
    registry_glob = "src/tenants/tenant_*/apps/registry.py"
    registry_entry_pattern = "TelAppSpec\\\\(\\\\s*[\\"']([a-z0-9_]+)[\\"']\\\\s*(?:,\\\\s*(?:routing\\\\s*=\\\\s*)?[\\"'](direct|broadcast)[\\"'])?"
    registry_default_routing = "direct"
    path_tenant_package_prefix = "tenant_"
    requires_tenant = true
    requires_queue = true

    [profiles.worker.queue_suffix]
    direct = "events"
    broadcast = "broadcast"

    [profiles.worker.kinds.handler_errors]
    required = ["window_minutes", "threshold"]
    tokens = ["event=tel_handler_failed"]

    [profiles.worker.kinds.flow_silence]
    required = ["window_minutes", "threshold"]
    tokens = ["event=tel_task_received"]

    [profiles.service]
    spec_glob = "src/services/*/monitoring.yaml"
    file_ref_fields = ["grafana_dashboard"]

    [profiles.service.kinds.error_rate]
    required = ["window_minutes", "threshold"]
    """
)

WORKER_SPEC = textwrap.dedent(
    """
    version: 1
    app:
      tenant: acme
      slug: alpha_app
      subsystem: tenant-acme-alpha-app-worker
      queue: alpha_app.events
    env: production
    slack_channel: "#alpha"
    alerts:
      - kind: handler_errors
        window_minutes: 15
        threshold: 5
        runbook: check the worker
      - kind: custom
        name: latency
        query: "source logs | filter $d.codeName == 'ALPHA_LATENCY'"
        condition: "count >= 1 in 15m"
        runbook: check latency
    dashboard: true
    """
)

SERVICE_SPEC = textwrap.dedent(
    """
    version: 1
    app:
      slug: billing
      subsystem: billing-service
    env: production
    slack_channel: "#billing"
    alerts:
      - kind: error_rate
        window_minutes: 15
        threshold: 10
        runbook: check billing errors
    dashboard: true
    """
)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    (tmp_path / "montu.toml").write_text(MONTU_TOML)
    (tmp_path / "helm").mkdir()
    (tmp_path / "helm" / "alpha.yaml").write_text("app:\n  name: tenant-acme-alpha-app\n")
    (tmp_path / "helm" / "billing.yaml").write_text("app:\n  name: billing-service\n")

    apps = tmp_path / "src" / "tenants" / "tenant_acme" / "apps"
    (apps / "alpha_app").mkdir(parents=True)
    (apps / "alpha_app" / "monitoring.yaml").write_text(WORKER_SPEC)
    (apps / "registry.py").write_text(
        'TEL_APPS = (TelAppSpec("alpha_app", routing="direct"), TelAppSpec("ghost_app", routing="broadcast"))\n'
    )
    (apps / "worker_lib.py").write_text(
        'log("event=tel_handler_failed")\nlog("event=tel_task_received")\nALPHA_LATENCY = 1\n'
    )

    billing = tmp_path / "src" / "services" / "billing"
    billing.mkdir(parents=True)
    (billing / "monitoring.yaml").write_text(SERVICE_SPEC)

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    return tmp_path


def lint(repo_path: Path) -> tuple[list, int]:
    config = load_config(str(repo_path))
    return Linter(config).lint()


def codes(findings: list) -> set[str]:
    return {f.code for f in findings}


def test_clean_repo_has_only_the_unmonitored_warning(repo: Path):
    findings, total = lint(repo)
    assert total == 2
    errors = [f for f in findings if f.is_error]
    assert errors == []
    assert codes(findings) == {"W-UNMONITORED"}  # ghost_app is registered, unspecced


def test_subsystem_drift_fails(repo: Path):
    helm = repo / "helm" / "alpha.yaml"
    helm.write_text("app:\n  name: tenant-acme-alpha-renamed\n")
    findings, _ = lint(repo)
    assert "E-SUBSYSTEM" in codes(findings)


def test_queue_vs_routing_drift_fails(repo: Path):
    registry = repo / "src" / "tenants" / "tenant_acme" / "apps" / "registry.py"
    registry.write_text('TEL_APPS = (TelAppSpec("alpha_app", routing="broadcast"),)\n')
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    findings, _ = lint(repo)
    assert "E-QUEUE" in codes(findings)


def test_renamed_token_fails(repo: Path):
    lib = repo / "src" / "tenants" / "tenant_acme" / "apps" / "worker_lib.py"
    lib.write_text('log("event=tel_handler_broke")\nALPHA_LATENCY = 1\n')
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    findings, _ = lint(repo)
    token_errors = [f for f in findings if f.code == "E-TOKEN"]
    assert any("event=tel_handler_failed" in f.message for f in token_errors)


def test_renamed_codename_fails(repo: Path):
    lib = repo / "src" / "tenants" / "tenant_acme" / "apps" / "worker_lib.py"
    lib.write_text('log("event=tel_handler_failed")\nlog("event=tel_task_received")\n')
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    findings, _ = lint(repo)
    token_errors = [f for f in findings if f.code == "E-TOKEN"]
    assert any("ALPHA_LATENCY" in f.message for f in token_errors)


def test_wrong_env_and_missing_registry_entry_fail(repo: Path):
    spec = repo / "src" / "tenants" / "tenant_acme" / "apps" / "alpha_app" / "monitoring.yaml"
    spec.write_text(WORKER_SPEC.replace("env: production", "env: staging"))
    registry = repo / "src" / "tenants" / "tenant_acme" / "apps" / "registry.py"
    registry.write_text("TEL_APPS = ()\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    findings, _ = lint(repo)
    assert {"E-SCHEMA", "E-REGISTRY"} <= codes(findings)


def test_missing_runbook_warns_but_does_not_fail(repo: Path):
    spec = repo / "src" / "services" / "billing" / "monitoring.yaml"
    stripped = SERVICE_SPEC.replace("    runbook: check billing errors\n", "")
    assert stripped != SERVICE_SPEC
    spec.write_text(stripped)
    findings, _ = lint(repo)
    runbook = [f for f in findings if f.code == "W-NO-RUNBOOK"]
    assert runbook and not any(f.is_error for f in runbook)


def test_service_profile_rejects_worker_kinds(repo: Path):
    spec = repo / "src" / "services" / "billing" / "monitoring.yaml"
    spec.write_text(SERVICE_SPEC.replace("kind: error_rate", "kind: handler_errors"))
    findings, _ = lint(repo)
    schema = [f for f in findings if f.code == "E-SCHEMA"]
    assert any("handler_errors" in f.message for f in schema)


def test_missing_file_ref_fails(repo: Path):
    spec = repo / "src" / "services" / "billing" / "monitoring.yaml"
    spec.write_text(SERVICE_SPEC + "grafana_dashboard: billing.grafana.json\n")
    findings, _ = lint(repo)
    assert "E-FILEREF" in codes(findings)


def test_present_file_ref_passes(repo: Path):
    billing = repo / "src" / "services" / "billing"
    (billing / "billing.grafana.json").write_text('{"uid": "svc-billing"}')
    (billing / "monitoring.yaml").write_text(SERVICE_SPEC + "grafana_dashboard: billing.grafana.json\n")
    findings, _ = lint(repo)
    assert "E-FILEREF" not in codes(findings)


def test_estate_map_prints_gaps_and_coverage(repo: Path, capsys):
    config = load_config(str(repo))
    print_estate(config)
    out = capsys.readouterr().out
    assert "ghost_app: UNMONITORED" in out
    assert "billing: src/services/billing/monitoring.yaml" in out
    assert "1/1 runbooks" in out
