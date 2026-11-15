"""Tests for the optional `[providers.coralogix]` compiler, renderer, client, and reconciler.

Uses a synthetic "cells / plain" vocabulary so the provider tests prove Montu's Coralogix
backend carries zero hardcoded assumptions about any consuming repo's alert kinds or names.
"""

from __future__ import annotations

import json
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import pytest

from montu.config import load_config
from montu.lint import Linter
from montu.providers.coralogix.client import (
    CoralogixAlertDef,
    CoralogixAlertsClient,
    CoralogixHttpError,
)
from montu.providers.coralogix.dataprime import (
    CompileError,
    SubsystemFilter,
    compile_filter_query,
    compile_ratio_query,
)
from montu.providers.coralogix.reconciler import (
    DRIFT_EXIT_CODE,
    PartialApplyError,
    apply_plan,
    build_plan,
    format_partial_apply_markdown,
    format_plan_markdown,
)
from montu.providers.coralogix.renderer import RenderResult, SkippedAlert, render_estate

PROVIDER_MONTU_TOML = textwrap.dedent(
    """
    version = 1

    [engine]
    unit_sources_glob = "deploy/*.yaml"
    unit_pattern = "^service: ([a-z0-9-]+)$"
    source_globs = ["src/**/*.py"]
    query_identifier_patterns = ["code == '([A-Z0-9_]+)'"]
    custom_query_field = "dataprime"
    id_field = "slug"
    unit_field = "subsystem"
    env = "production"
    strict_keys = true
    spec_fields = ["dashboard", "incident_minutes", "renotify_minutes"]

    [providers.coralogix]
    domain = "cx498.coralogix.com"
    managed_by_label = "monitoring-yaml"
    legacy_managed_by_labels = ["legacy-monitoring-yaml"]
    max_auto_disable = 3

    [providers.coralogix.webhooks]
    "#ops-alerts" = 11111

    [profiles.svc]
    spec_glob = "services/*/monitoring.yaml"
    name_template = "[SVC][{slug}] {alert}"
    common_alert_fields = [
        "subsystem",
        "active_hours.days",
        "active_hours.start",
        "active_hours.end",
        "incident_minutes",
        "renotify_minutes",
        "notify_on_resolved",
        "enabled",
        "disabled_reason",
    ]
    common_requires_when = [
        { field = "enabled", equals = "False", require = ["disabled_reason"] },
    ]

    [profiles.svc.providers.coralogix]
    labels = { deploy_env = "{env}", service = "{slug}" }

    [profiles.svc.kinds.error_rate]
    required = ["priority", "window_minutes", "deviation_pct", "min_threshold"]

    [profiles.svc.kinds.error_rate.providers.coralogix]
    type = "logs_anomaly"
    dataprime = "source logs | filter $l.subsystemname == '{subsystem}' && $d.environment == '{env}' && ($d.level == 'ERROR' || $d.level == 'error')"

    [profiles.svc.kinds.http_5xx_ratio]
    required = ["priority", "window_minutes", "threshold_pct"]

    [profiles.svc.kinds.http_5xx_ratio.providers.coralogix]
    type = "logs_ratio"
    numerator_lucene = 'environment.keyword:"{env}" AND level.keyword:"http" AND statusCode.keyword:/5[0-9]{{2}}/'
    denominator_dataprime = "source logs | filter $l.subsystemname == '{subsystem}' && $d.environment == '{env}' && $d.level == 'http'"
    numerator_alias = "5xx"
    denominator_alias = "total"
    threshold_field = "threshold_pct"
    threshold_scale = 0.01

    [profiles.svc.kinds.silence]
    required = ["priority", "window_minutes", "threshold"]

    [profiles.svc.kinds.silence.providers.coralogix]
    type = "logs_threshold"
    operator = "less_than"
    dataprime = "source logs | filter $l.subsystemname == '{subsystem}' && $d.environment == '{env}' && $d.message.contains('heartbeat_ok')"

    [profiles.svc.kinds.backlog]
    required = ["priority", "metric", "queue_label", "queues", "threshold", "window_minutes"]

    [profiles.svc.kinds.backlog.providers.coralogix]
    type = "metric_promql"
    skip_when_empty = ["metric", "queue_label"]
    selector_values_field = "queues"

    [profiles.svc.kinds.custom]
    required = ["priority", "condition.operator", "condition.threshold", "condition.window_minutes"]
    optional = ["condition.eval_every_minutes", "condition.group_by", "condition.compared_to", "condition.ratio.numerator", "condition.ratio.denominator", "condition.ratio.min_total"]
    """
)


class FakeBackend:
    def __init__(self, initial: list[CoralogixAlertDef], *, fail_on_replace_id: str = ""):
        self.alerts = list(initial)
        self.fail_on_replace_id = fail_on_replace_id
        self.created: list[dict[str, Any]] = []
        self.replaced: list[tuple[str, dict[str, Any]]] = []

    def list_alerts(self) -> list[CoralogixAlertDef]:
        return list(self.alerts)

    def create_alert(self, properties: dict[str, Any]) -> CoralogixAlertDef:
        item = CoralogixAlertDef(id=f"new-{len(self.created) + 1}", properties=properties)
        self.created.append(properties)
        return item

    def replace_alert(self, alert_id: str, properties: dict[str, Any]) -> CoralogixAlertDef:
        if alert_id == self.fail_on_replace_id:
            raise RuntimeError("simulated 500")
        self.replaced.append((alert_id, properties))
        return CoralogixAlertDef(id=alert_id, properties=properties)


def _setup_provider_repo(tmp_path: Path, spec_yaml: str) -> Path:
    (tmp_path / "montu.toml").write_text(PROVIDER_MONTU_TOML)
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "billing.yaml").write_text("service: billing-api\n")
    (tmp_path / "src" / "lib").mkdir(parents=True)
    (tmp_path / "src" / "lib" / "codes.py").write_text("CHARGE_FAILED = 1\nDISPATCH_OK = 2\n")
    svc = tmp_path / "services" / "billing"
    svc.mkdir(parents=True)
    (svc / "monitoring.yaml").write_text(textwrap.dedent(spec_yaml))
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    return tmp_path


def test_dataprime_compiler_generalizes_exact_string_subsumption_and_ratios():
    compiled = compile_filter_query(
        """
        source logs
        | filter $l.subsystemname == 'billing-api'
            && $d.tier == 'live'
            && !$d.tier.contains('canary')
            && $d.latency_ms >= 250 && $d.latency_ms <= 10000
            && ($d.code != 'A' || $d.code != 'B')
        """
    )
    assert compiled.subsystems == (
        SubsystemFilter(value="billing-api", operation="LOG_FILTER_OPERATION_TYPE_IS_OR_UNSPECIFIED"),
    )
    assert compiled.lucene_query == (
        'tier.keyword:"live" '
        'AND NOT (code.keyword:"A" AND code.keyword:"B") '
        "AND latency_ms.numeric:[250 TO 10000]"
    )

    ratio = compile_ratio_query(
        """
        source logs
        | filter $l.subsystemname == 'billing-api'
            && $d.tier == 'live'
            && ($d.code == 'CHARGE_FAILED' || $d.code == 'DISPATCH_OK')
        | groupby $d.region calculate
            count(if($d.code == 'CHARGE_FAILED')) as bad,
            count() as total
        """
    )
    assert ratio.group_by == ("region",)
    assert ratio.numerator.lucene_query == 'tier.keyword:"live" AND code.keyword:"CHARGE_FAILED"'
    assert ratio.denominator.lucene_query == 'tier.keyword:"live" AND code.keyword:("CHARGE_FAILED" OR "DISPATCH_OK")'

    with pytest.raises(CompileError):
        compile_filter_query("source logs | filter $l.subsystemname == 'x' && $d.message == 'truncated'")
    with pytest.raises(CompileError):
        compile_filter_query("source logs | filter $l.subsystemname == 'x' && $d.ms >= 500 && $d.ms <= 100")


def test_coralogix_renderer_and_lint_compile_hook(tmp_path: Path):
    repo_dir = _setup_provider_repo(
        tmp_path,
        """
        version: 1
        incident_minutes: 30
        renotify_minutes: 45
        app:
          slug: billing
          subsystem: billing-api
        env: production
        slack_channel: "#ops-alerts"
        alerts:
          - kind: error_rate
            priority: P3
            window_minutes: 60
            deviation_pct: 100
            min_threshold: 10
            runbook: Errors up.
          - kind: http_5xx_ratio
            priority: P2
            window_minutes: 60
            threshold_pct: 5
            runbook: 5xx up.
          - kind: silence
            priority: P1
            notify_on_resolved: true
            window_minutes: 60
            threshold: 1
            active_hours:
              days: ["monday"]
              start: "08:00"
              end: "18:00"
            runbook: Silent.
          - kind: backlog
            priority: P2
            metric: mq_ready
            queue_label: Queue
            queues: ["billing.q1", "billing.q2"]
            threshold: 50
            window_minutes: 15
            runbook: Queue full.
          - kind: custom
            name: charge-drop
            priority: P2
            dataprime: "source logs | filter $l.subsystemname == 'billing-api' && $d.code == 'CHARGE_FAILED'"
            condition:
              operator: less_than
              threshold: 0.3
              window_minutes: 60
              compared_to: same_hour_yesterday
            runbook: Drop.
        """,
    )
    cfg = load_config(str(repo_dir))
    findings, total = Linter(cfg).lint()
    assert total == 1
    assert [f for f in findings if f.is_error] == []

    res = render_estate(cfg)
    by_name = {a.name: a.properties for a in res.alerts}
    assert by_name["[SVC][billing] error_rate"]["type"] == "ALERT_DEF_TYPE_LOGS_ANOMALY"
    assert by_name["[SVC][billing] http_5xx_ratio"]["logsRatioThreshold"]["rules"][0]["condition"]["threshold"] == 0.05
    silence = by_name["[SVC][billing] silence"]
    assert silence["incidentsSettings"]["notifyOn"] == "NOTIFY_ON_TRIGGERED_AND_RESOLVED"
    assert silence["logsThreshold"]["undetectedValuesManagement"]["triggerUndetectedValues"] is True
    assert by_name["[SVC][billing] backlog"]["metricThreshold"]["metricFilter"]["promql"] == (
        'sum by (Queue) (mq_ready{Queue=~"billing\\.q1|billing\\.q2"})'
    )
    assert by_name["[SVC][billing] charge-drop"]["type"] == "ALERT_DEF_TYPE_LOGS_TIME_RELATIVE_THRESHOLD"

    # Invalid DataPrime surfaces as E-COMPILE during `montu lint`
    spec_file = repo_dir / "services" / "billing" / "monitoring.yaml"
    spec_file.write_text(spec_file.read_text().replace("$d.code == 'CHARGE_FAILED'", "$d.message == 'CHARGE_FAILED'"))
    bad_findings, _ = Linter(load_config(str(repo_dir))).lint()
    assert any(f.code == "E-COMPILE" for f in bad_findings)


def test_coralogix_client_pagination_cycle_and_post_no_retry():
    calls: list[tuple[str, str]] = []
    put_count = 0

    def fake_transport(method: str, url: str, _headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
        nonlocal put_count
        calls.append((method, url))
        if method == "GET" and "page_token=p2" not in url:
            return 200, json.dumps(
                {
                    "alertDefs": [{"id": "a1", "alertDefProperties": {"name": "one"}}],
                    "pagination": {"nextPageToken": "p2"},
                }
            ).encode()
        if method == "GET":
            return 200, json.dumps(
                {
                    "alertDefs": [{"id": "a2", "alertDefProperties": {"name": "two"}}],
                    "pagination": {"nextPageToken": ""},
                }
            ).encode()
        if method == "POST":
            return 504, b'{"message":"timeout"}'
        if method == "PUT":
            put_count += 1
            if put_count == 1:
                return 429, b'{"message":"rate limit"}'
            parsed = json.loads((body or b"{}").decode())
            return 200, json.dumps({"alertDef": parsed}).encode()
        return 500, b""

    client = CoralogixAlertsClient(
        api_key="k", domain="cx498.coralogix.com", transport=fake_transport, sleep_fn=lambda _: None
    )
    assert [a.id for a in client.list_alerts(page_size=1)] == ["a1", "a2"]
    with pytest.raises(CoralogixHttpError):
        client.create_alert({"name": "never-retried"})
    assert sum(1 for m, _ in calls if m == "POST") == 1
    replaced = client.replace_alert("a1", {"name": "one", "enabled": False})
    assert replaced.properties["enabled"] is False
    assert put_count == 2


def test_reconciler_plan_apply_orphan_cap_and_partial_error(tmp_path: Path):
    repo_dir = _setup_provider_repo(
        tmp_path,
        """
        version: 1
        app:
          slug: billing
          subsystem: billing-api
        env: production
        slack_channel: "#ops-alerts"
        alerts:
          - kind: custom
            name: unchanged
            priority: P3
            dataprime: "source logs | filter $l.subsystemname == 'billing-api' && $d.code == 'CHARGE_FAILED'"
            condition:
              operator: more_than_or_equals
              threshold: 5
              window_minutes: 15
            runbook: Check.
          - kind: custom
            name: updated
            priority: P2
            dataprime: "source logs | filter $l.subsystemname == 'billing-api' && $d.code == 'DISPATCH_OK'"
            condition:
              operator: more_than
              threshold: 0
              window_minutes: 5
            runbook: New runbook.
          - kind: custom
            name: created
            priority: P2
            dataprime: "source logs | filter $l.subsystemname == 'billing-api' && $d.code == 'CHARGE_FAILED'"
            condition:
              operator: more_than
              threshold: 1
              window_minutes: 10
            runbook: Created.
        """,
    )
    rendered = render_estate(load_config(str(repo_dir)))
    with_skip = RenderResult(
        alerts=rendered.alerts,
        skipped=[SkippedAlert(name="[SVC][billing] pending", spec_path="services/billing/monitoring.yaml", reason="pending")],
    )
    email_wh = {
        "minutes": 60,
        "notifyOn": "NOTIFY_ON_TRIGGERED_ONLY_UNSPECIFIED",
        "integration": {"recipients": {"emails": ["oncall@example.com"]}},
    }
    live = [
        CoralogixAlertDef(
            id="id-1",
            properties={
                **rendered.alerts[0].properties,
                "deleted": False,
                "logsThreshold": {
                    **rendered.alerts[0].properties["logsThreshold"],
                    "evaluationDelayMs": 0,
                    "noDataPolicy": {"state": "NO_DATA_POLICY_STATE_UNSPECIFIED"},
                },
            },
        ),
        CoralogixAlertDef(
            id="id-2",
            properties={
                **rendered.alerts[1].properties,
                "description": "Old.",
                "notificationGroup": {
                    "groupByKeys": [],
                    "destinations": [],
                    "webhooks": [
                        *rendered.alerts[1].properties["notificationGroup"]["webhooks"],
                        email_wh,
                    ],
                },
            },
        ),
        CoralogixAlertDef(
            id="id-orphan",
            properties={
                "name": "[SVC][billing] retired",
                "enabled": True,
                "entityLabels": {"managed_by": "legacy-monitoring-yaml"},
            },
        ),
        CoralogixAlertDef(
            id="id-vendor",
            properties={"name": "Vendor Alert", "enabled": True, "entityLabels": {}},
        ),
    ]
    backend = FakeBackend(live)
    plan = build_plan(
        with_skip,
        backend.list_alerts(),
        managed_by_label="monitoring-yaml",
        managed_by_values=frozenset({"monitoring-yaml", "legacy-monitoring-yaml"}),
    )
    assert plan.counts() == {"CREATE": 1, "UPDATE": 1, "DISABLE": 1, "UNCHANGED": 1, "CONFLICT": 0}
    assert DRIFT_EXIT_CODE == 3
    assert "Dry-Run Plan" in format_plan_markdown(plan, mode="plan")

    applied = apply_plan(plan, backend, max_auto_disable=3)
    assert len(applied) == 3
    assert email_wh in backend.replaced[0][1]["notificationGroup"]["webhooks"]
    assert backend.replaced[1][1]["enabled"] is False
    assert backend.replaced[1][1]["entityLabels"]["managed_by"] == "monitoring-yaml"

    failing_backend = FakeBackend(live, fail_on_replace_id="id-orphan")
    plan2 = build_plan(
        with_skip,
        failing_backend.list_alerts(),
        managed_by_label="monitoring-yaml",
        managed_by_values=frozenset({"monitoring-yaml", "legacy-monitoring-yaml"}),
    )
    with pytest.raises(PartialApplyError) as exc_info:
        apply_plan(plan2, failing_backend, max_auto_disable=3)
    assert "Partial Apply (Failed)" in format_partial_apply_markdown(exc_info.value, 3)
