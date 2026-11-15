"""Exact-name planner and applier for Coralogix Alert Definitions v3."""

from __future__ import annotations

import copy
import difflib
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from montu.config import Config
from montu.providers.coralogix.client import CoralogixAlertDef, CoralogixAlertsClient
from montu.providers.coralogix.renderer import (
    ProviderSettings,
    RenderedAlert,
    RenderResult,
    SkippedAlert,
    SpecRenderError,
    render_estate,
)

PlanAction = Literal["CREATE", "UPDATE", "DISABLE", "UNCHANGED", "CONFLICT"]

DRIFT_EXIT_CODE = 3
_TYPE_BLOCKS = (
    "logsThreshold",
    "logsAnomaly",
    "logsRatioThreshold",
    "logsTimeRelativeThreshold",
    "metricThreshold",
)


class AlertsBackend(Protocol):
    def list_alerts(self) -> list[CoralogixAlertDef]: ...
    def create_alert(self, properties: dict[str, Any]) -> CoralogixAlertDef: ...
    def replace_alert(self, alert_id: str, properties: dict[str, Any]) -> CoralogixAlertDef: ...


class PartialApplyError(RuntimeError):
    """Raised when `apply_plan` fails partway, carrying already-applied status lines."""

    def __init__(self, message: str, *, applied: list[str], failed_name: str):
        super().__init__(message)
        self.applied = applied
        self.failed_name = failed_name


@dataclass
class PlannedChange:
    action: PlanAction
    name: str
    spec_path: str = ""
    alert_id: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    diff_lines: list[str] = field(default_factory=list)
    categories: tuple[str, ...] = ()
    detail: str = ""


@dataclass
class Plan:
    changes: list[PlannedChange]
    skipped: list[SkippedAlert] = field(default_factory=list)
    unmanaged_count: int = 0
    already_disabled_count: int = 0

    @property
    def conflicts(self) -> list[PlannedChange]:
        return [change for change in self.changes if change.action == "CONFLICT"]

    @property
    def actionable(self) -> list[PlannedChange]:
        return [change for change in self.changes if change.action in ("CREATE", "UPDATE", "DISABLE")]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {"CREATE": 0, "UPDATE": 0, "DISABLE": 0, "UNCHANGED": 0, "CONFLICT": 0}
        for item in self.changes:
            out[item.action] = out.get(item.action, 0) + 1
        return out


@dataclass(frozen=True)
class _OrphanPlan:
    changes: list[PlannedChange]
    already_disabled: int


def is_managed(properties: dict[str, Any], managed_values: frozenset[str]) -> bool:
    labels = properties.get("entityLabels") or {}
    return isinstance(labels, dict) and labels.get("managed_by") in managed_values


def merge_for_replace(desired: dict[str, Any], live: dict[str, Any]) -> dict[str, Any]:
    """Build the full-replace payload, preserving UI-owned `caseSettings` and email recipients."""
    merged = copy.deepcopy(desired)
    if "caseSettings" in live and live["caseSettings"] is not None:
        merged["caseSettings"] = copy.deepcopy(live["caseSettings"])

    live_webhooks = (live.get("notificationGroup") or {}).get("webhooks") or []
    extra_email_webhooks = [
        copy.deepcopy(wh)
        for wh in live_webhooks
        if isinstance(wh, dict) and (wh.get("integration") or {}).get("recipients")
    ]
    if extra_email_webhooks:
        merged["notificationGroup"]["webhooks"].extend(extra_email_webhooks)
    return merged


def _normalize_numbers(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {key: _normalize_numbers(val) for key, val in obj.items()}
    if isinstance(obj, list):
        return [_normalize_numbers(val) for val in obj]
    if isinstance(obj, float) and obj.is_integer():
        return int(obj)
    return obj


def canonicalize_props(props: dict[str, Any]) -> dict[str, Any]:
    """Normalize Coralogix server-filled defaults so converged alerts compare equal."""
    norm = copy.deepcopy(props)
    for server_default_empty in ("deleted", "notificationGroupExcess", "dataSources"):
        if norm.get(server_default_empty) in (False, None, []):
            norm.pop(server_default_empty, None)
    if norm.get("activeOn") is None:
        norm.pop("activeOn", None)
    elif isinstance(norm.get("activeOn"), dict):
        for slot in ("startTime", "endTime"):
            if isinstance(norm["activeOn"].get(slot), dict):
                norm["activeOn"][slot].setdefault("hours", 0)
                norm["activeOn"][slot].setdefault("minutes", 0)
    norm["phantomMode"] = bool(norm.get("phantomMode", False))
    norm["enabled"] = bool(norm.get("enabled", True))
    norm["groupByKeys"] = list(norm.get("groupByKeys") or [])

    ng = norm.get("notificationGroup") or {}
    ng["groupByKeys"] = list(ng.get("groupByKeys") or [])
    ng["destinations"] = list(ng.get("destinations") or [])
    webhooks = list(ng.get("webhooks") or [])
    ng["webhooks"] = sorted(webhooks, key=lambda item: json.dumps(item, sort_keys=True))
    norm["notificationGroup"] = ng

    for block_key in _TYPE_BLOCKS:
        block = norm.get(block_key)
        if not isinstance(block, dict):
            continue
        if block.get("evaluationDelayMs") in (0, None):
            block.pop("evaluationDelayMs", None)
        ndp = block.get("noDataPolicy")
        if isinstance(ndp, dict) and ndp.get("state") in (None, "", "NO_DATA_POLICY_STATE_UNSPECIFIED"):
            block.pop("noDataPolicy", None)
        uvm = block.get("undetectedValuesManagement")
        if isinstance(uvm, dict) and not uvm.get("triggerUndetectedValues"):
            block.pop("undetectedValuesManagement", None)
        if block_key in ("logsThreshold", "logsAnomaly", "logsTimeRelativeThreshold"):
            _normalize_log_filter_holder(block)
        elif block_key == "logsRatioThreshold":
            for side in ("numerator", "denominator"):
                holder = block.get(side)
                if isinstance(holder, dict):
                    _normalize_simple_filter(holder)
            block.setdefault("notificationPayloadFilter", [])

    return _normalize_numbers(norm)


def _normalize_log_filter_holder(block: dict[str, Any]) -> None:
    block.setdefault("notificationPayloadFilter", [])
    lf = block.get("logsFilter")
    if isinstance(lf, dict):
        _normalize_simple_filter(lf)


def _normalize_simple_filter(lf: dict[str, Any]) -> None:
    sf = lf.get("simpleFilter")
    if not isinstance(sf, dict):
        return
    sf["luceneQuery"] = sf.get("luceneQuery") or ""
    label_filters = sf.setdefault("labelFilters", {})
    label_filters["applicationName"] = list(label_filters.get("applicationName") or [])
    label_filters["severities"] = list(label_filters.get("severities") or [])
    subs = list(label_filters.get("subsystemName") or [])
    for sub_entry in subs:
        sub_entry.setdefault("operation", "LOG_FILTER_OPERATION_TYPE_IS_OR_UNSPECIFIED")
    label_filters["subsystemName"] = sorted(
        subs, key=lambda sub_entry: (sub_entry.get("value", ""), sub_entry.get("operation", ""))
    )


def classify_update_categories(live_norm: dict[str, Any], desired_norm: dict[str, Any]) -> tuple[str, ...]:
    cats: list[str] = []
    if live_norm.get("enabled") != desired_norm.get("enabled"):
        cats.append("re-enable" if desired_norm.get("enabled") else "disable")
    if live_norm.get("type") != desired_norm.get("type") or _query_slice(live_norm) != _query_slice(desired_norm):
        cats.append("query")
    if (
        live_norm.get("priority") != desired_norm.get("priority")
        or live_norm.get("activeOn") != desired_norm.get("activeOn")
        or live_norm.get("groupByKeys") != desired_norm.get("groupByKeys")
        or _rules_slice(live_norm) != _rules_slice(desired_norm)
    ):
        cats.append("condition")
    if (
        live_norm.get("incidentsSettings") != desired_norm.get("incidentsSettings")
        or live_norm.get("notificationGroup") != desired_norm.get("notificationGroup")
    ):
        cats.append("notifications")
    if live_norm.get("entityLabels") != desired_norm.get("entityLabels"):
        cats.append("labels")
    if live_norm.get("description") != desired_norm.get("description"):
        cats.append("description")
    return tuple(cats or ["other"])


def _query_slice(norm: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for block_key in _TYPE_BLOCKS:
        block = norm.get(block_key)
        if not isinstance(block, dict):
            continue
        out[block_key] = {
            k: block.get(k)
            for k in ("logsFilter", "metricFilter", "numerator", "denominator")
            if k in block
        }
    return out


def _rules_slice(norm: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for block_key in _TYPE_BLOCKS:
        block = norm.get(block_key)
        if not isinstance(block, dict):
            continue
        out[block_key] = {
            k: block.get(k)
            for k in ("rules", "anomalyAlertSettings", "missingValues", "undetectedValuesManagement")
            if k in block
        }
    return out


def build_plan(
    rendered: RenderResult,
    live_alerts: list[CoralogixAlertDef],
    *,
    managed_by_label: str = "monitoring-yaml",
    managed_by_values: frozenset[str] = frozenset({"monitoring-yaml"}),
) -> Plan:
    live_by_name: dict[str, list[CoralogixAlertDef]] = {}
    unmanaged_count = 0
    for live in live_alerts:
        if not is_managed(live.properties, managed_by_values):
            unmanaged_count += 1
        name = str(live.properties.get("name") or "")
        live_by_name.setdefault(name, []).append(live)

    changes = [
        _plan_desired_one(desired, live_by_name.get(desired.name, []), managed_by_values, managed_by_label)
        for desired in rendered.alerts
    ]
    orphan_plan = _plan_orphans(rendered, live_alerts, managed_by_values, managed_by_label)
    changes.extend(orphan_plan.changes)

    return Plan(
        changes=changes,
        skipped=list(rendered.skipped),
        unmanaged_count=unmanaged_count,
        already_disabled_count=orphan_plan.already_disabled,
    )


def _plan_desired_one(
    desired: RenderedAlert,
    matches: list[CoralogixAlertDef],
    managed_by_values: frozenset[str],
    managed_by_label: str,
) -> PlannedChange:
    if not matches:
        created_lines = json.dumps(canonicalize_props(desired.properties), indent=2, sort_keys=True).splitlines()
        create_diff = list(
            difflib.unified_diff([], created_lines, fromfile="/dev/null", tofile=desired.spec_path, lineterm="")
        )
        return PlannedChange(
            action="CREATE",
            name=desired.name,
            spec_path=desired.spec_path,
            payload=desired.properties,
            diff_lines=create_diff,
        )

    if len(matches) > 1:
        ids = ", ".join(match.id for match in matches)
        return PlannedChange(
            action="CONFLICT",
            name=desired.name,
            spec_path=desired.spec_path,
            alert_id=ids,
            detail=f"multiple live alerts share this exact name (ids={ids}); deduplicate in Coralogix first",
        )

    target = matches[0]
    if not is_managed(target.properties, managed_by_values):
        return PlannedChange(
            action="CONFLICT",
            name=desired.name,
            spec_path=desired.spec_path,
            alert_id=target.id,
            detail=(
                f"live alert exists without managed_by={managed_by_label} (id={target.id}); "
                "refusing to overwrite an unlabeled alert"
            ),
        )

    replacement = merge_for_replace(desired.properties, target.properties)
    live_norm = canonicalize_props(target.properties)
    desired_norm = canonicalize_props(replacement)
    left = json.dumps(live_norm, indent=2, sort_keys=True).splitlines()
    right = json.dumps(desired_norm, indent=2, sort_keys=True).splitlines()
    diff = list(
        difflib.unified_diff(
            left, right, fromfile=f"live ({target.id})", tofile=desired.spec_path, lineterm=""
        )
    )
    if not diff:
        return PlannedChange(
            action="UNCHANGED",
            name=desired.name,
            spec_path=desired.spec_path,
            alert_id=target.id,
        )
    return PlannedChange(
        action="UPDATE",
        name=desired.name,
        spec_path=desired.spec_path,
        alert_id=target.id,
        payload=replacement,
        diff_lines=diff,
        categories=classify_update_categories(live_norm, desired_norm),
    )


def _plan_orphans(
    rendered: RenderResult,
    live_alerts: list[CoralogixAlertDef],
    managed_by_values: frozenset[str],
    managed_by_label: str,
) -> _OrphanPlan:
    desired_names = {item.name for item in rendered.alerts}
    skipped_names = {item.name for item in rendered.skipped}
    orphan_changes: list[PlannedChange] = []
    already_disabled = 0

    for live in sorted(live_alerts, key=lambda alert: str(alert.properties.get("name") or "")):
        if not is_managed(live.properties, managed_by_values):
            continue
        name = str(live.properties.get("name") or "")
        if name in desired_names or name in skipped_names:
            continue
        if not live.properties.get("enabled", True):
            already_disabled += 1
            continue
        disabled_props = copy.deepcopy(live.properties)
        disabled_props["enabled"] = False
        disabled_props.setdefault("entityLabels", {})["managed_by"] = managed_by_label
        for server_ro in ("deleted", "notificationGroupExcess"):
            disabled_props.pop(server_ro, None)
        if disabled_props.get("dataSources") in (None, []):
            disabled_props.pop("dataSources", None)
        orphan_changes.append(
            PlannedChange(
                action="DISABLE",
                name=name,
                alert_id=live.id,
                payload=disabled_props,
                detail="orphaned managed alert (no spec entry); disabling, never deleting",
            )
        )
    return _OrphanPlan(changes=orphan_changes, already_disabled=already_disabled)


def emit_plan_warnings(plan: Plan, *, max_auto_disable: int = 3) -> None:
    for change in plan.changes:
        if change.action == "DISABLE":
            print(f"::warning::Orphaned managed alert will be disabled on merge: {change.name} (id={change.alert_id})")
        elif change.action == "UPDATE" and "re-enable" in change.categories:
            print(
                f"::warning::Live-disabled managed alert will be re-enabled on merge: {change.name} "
                f"(id={change.alert_id}); set `enabled: false` + `disabled_reason` in {change.spec_path} to keep it off"
            )
    disable_count = plan.counts()["DISABLE"]
    if disable_count > max_auto_disable:
        print(
            f"::warning::Plan disables {disable_count} alerts, exceeding max_auto_disable={max_auto_disable}; "
            "apply on main will refuse unless --allow-mass-disable is passed."
        )


def format_plan_text(plan: Plan, *, heading: str = "Coralogix Alert Plan") -> str:
    counts = plan.counts()
    lines = [
        (f"{heading}: {counts['CREATE']} create, {counts['UPDATE']} update, "
        f"{counts['DISABLE']} disable, {counts['UNCHANGED']} unchanged "
        f"({plan.unmanaged_count} unlabeled/vendor untouched, "
        f"{plan.already_disabled_count} orphaned already disabled)")
    ]
    for skip_item in plan.skipped:
        lines.append(f"  SKIP      {skip_item.name} ({skip_item.spec_path}) — {skip_item.reason}")
    for change in plan.changes:
        if change.action == "UNCHANGED":
            continue
        tags = f" [{', '.join(change.categories)}]" if change.categories else ""
        loc = f" [{change.spec_path}]" if change.spec_path else ""
        id_note = f" (id={change.alert_id})" if change.alert_id else ""
        extra = f" — {change.detail}" if change.detail else ""
        lines.append(f"  {change.action:<9} {change.name}{tags}{id_note}{loc}{extra}")
        for dline in change.diff_lines:
            lines.append(f"      {dline}")
    return "\n".join(lines)


def format_plan_markdown(plan: Plan, *, mode: str) -> str:
    counts = plan.counts()
    title = "Coralogix Alerts — Dry-Run Plan" if mode == "plan" else "Coralogix Alerts — Applied"
    md = [
        f"## {title}",
        "",
        (f"- **Create**: `{counts['CREATE']}` · **Update**: `{counts['UPDATE']}` · "
        f"**Disable**: `{counts['DISABLE']}` · **Unchanged**: `{counts['UNCHANGED']}`"),
        (f"- **Untouched unlabeled/vendor alerts**: `{plan.unmanaged_count}` · "
        f"**Already-disabled orphans**: `{plan.already_disabled_count}`"),
        "",
    ]
    shown = [change for change in plan.changes if change.action != "UNCHANGED"]
    if shown:
        md.extend(["| Action | Alert | Changed | Spec / Notes |", "|---|---|---|---|"])
        for change in shown:
            changed_col = ", ".join(f"`{cat}`" for cat in change.categories) if change.categories else "—"
            note = change.detail or change.spec_path or "—"
            md.append(f"| `{change.action}` | `{change.name}` | {changed_col} | {note} |")
        md.append("")
    for change in shown:
        if change.diff_lines:
            tag_suffix = f" ({', '.join(change.categories)})" if change.categories else ""
            md.extend(
                [
                    f"<details><summary>Diff: <code>{change.name}</code>{tag_suffix}</summary>",
                    "",
                    "```diff",
                    *change.diff_lines,
                    "```",
                    "</details>",
                    "",
                ]
            )
    return "\n".join(md)


def format_partial_apply_markdown(err: PartialApplyError, total_planned: int) -> str:
    md = [
        "## Coralogix Alerts — Partial Apply (Failed)",
        "",
        f"- **Succeeded before failure**: `{len(err.applied)}` / `{total_planned}`",
        f"- **Failed on**: `{err.failed_name}` — `{err}`",
        "- Re-running `apply` is idempotent and will converge the remaining alerts.",
        "",
    ]
    if err.applied:
        md.extend(["### Succeeded mutations", "", "```text", *err.applied, "```", ""])
    return "\n".join(md)


def write_step_summary(markdown: str) -> None:
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write(markdown + "\n")


def apply_plan(
    plan: Plan,
    backend: AlertsBackend,
    *,
    max_auto_disable: int = 3,
    allow_mass_disable: bool = False,
) -> list[str]:
    if plan.conflicts:
        raise PartialApplyError(
            "refusing to apply plan with conflicts", applied=[], failed_name=plan.conflicts[0].name
        )
    disable_count = plan.counts()["DISABLE"]
    if disable_count > max_auto_disable and not allow_mass_disable:
        raise PartialApplyError(
            f"refusing to disable {disable_count} managed alerts in one run "
            f"(max_auto_disable={max_auto_disable}); pass --allow-mass-disable if intentional",
            applied=[],
            failed_name="max_auto_disable",
        )
    results: list[str] = []
    for change in plan.actionable:
        try:
            if change.action == "CREATE":
                created = backend.create_alert(change.payload)
                results.append(f"CREATED  {change.name} (id={created.id})")
            elif change.action == "UPDATE":
                updated = backend.replace_alert(change.alert_id, change.payload)
                results.append(f"UPDATED  {change.name} (id={updated.id or change.alert_id})")
            elif change.action == "DISABLE":
                backend.replace_alert(change.alert_id, change.payload)
                results.append(f"DISABLED {change.name} (id={change.alert_id})")
        except Exception as exc:
            raise PartialApplyError(
                f"failed during {change.action} of {change.name!r} "
                f"({len(results)} prior change(s) succeeded): {exc}",
                applied=list(results),
                failed_name=change.name,
            ) from exc
    return results


def _build_live_client(settings: ProviderSettings) -> CoralogixAlertsClient:
    api_key = os.getenv(settings.api_key_env, "").strip()
    if not api_key:
        print(
            f"{settings.api_key_env} is not set (requires Coralogix alerts read/update permissions).",
            file=sys.stderr,
        )
        raise SystemExit(2)
    domain = os.getenv(settings.domain_env, settings.domain).strip() or settings.domain
    return CoralogixAlertsClient(api_key=api_key, domain=domain)


def run_render(config: Config, only_paths: list[str] | None = None) -> int:
    try:
        result = render_estate(config, only_paths)
    except SpecRenderError as exc:
        loc = f"{exc.spec_path}: " if exc.spec_path else ""
        print(f"montu render error: {loc}{exc}", file=sys.stderr)
        return 1
    payload = [
        {"spec": item.spec_path, "alertDefProperties": item.properties} for item in result.alerts
    ]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def run_plan(config: Config, *, fail_on_drift: bool = False) -> int:
    try:
        settings = ProviderSettings.from_config(config)
        rendered = render_estate(config)
    except SpecRenderError as exc:
        loc = f"{exc.spec_path}: " if exc.spec_path else ""
        print(f"montu plan error: {loc}{exc}", file=sys.stderr)
        return 1
    backend = _build_live_client(settings)
    plan = build_plan(
        rendered,
        backend.list_alerts(),
        managed_by_label=settings.managed_by_label,
        managed_by_values=settings.managed_by_values,
    )
    emit_plan_warnings(plan, max_auto_disable=settings.max_auto_disable)
    print(format_plan_text(plan))
    write_step_summary(format_plan_markdown(plan, mode="plan"))
    if plan.conflicts:
        return 1
    if fail_on_drift and plan.actionable:
        return DRIFT_EXIT_CODE
    return 0


def run_apply(config: Config, *, allow_mass_disable: bool = False) -> int:
    try:
        settings = ProviderSettings.from_config(config)
        rendered = render_estate(config)
    except SpecRenderError as exc:
        loc = f"{exc.spec_path}: " if exc.spec_path else ""
        print(f"montu apply error: {loc}{exc}", file=sys.stderr)
        return 1
    backend = _build_live_client(settings)
    plan = build_plan(
        rendered,
        backend.list_alerts(),
        managed_by_label=settings.managed_by_label,
        managed_by_values=settings.managed_by_values,
    )
    emit_plan_warnings(plan, max_auto_disable=settings.max_auto_disable)
    print(format_plan_text(plan, heading="Coralogix Alert Apply Plan"))
    if plan.conflicts:
        write_step_summary(format_plan_markdown(plan, mode="plan"))
        return 1
    try:
        applied = apply_plan(
            plan,
            backend,
            max_auto_disable=settings.max_auto_disable,
            allow_mass_disable=allow_mass_disable,
        )
    except PartialApplyError as exc:
        for line in exc.applied:
            print(f"  {line}")
        print(f"montu apply error: {exc}", file=sys.stderr)
        write_step_summary(format_partial_apply_markdown(exc, len(plan.actionable)))
        return 1
    for line in applied:
        print(f"  {line}")
    if not applied:
        print("  No changes needed — live Coralogix matches monitoring.yaml.")
    write_step_summary(format_plan_markdown(plan, mode="apply"))
    return 0
