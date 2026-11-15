"""Config-driven Coralogix AlertDefs v3 renderer.

Reads profile, label, webhook, and kind-template rules from `montu.toml` (`[providers.coralogix]`,
`[profiles.<p>.providers.coralogix]`, `[profiles.<p>.kinds.<k>.providers.coralogix]`) and compiles
checked-in `monitoring.yaml` specs into deterministic `alertDefProperties` mappings.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from typing import Any

import yaml

from montu.config import Config, Profile
from montu.providers.coralogix.dataprime import (
    CompileError,
    SimpleLogFilter,
    SubsystemFilter,
    compile_filter_query,
    compile_ratio_query,
)
from montu.repo import discover_all


class SpecRenderError(ValueError):
    """Raised when a spec cannot be rendered deterministically into Coralogix v3 JSON."""

    def __init__(self, message: str, *, spec_path: str = ""):
        super().__init__(message)
        self.spec_path = spec_path


NOTIFY_TRIGGERED_ONLY = "NOTIFY_ON_TRIGGERED_ONLY_UNSPECIFIED"
NOTIFY_TRIGGERED_AND_RESOLVED = "NOTIFY_ON_TRIGGERED_AND_RESOLVED"
SUBSYSTEM_OP_IS = "LOG_FILTER_OPERATION_TYPE_IS_OR_UNSPECIFIED"

LOGS_TIME_WINDOWS: dict[int, str] = {
    5: "LOGS_TIME_WINDOW_VALUE_MINUTES_5_OR_UNSPECIFIED",
    10: "LOGS_TIME_WINDOW_VALUE_MINUTES_10",
    15: "LOGS_TIME_WINDOW_VALUE_MINUTES_15",
    20: "LOGS_TIME_WINDOW_VALUE_MINUTES_20",
    30: "LOGS_TIME_WINDOW_VALUE_MINUTES_30",
    60: "LOGS_TIME_WINDOW_VALUE_HOUR_1",
    120: "LOGS_TIME_WINDOW_VALUE_HOURS_2",
    240: "LOGS_TIME_WINDOW_VALUE_HOURS_4",
    360: "LOGS_TIME_WINDOW_VALUE_HOURS_6",
    720: "LOGS_TIME_WINDOW_VALUE_HOURS_12",
    1440: "LOGS_TIME_WINDOW_VALUE_HOURS_24",
    2160: "LOGS_TIME_WINDOW_VALUE_HOURS_36",
}

MAX_WINDOW_MINUTES = max(LOGS_TIME_WINDOWS)

LOGS_RATIO_TIME_WINDOWS: dict[int, str] = {
    minutes: enum_name.replace("LOGS_TIME_WINDOW_VALUE_", "LOGS_RATIO_TIME_WINDOW_VALUE_")
    for minutes, enum_name in LOGS_TIME_WINDOWS.items()
    if minutes != 20
}

PRIORITIES: dict[str, str] = {
    "P1": "ALERT_DEF_PRIORITY_P1",
    "P2": "ALERT_DEF_PRIORITY_P2",
    "P3": "ALERT_DEF_PRIORITY_P3",
    "P4": "ALERT_DEF_PRIORITY_P4",
    "P5": "ALERT_DEF_PRIORITY_P5_OR_UNSPECIFIED",
}

DAYS_OF_WEEK: dict[str, str] = {
    "monday": "DAY_OF_WEEK_MONDAY_OR_UNSPECIFIED",
    "tuesday": "DAY_OF_WEEK_TUESDAY",
    "wednesday": "DAY_OF_WEEK_WEDNESDAY",
    "thursday": "DAY_OF_WEEK_THURSDAY",
    "friday": "DAY_OF_WEEK_FRIDAY",
    "saturday": "DAY_OF_WEEK_SATURDAY",
    "sunday": "DAY_OF_WEEK_SUNDAY",
}

TIME_RELATIVE_COMPARED_TO: dict[str, str] = {
    "previous_hour": "LOGS_TIME_RELATIVE_COMPARED_TO_PREVIOUS_HOUR_OR_UNSPECIFIED",
    "same_hour_yesterday": "LOGS_TIME_RELATIVE_COMPARED_TO_SAME_HOUR_YESTERDAY",
    "same_hour_last_week": "LOGS_TIME_RELATIVE_COMPARED_TO_SAME_HOUR_LAST_WEEK",
    "yesterday": "LOGS_TIME_RELATIVE_COMPARED_TO_YESTERDAY",
    "same_day_last_week": "LOGS_TIME_RELATIVE_COMPARED_TO_SAME_DAY_LAST_WEEK",
    "same_day_last_month": "LOGS_TIME_RELATIVE_COMPARED_TO_SAME_DAY_LAST_MONTH",
}

TIME_RELATIVE_WINDOWS: dict[str, int] = {
    "previous_hour": 60,
    "same_hour_yesterday": 60,
    "same_hour_last_week": 60,
    "yesterday": 1440,
    "same_day_last_week": 1440,
    "same_day_last_month": 1440,
}

ALLOWED_CONDITION_KEYS = frozenset(
    {"operator", "threshold", "window_minutes", "eval_every_minutes", "group_by", "ratio", "compared_to"}
)
ALLOWED_RATIO_KEYS = frozenset({"numerator", "denominator", "min_total"})

_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_PROMQL_REGEX_META = re.compile(r"([.+*?^$()\[\]{}|\\])")
_PARAGRAPH_SPLIT_RE = re.compile(r"\n\s*\n")


@dataclass(frozen=True)
class ProviderSettings:
    domain: str
    api_key_env: str
    domain_env: str
    managed_by_label: str
    managed_by_values: frozenset[str]
    max_auto_disable: int
    default_incident_minutes: int
    default_renotify_minutes: int
    webhooks: dict[str, int]

    @classmethod
    def from_config(cls, config: Config) -> ProviderSettings:
        raw = config.providers.get("coralogix")
        if not isinstance(raw, dict):
            raise SpecRenderError("montu.toml defines no [providers.coralogix]")
        domain = str(raw.get("domain") or "").strip()
        if not domain:
            raise SpecRenderError("[providers.coralogix] requires non-empty `domain`")
        managed_by = str(raw.get("managed_by_label") or "monitoring-yaml").strip()
        legacy = [str(item) for item in (raw.get("legacy_managed_by_labels") or [])]
        raw_webhooks = raw.get("webhooks") or {}
        if not isinstance(raw_webhooks, dict):
            raise SpecRenderError("[providers.coralogix.webhooks] must be a table")
        webhooks: dict[str, int] = {}
        for ch, wh_id in raw_webhooks.items():
            if not isinstance(wh_id, int) or isinstance(wh_id, bool):
                raise SpecRenderError(
                    f"[providers.coralogix.webhooks] {ch!r} must be an integer webhook externalId"
                )
            webhooks[str(ch)] = wh_id
        return cls(
            domain=domain,
            api_key_env=str(raw.get("api_key_env") or "CORALOGIX_ALERTS_API_KEY"),
            domain_env=str(raw.get("domain_env") or "CORALOGIX_DOMAIN"),
            managed_by_label=managed_by,
            managed_by_values=frozenset({managed_by, *legacy}),
            max_auto_disable=int(raw.get("max_auto_disable", 3)),
            default_incident_minutes=int(raw.get("default_incident_minutes", 10)),
            default_renotify_minutes=int(raw.get("default_renotify_minutes", 60)),
            webhooks=webhooks,
        )


@dataclass(frozen=True)
class RenderedAlert:
    name: str
    spec_path: str
    profile: str
    kind: str
    properties: dict[str, Any]


@dataclass(frozen=True)
class SkippedAlert:
    name: str
    spec_path: str
    reason: str


@dataclass(frozen=True)
class RenderResult:
    alerts: list[RenderedAlert]
    skipped: list[SkippedAlert]


@dataclass(frozen=True)
class CountCondition:
    condition_type: str
    threshold: int | float


@dataclass(frozen=True)
class _AlertContext:
    ctx: str
    spec_path: str
    config: Config
    profile: Profile
    app: dict[str, Any]
    env: str
    alert_name: str
    description: str
    enabled: bool
    priority_enum: str
    subsystem: str
    labels: dict[str, str]
    webhook_id: int
    incident_minutes: int
    renotify_minutes: int
    notify_on_enum: str
    active_on: dict[str, Any] | None


def render_estate(config: Config, only_paths: list[str] | None = None) -> RenderResult:
    """Render every discovered spec (or `only_paths`) and verify cross-spec name uniqueness."""
    settings = ProviderSettings.from_config(config)
    requested = set(only_paths) if only_paths else None
    rendered: list[RenderedAlert] = []
    skipped: list[SkippedAlert] = []
    seen_names: dict[str, str] = {}
    matched: set[str] = set()

    for profile in config.profiles.values():
        hits = discover_all(config.root, profile.spec_globs)
        if requested is None and not hits:
            raise SpecRenderError(
                f"profile {profile.name!r} spec_glob {list(profile.spec_globs)} matched 0 files"
            )
        for rel in hits:
            if requested is not None and rel not in requested:
                continue
            matched.add(rel)
            abs_path = os.path.join(config.root, rel)
            try:
                with open(abs_path, encoding="utf-8") as handle:
                    spec = yaml.safe_load(handle)
            except (OSError, yaml.YAMLError) as exc:
                raise SpecRenderError(f"invalid YAML: {exc}", spec_path=rel) from exc
            if not isinstance(spec, dict):
                raise SpecRenderError("top-level YAML must be a mapping", spec_path=rel)
            spec_res = render_spec(
                spec, config=config, profile=profile, settings=settings, spec_path=rel
            )
            for item in spec_res.alerts:
                _record_unique(item.name, rel, seen_names)
                rendered.append(item)
            for skip_item in spec_res.skipped:
                _record_unique(skip_item.name, rel, seen_names)
                skipped.append(skip_item)

    if requested is not None:
        unmatched = sorted(requested - matched)
        if unmatched:
            raise SpecRenderError(
                f"path(s) did not match any montu.toml profile spec_glob: {unmatched}",
                spec_path=unmatched[0],
            )
    return RenderResult(alerts=rendered, skipped=skipped)


def _record_unique(name: str, spec_path: str, seen_names: dict[str, str]) -> None:
    prev = seen_names.get(name)
    if prev is not None:
        raise SpecRenderError(
            f"duplicate alert name {name!r} in {spec_path} and {prev}", spec_path=spec_path
        )
    seen_names[name] = spec_path


def render_spec(
    spec: dict[str, Any],
    *,
    config: Config,
    profile: Profile,
    settings: ProviderSettings,
    spec_path: str,
) -> RenderResult:
    env = spec.get("env")
    if env != config.env:
        raise SpecRenderError(f"refusing env={env!r}; expected {config.env!r}", spec_path=spec_path)

    app = spec.get("app")
    if not isinstance(app, dict):
        raise SpecRenderError("app must be a mapping", spec_path=spec_path)
    owner_id = app.get(config.id_field)
    base_unit = app.get(config.unit_field)
    if not isinstance(owner_id, str) or not owner_id or not isinstance(base_unit, str) or not base_unit:
        raise SpecRenderError(
            f"app.{config.id_field} and app.{config.unit_field} are required strings",
            spec_path=spec_path,
        )

    channel = (spec.get("slack_channel") or "").strip() if isinstance(spec.get("slack_channel"), str) else ""
    if not channel:
        raise SpecRenderError(
            "slack_channel is empty; cannot render alerts without a webhook", spec_path=spec_path
        )
    webhook_id = settings.webhooks.get(channel)
    if webhook_id is None:
        raise SpecRenderError(
            f"unknown slack_channel {channel!r}; add its Coralogix outbound webhook externalId "
            "to [providers.coralogix.webhooks] in montu.toml",
            spec_path=spec_path,
        )

    spec_incident_min = _optional_positive_int(
        spec.get("incident_minutes"),
        "incident_minutes",
        spec_path,
        settings.default_incident_minutes,
        spec_path=spec_path,
    )
    spec_renotify_min = _optional_positive_int(
        spec.get("renotify_minutes"),
        "renotify_minutes",
        spec_path,
        settings.default_renotify_minutes,
        spec_path=spec_path,
    )

    labels = _build_labels(profile, settings, app, env, spec_path)
    out: list[RenderedAlert] = []
    skipped: list[SkippedAlert] = []

    for idx, entry in enumerate(spec.get("alerts") or []):
        if not isinstance(entry, dict):
            raise SpecRenderError(f"alerts[{idx}] must be a mapping", spec_path=spec_path)
        kind = str(entry.get("kind") or "")
        declared = profile.kinds.get(kind)
        if kind != "custom" and declared is None:
            raise SpecRenderError(
                f"alerts[{idx}]: unsupported alert kind {kind!r} for profile {profile.name!r}",
                spec_path=spec_path,
            )
        cx_kind = (declared.providers.get("coralogix") if declared else None) or {}
        archetype = str(cx_kind.get("type") or ("custom" if kind == "custom" else ""))
        if not archetype:
            raise SpecRenderError(
                f"alerts[{idx}] ({kind}): missing [profiles.{profile.name}.kinds.{kind}.providers.coralogix] type",
                spec_path=spec_path,
            )

        suffix = entry.get("name") if kind == "custom" else kind
        if not isinstance(suffix, str) or not suffix.strip():
            raise SpecRenderError(f"alerts[{idx}] missing alert name/kind", spec_path=spec_path)
        alert_name = _format_alert_name(config, profile, app, suffix.strip(), env, spec_path)

        skip_fields = cx_kind.get("skip_when_empty") or []
        if skip_fields and any(not entry.get(f) for f in skip_fields):
            skipped.append(
                SkippedAlert(
                    name=alert_name,
                    spec_path=spec_path,
                    reason=f"{'/'.join(skip_fields)} empty (discovery pending)",
                )
            )
            continue

        actx = _build_alert_context(
            entry,
            idx=idx,
            spec_path=spec_path,
            config=config,
            profile=profile,
            app=app,
            env=env,
            alert_name=alert_name,
            base_subsystem=base_unit,
            labels=labels,
            webhook_id=webhook_id,
            default_incident_min=spec_incident_min,
            default_renotify_min=spec_renotify_min,
        )
        props = _dispatch_archetype(archetype, cx_kind, entry, actx)
        out.append(
            RenderedAlert(
                name=alert_name,
                spec_path=spec_path,
                profile=profile.name,
                kind=kind,
                properties=props,
            )
        )

    return RenderResult(alerts=out, skipped=skipped)


def _dispatch_archetype(
    archetype: str, cx_kind: dict[str, Any], entry: dict[str, Any], actx: _AlertContext
) -> dict[str, Any]:
    if archetype == "custom":
        return _render_custom(entry, actx)
    if archetype == "logs_anomaly":
        return _render_logs_anomaly(cx_kind, entry, actx)
    if archetype == "logs_threshold":
        return _render_logs_threshold_kind(cx_kind, entry, actx)
    if archetype == "logs_ratio":
        return _render_logs_ratio_kind(cx_kind, entry, actx)
    if archetype == "metric_promql":
        return _render_metric_promql_kind(cx_kind, entry, actx)
    raise SpecRenderError(
        f"{actx.ctx}: unknown Coralogix kind archetype {archetype!r}", spec_path=actx.spec_path
    )


def _build_alert_context(
    entry: dict[str, Any],
    *,
    idx: int,
    spec_path: str,
    config: Config,
    profile: Profile,
    app: dict[str, Any],
    env: str,
    alert_name: str,
    base_subsystem: str,
    labels: dict[str, str],
    webhook_id: int,
    default_incident_min: int,
    default_renotify_min: int,
) -> _AlertContext:
    ctx = f"{spec_path} alerts[{idx}] ({alert_name})"
    enabled = _parse_enabled(entry, ctx, spec_path)
    incident_min = _optional_positive_int(
        entry.get("incident_minutes"),
        "incident_minutes",
        ctx,
        default_incident_min,
        spec_path=spec_path,
    )
    renotify_min = _optional_positive_int(
        entry.get("renotify_minutes"),
        "renotify_minutes",
        ctx,
        default_renotify_min,
        spec_path=spec_path,
    )
    notify_resolved = entry.get("notify_on_resolved", False)
    if not isinstance(notify_resolved, bool):
        raise SpecRenderError(f"{ctx}: notify_on_resolved must be a boolean", spec_path=spec_path)
    return _AlertContext(
        ctx=ctx,
        spec_path=spec_path,
        config=config,
        profile=profile,
        app=app,
        env=env,
        alert_name=alert_name,
        description=_clean_description(entry),
        enabled=enabled,
        priority_enum=_priority_enum(entry.get("priority"), ctx, spec_path),
        subsystem=str(entry.get(config.unit_field) or base_subsystem),
        labels=labels,
        webhook_id=webhook_id,
        incident_minutes=incident_min,
        renotify_minutes=renotify_min,
        notify_on_enum=NOTIFY_TRIGGERED_AND_RESOLVED if notify_resolved else NOTIFY_TRIGGERED_ONLY,
        active_on=_parse_active_hours(entry.get("active_hours"), ctx, spec_path),
    )


def _parse_enabled(entry: dict[str, Any], ctx: str, spec_path: str) -> bool:
    raw = entry.get("enabled", True)
    if not isinstance(raw, bool):
        raise SpecRenderError(f"{ctx}: enabled must be a boolean, got {raw!r}", spec_path=spec_path)
    if not raw:
        reason = entry.get("disabled_reason")
        if not isinstance(reason, str) or not reason.strip():
            raise SpecRenderError(
                f"{ctx}: enabled=false requires a non-empty disabled_reason", spec_path=spec_path
            )
    return raw


def _build_labels(
    profile: Profile, settings: ProviderSettings, app: dict[str, Any], env: str, spec_path: str
) -> dict[str, str]:
    prof_cx = profile.providers.get("coralogix") or {}
    label_templates = prof_cx.get("labels") or {}
    out: dict[str, str] = {"managed_by": settings.managed_by_label}
    ctx_vars = {**app, "env": env}
    for key, tmpl in label_templates.items():
        try:
            out[str(key)] = str(tmpl).format(**ctx_vars)
        except KeyError as exc:
            raise SpecRenderError(
                f"missing app field {exc} required by profile {profile.name!r} label {key!r}",
                spec_path=spec_path,
            ) from exc
    return out


def _format_alert_name(
    config: Config, profile: Profile, app: dict[str, Any], suffix: str, env: str, spec_path: str
) -> str:
    if not profile.name_template:
        raise SpecRenderError(
            f"profile {profile.name!r} requires `name_template` to render Coralogix alert names",
            spec_path=spec_path,
        )
    try:
        head = profile.name_template.format(**app, alert=suffix, env=env)
    except KeyError as exc:
        raise SpecRenderError(
            f"missing app field {exc} required by profile {profile.name!r} name_template",
            spec_path=spec_path,
        ) from exc
    if "{env}" not in profile.name_template and env != config.env:
        return f"{head} · {env}"
    return head


def _priority_enum(raw: Any, ctx: str, spec_path: str) -> str:
    val = str(raw or "")
    if val not in PRIORITIES:
        raise SpecRenderError(f"{ctx}: invalid priority {raw!r} (expected P1..P5)", spec_path=spec_path)
    return PRIORITIES[val]


def _check_positive_int(
    val: Any, field_name: str, ctx: str, *, spec_path: str, maximum: int | None = None
) -> int:
    if not isinstance(val, int) or isinstance(val, bool) or val < 1:
        raise SpecRenderError(
            f"{ctx}: {field_name} must be a positive integer, got {val!r}", spec_path=spec_path
        )
    if maximum is not None and val > maximum:
        raise SpecRenderError(
            f"{ctx}: {field_name} ({val}) must not exceed {maximum}", spec_path=spec_path
        )
    return val


def _optional_positive_int(
    val: Any, field_name: str, ctx: str, default: int, *, spec_path: str
) -> int:
    return default if val is None else _check_positive_int(val, field_name, ctx, spec_path=spec_path)


def _check_number(val: Any, field_name: str, ctx: str, *, spec_path: str) -> int | float:
    if not isinstance(val, (int, float)) or isinstance(val, bool) or not math.isfinite(val):
        raise SpecRenderError(
            f"{ctx}: {field_name} must be a finite number, got {val!r}", spec_path=spec_path
        )
    return val


def _logs_window(minutes: Any, ctx: str, *, spec_path: str, ratio: bool = False) -> str:
    win = _check_positive_int(minutes, "window_minutes", ctx, spec_path=spec_path)
    table = LOGS_RATIO_TIME_WINDOWS if ratio else LOGS_TIME_WINDOWS
    if win not in table:
        raise SpecRenderError(
            f"{ctx}: window_minutes={win} is not a valid Coralogix preset {sorted(table)}",
            spec_path=spec_path,
        )
    return table[win]


def _parse_active_hours(raw: Any, ctx: str, spec_path: str) -> dict[str, Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise SpecRenderError(f"{ctx}: active_hours must be a mapping or null", spec_path=spec_path)
    unknown = set(raw) - {"days", "start", "end"}
    if unknown:
        raise SpecRenderError(
            f"{ctx}: unknown key(s) in active_hours: {sorted(unknown)} (times are always UTC)",
            spec_path=spec_path,
        )
    days_raw = raw.get("days")
    if not isinstance(days_raw, list) or not days_raw:
        raise SpecRenderError(f"{ctx}: active_hours.days must be a non-empty list", spec_path=spec_path)
    days = []
    for day in days_raw:
        key = str(day).lower()
        if key not in DAYS_OF_WEEK:
            raise SpecRenderError(
                f"{ctx}: invalid day {day!r} in active_hours.days", spec_path=spec_path
            )
        days.append(DAYS_OF_WEEK[key])

    start_m = _HHMM_RE.match(str(raw.get("start") or ""))
    end_m = _HHMM_RE.match(str(raw.get("end") or ""))
    if not start_m or not end_m:
        raise SpecRenderError(
            f"{ctx}: active_hours start/end must be HH:MM (00:00..23:59)", spec_path=spec_path
        )
    return {
        "dayOfWeek": days,
        "startTime": {"hours": int(start_m.group(1)), "minutes": int(start_m.group(2))},
        "endTime": {"hours": int(end_m.group(1)), "minutes": int(end_m.group(2))},
    }


def _clean_description(entry: dict[str, Any]) -> str:
    runbook = (entry.get("runbook") or "").strip()
    if not runbook:
        return str(entry.get("description") or "").strip()
    paragraphs = [
        " ".join(line.strip() for line in para.splitlines() if line.strip())
        for para in _PARAGRAPH_SPLIT_RE.split(runbook)
    ]
    return "\n\n".join(para for para in paragraphs if para)


def _base_props(
    actx: _AlertContext,
    *,
    alert_type: str,
    group_by_keys: list[str] | None = None,
    notif_group_by_keys: list[str] | None = None,
) -> dict[str, Any]:
    gb = list(group_by_keys or [])
    ng_gb = list(notif_group_by_keys) if notif_group_by_keys is not None else list(gb)
    props: dict[str, Any] = {
        "name": actx.alert_name,
        "description": actx.description,
        "enabled": actx.enabled,
        "priority": actx.priority_enum,
        "type": alert_type,
        "groupByKeys": gb,
        "incidentsSettings": {
            "minutes": actx.incident_minutes,
            "notifyOn": actx.notify_on_enum,
        },
        "notificationGroup": {
            "groupByKeys": ng_gb,
            "webhooks": [
                {
                    "minutes": actx.renotify_minutes,
                    "notifyOn": actx.notify_on_enum,
                    "integration": {"integrationId": actx.webhook_id},
                }
            ],
            "destinations": [],
        },
        "entityLabels": dict(actx.labels),
        "phantomMode": False,
    }
    if actx.active_on is not None:
        props["activeOn"] = actx.active_on
    return props


def _single_subsystem(subsystem: str) -> tuple[SubsystemFilter, ...]:
    return (SubsystemFilter(value=subsystem, operation=SUBSYSTEM_OP_IS),)


def _template_vars(actx: _AlertContext) -> dict[str, Any]:
    return {
        **actx.app,
        "env": actx.env,
        actx.config.unit_field: actx.subsystem,
        "unit": actx.subsystem,
    }


def _compile_kind_filter(cx_kind: dict[str, Any], actx: _AlertContext, *, prefix: str = "") -> SimpleLogFilter:
    dp_key = f"{prefix}dataprime" if prefix else "dataprime"
    lucene_key = f"{prefix}lucene" if prefix else "lucene"
    vars_map = _template_vars(actx)
    if cx_kind.get(dp_key):
        rendered_dp = str(cx_kind[dp_key]).format(**vars_map)
        try:
            return compile_filter_query(rendered_dp)
        except CompileError as exc:
            raise SpecRenderError(
                f"{actx.ctx}: DataPrime template compile error: {exc}", spec_path=actx.spec_path
            ) from exc
    if cx_kind.get(lucene_key) is not None:
        rendered_lucene = str(cx_kind[lucene_key]).format(**vars_map)
        return SimpleLogFilter(
            lucene_query=rendered_lucene,
            subsystems=_single_subsystem(actx.subsystem),
        )
    raise SpecRenderError(
        f"{actx.ctx}: Coralogix kind config requires {dp_key!r} or {lucene_key!r}",
        spec_path=actx.spec_path,
    )


def _render_logs_anomaly(
    cx_kind: dict[str, Any], entry: dict[str, Any], actx: _AlertContext
) -> dict[str, Any]:
    win = _logs_window(entry.get("window_minutes"), actx.ctx, spec_path=actx.spec_path)
    dev = _check_number(entry.get("deviation_pct"), "deviation_pct", actx.ctx, spec_path=actx.spec_path)
    min_thr = _check_number(entry.get("min_threshold"), "min_threshold", actx.ctx, spec_path=actx.spec_path)
    log_filter = _compile_kind_filter(cx_kind, actx)
    props = _base_props(actx, alert_type="ALERT_DEF_TYPE_LOGS_ANOMALY")
    props["logsAnomaly"] = {
        "logsFilter": log_filter.to_coralogix(),
        "rules": [
            {
                "condition": {
                    "minimumThreshold": min_thr,
                    "timeWindow": {"logsTimeWindowSpecificValue": win},
                    "conditionType": "LOGS_ANOMALY_CONDITION_TYPE_MORE_THAN_USUAL_OR_UNSPECIFIED",
                }
            }
        ],
        "notificationPayloadFilter": [],
        "anomalyAlertSettings": {"percentageOfDeviation": dev},
    }
    return props


def _render_logs_ratio_kind(
    cx_kind: dict[str, Any], entry: dict[str, Any], actx: _AlertContext
) -> dict[str, Any]:
    win_min = _check_positive_int(entry.get("window_minutes"), "window_minutes", actx.ctx, spec_path=actx.spec_path)
    win = _logs_window(win_min, actx.ctx, spec_path=actx.spec_path, ratio=True)
    if entry.get("eval_every_minutes") is not None:
        _check_positive_int(
            entry.get("eval_every_minutes"),
            "eval_every_minutes",
            actx.ctx,
            spec_path=actx.spec_path,
            maximum=win_min,
        )
    thr_field = str(cx_kind.get("threshold_field") or "threshold")
    scale = float(cx_kind.get("threshold_scale", 1.0))
    raw_thr = _check_number(entry.get(thr_field), thr_field, actx.ctx, spec_path=actx.spec_path)
    scaled_thr = round(raw_thr * scale, 6)
    if scaled_thr <= 0 or scaled_thr > 1:
        raise SpecRenderError(
            f"{actx.ctx}: scaled ratio threshold must be in (0, 1], got {scaled_thr!r}",
            spec_path=actx.spec_path,
        )
    operator = str(cx_kind.get("operator") or "more_than")
    cond_type = (
        "LOGS_RATIO_CONDITION_TYPE_MORE_THAN_OR_UNSPECIFIED"
        if operator == "more_than"
        else "LOGS_RATIO_CONDITION_TYPE_LESS_THAN"
    )
    num_filter = _compile_kind_filter(cx_kind, actx, prefix="numerator_")
    den_filter = _compile_kind_filter(cx_kind, actx, prefix="denominator_")
    props = _base_props(actx, alert_type="ALERT_DEF_TYPE_LOGS_RATIO_THRESHOLD")
    props["logsRatioThreshold"] = {
        "numerator": num_filter.to_coralogix(),
        "numeratorAlias": str(cx_kind.get("numerator_alias") or "numerator"),
        "denominator": den_filter.to_coralogix(),
        "denominatorAlias": str(cx_kind.get("denominator_alias") or "denominator"),
        "rules": [
            {
                "condition": {
                    "threshold": scaled_thr,
                    "timeWindow": {"logsRatioTimeWindowSpecificValue": win},
                    "conditionType": cond_type,
                },
                "override": {"priority": actx.priority_enum},
            }
        ],
        "notificationPayloadFilter": [],
        "groupByFor": "LOGS_RATIO_GROUP_BY_FOR_BOTH_OR_UNSPECIFIED",
        "ignoreInfinity": True,
    }
    return props


def _render_logs_threshold_kind(
    cx_kind: dict[str, Any], entry: dict[str, Any], actx: _AlertContext
) -> dict[str, Any]:
    win_min = _check_positive_int(entry.get("window_minutes"), "window_minutes", actx.ctx, spec_path=actx.spec_path)
    win = _logs_window(win_min, actx.ctx, spec_path=actx.spec_path)
    if entry.get("eval_every_minutes") is not None:
        _check_positive_int(
            entry.get("eval_every_minutes"),
            "eval_every_minutes",
            actx.ctx,
            spec_path=actx.spec_path,
            maximum=win_min,
        )
    thr = _check_number(entry.get("threshold"), "threshold", actx.ctx, spec_path=actx.spec_path)
    operator = str(cx_kind.get("operator") or "more_than")
    norm = _normalize_count_condition(operator, thr, actx.ctx, actx.spec_path)
    log_filter = _compile_kind_filter(cx_kind, actx)
    return _build_logs_threshold(
        actx,
        log_filter=log_filter,
        condition_type=norm.condition_type,
        threshold=norm.threshold,
        window_enum=win,
    )


def _render_metric_promql_kind(
    cx_kind: dict[str, Any], entry: dict[str, Any], actx: _AlertContext
) -> dict[str, Any]:
    metric_field = str(cx_kind.get("metric_field") or "metric")
    label_field = str(cx_kind.get("group_label_field") or "queue_label")
    metric = str(entry.get(metric_field) or "").strip()
    qlabel = str(entry.get(label_field) or "").strip()
    if not metric or not qlabel:
        raise SpecRenderError(
            f"{actx.ctx}: {metric_field} and {label_field} must be non-empty strings",
            spec_path=actx.spec_path,
        )
    thr = _check_number(entry.get("threshold"), "threshold", actx.ctx, spec_path=actx.spec_path)
    win_min = _check_positive_int(
        entry.get("window_minutes"),
        "window_minutes",
        actx.ctx,
        spec_path=actx.spec_path,
        maximum=MAX_WINDOW_MINUTES,
    )
    app_val_field = cx_kind.get("selector_value_from_app")
    if app_val_field:
        raw_val = actx.app.get(str(app_val_field))
        if not isinstance(raw_val, str) or not raw_val.strip():
            raise SpecRenderError(
                f"{actx.ctx}: requires non-empty app.{app_val_field}", spec_path=actx.spec_path
            )
        values = [raw_val.strip()]
    else:
        vals_field = str(cx_kind.get("selector_values_field") or "queues")
        raw_vals = entry.get(vals_field)
        if (
            not isinstance(raw_vals, list)
            or not raw_vals
            or not all(isinstance(v, str) and v.strip() for v in raw_vals)
        ):
            raise SpecRenderError(
                f"{actx.ctx}: {vals_field} must be a non-empty list of strings",
                spec_path=actx.spec_path,
            )
        values = [v.strip() for v in raw_vals]

    if len(values) == 1:
        selector = f'{qlabel}="{values[0]}"'
    else:
        escaped = "|".join(_PROMQL_REGEX_META.sub(r"\\\1", item) for item in values)
        selector = f'{qlabel}=~"{escaped}"'

    props = _base_props(
        actx,
        alert_type="ALERT_DEF_TYPE_METRIC_THRESHOLD",
        group_by_keys=[qlabel],
        notif_group_by_keys=[],
    )
    props["metricThreshold"] = {
        "metricFilter": {"promql": f"sum by ({qlabel}) ({metric}{{{selector}}})"},
        "rules": [
            {
                "condition": {
                    "threshold": thr,
                    "forOverPct": 100,
                    "ofTheLast": {"metricTimeWindowDynamicDuration": f"{win_min}m"},
                    "conditionType": "METRIC_THRESHOLD_CONDITION_TYPE_MORE_THAN_OR_UNSPECIFIED",
                },
                "override": {"priority": actx.priority_enum},
            }
        ],
        "missingValues": {"replaceWithZero": True},
    }
    return props


def _render_custom(entry: dict[str, Any], actx: _AlertContext) -> dict[str, Any]:
    cond = entry.get("condition")
    if not isinstance(cond, dict):
        raise SpecRenderError(
            f"{actx.ctx}: custom condition must be a structured mapping, got {type(cond).__name__}",
            spec_path=actx.spec_path,
        )
    unknown = set(cond) - ALLOWED_CONDITION_KEYS
    if unknown:
        raise SpecRenderError(
            f"{actx.ctx}: unknown key(s) in condition: {sorted(unknown)}", spec_path=actx.spec_path
        )

    operator = cond.get("operator")
    threshold = _check_number(
        cond.get("threshold"), "condition.threshold", actx.ctx, spec_path=actx.spec_path
    )
    win_min = _check_positive_int(
        cond.get("window_minutes"), "condition.window_minutes", actx.ctx, spec_path=actx.spec_path
    )
    if cond.get("eval_every_minutes") is not None:
        _check_positive_int(
            cond.get("eval_every_minutes"),
            "condition.eval_every_minutes",
            actx.ctx,
            spec_path=actx.spec_path,
            maximum=win_min,
        )

    group_by = _parse_group_by(cond.get("group_by"), actx.ctx, actx.spec_path)
    qfield = actx.config.custom_query_field
    dataprime = entry.get(qfield)
    if not isinstance(dataprime, str) or not dataprime.strip():
        raise SpecRenderError(
            f"{actx.ctx}: custom alert requires non-empty {qfield} string", spec_path=actx.spec_path
        )

    ratio_cfg = cond.get("ratio")
    compared_to = cond.get("compared_to")
    if ratio_cfg is not None and compared_to is not None:
        raise SpecRenderError(
            f"{actx.ctx}: condition cannot set both ratio and compared_to", spec_path=actx.spec_path
        )

    if ratio_cfg is not None:
        return _render_custom_ratio(
            actx,
            dataprime=dataprime,
            ratio_cfg=ratio_cfg,
            operator=operator,
            threshold=threshold,
            win_min=win_min,
            group_by=group_by,
        )
    if compared_to is not None:
        return _render_custom_time_relative(
            actx,
            dataprime=dataprime,
            compared_to=compared_to,
            operator=operator,
            threshold=threshold,
            win_min=win_min,
            group_by=group_by,
        )
    return _render_custom_count(
        actx,
        dataprime=dataprime,
        operator=operator,
        threshold=threshold,
        win_min=win_min,
        group_by=group_by,
    )


def _parse_group_by(group_by_raw: Any, ctx: str, spec_path: str) -> list[str]:
    if group_by_raw is None:
        return []
    if (
        not isinstance(group_by_raw, list)
        or not group_by_raw
        or not all(isinstance(field_key, str) and field_key for field_key in group_by_raw)
    ):
        raise SpecRenderError(
            f"{ctx}: condition.group_by must be a non-empty list of field names", spec_path=spec_path
        )
    return [field_key.removeprefix("$d.") for field_key in group_by_raw]


def _render_custom_ratio(
    actx: _AlertContext,
    *,
    dataprime: str,
    ratio_cfg: Any,
    operator: Any,
    threshold: float,
    win_min: int,
    group_by: list[str],
) -> dict[str, Any]:
    if not isinstance(ratio_cfg, dict):
        raise SpecRenderError(f"{actx.ctx}: condition.ratio must be a mapping", spec_path=actx.spec_path)
    unknown_ratio = set(ratio_cfg) - ALLOWED_RATIO_KEYS
    if unknown_ratio:
        raise SpecRenderError(
            f"{actx.ctx}: unknown key(s) in condition.ratio: {sorted(unknown_ratio)}",
            spec_path=actx.spec_path,
        )
    if ratio_cfg.get("min_total") is not None:
        _check_positive_int(
            ratio_cfg.get("min_total"),
            "condition.ratio.min_total",
            actx.ctx,
            spec_path=actx.spec_path,
        )
    if operator not in ("more_than", "less_than"):
        raise SpecRenderError(
            f"{actx.ctx}: ratio alerts support operator more_than or less_than, got {operator!r}",
            spec_path=actx.spec_path,
        )
    if operator == "more_than" and not (0 <= threshold < 1):
        raise SpecRenderError(
            f"{actx.ctx}: ratio threshold for more_than must be a fraction in [0, 1) (e.g. 0.2 for 20%), got {threshold!r}",
            spec_path=actx.spec_path,
        )
    if operator == "less_than" and not (0 < threshold <= 1):
        raise SpecRenderError(
            f"{actx.ctx}: ratio threshold for less_than must be a fraction in (0, 1], got {threshold!r}",
            spec_path=actx.spec_path,
        )

    try:
        compiled = compile_ratio_query(dataprime)
    except CompileError as exc:
        raise SpecRenderError(f"{actx.ctx}: DataPrime compile error: {exc}", spec_path=actx.spec_path) from exc
    if compiled.numerator_alias != ratio_cfg.get("numerator") or compiled.denominator_alias != ratio_cfg.get("denominator"):
        raise SpecRenderError(
            f"{actx.ctx}: condition.ratio ({ratio_cfg.get('numerator')}/{ratio_cfg.get('denominator')}) "
            f"disagrees with DataPrime groupby aliases ({compiled.numerator_alias}/{compiled.denominator_alias})",
            spec_path=actx.spec_path,
        )
    if group_by and tuple(group_by) != compiled.group_by:
        raise SpecRenderError(
            f"{actx.ctx}: condition.group_by {group_by} disagrees with DataPrime groupby {list(compiled.group_by)}",
            spec_path=actx.spec_path,
        )
    effective_gb = list(compiled.group_by)
    ratio_op = (
        "LOGS_RATIO_CONDITION_TYPE_MORE_THAN_OR_UNSPECIFIED"
        if operator == "more_than"
        else "LOGS_RATIO_CONDITION_TYPE_LESS_THAN"
    )
    win_enum = _logs_window(win_min, actx.ctx, spec_path=actx.spec_path, ratio=True)
    props = _base_props(
        actx,
        alert_type="ALERT_DEF_TYPE_LOGS_RATIO_THRESHOLD",
        group_by_keys=effective_gb,
        notif_group_by_keys=effective_gb,
    )
    props["logsRatioThreshold"] = {
        "numerator": compiled.numerator.to_coralogix(),
        "numeratorAlias": compiled.numerator_alias,
        "denominator": compiled.denominator.to_coralogix(),
        "denominatorAlias": compiled.denominator_alias,
        "rules": [
            {
                "condition": {
                    "threshold": threshold,
                    "timeWindow": {"logsRatioTimeWindowSpecificValue": win_enum},
                    "conditionType": ratio_op,
                },
                "override": {"priority": actx.priority_enum},
            }
        ],
        "notificationPayloadFilter": [],
        "groupByFor": "LOGS_RATIO_GROUP_BY_FOR_BOTH_OR_UNSPECIFIED",
        "ignoreInfinity": True,
    }
    return props


def _render_custom_time_relative(
    actx: _AlertContext,
    *,
    dataprime: str,
    compared_to: Any,
    operator: Any,
    threshold: float,
    win_min: int,
    group_by: list[str],
) -> dict[str, Any]:
    key = str(compared_to)
    if key not in TIME_RELATIVE_COMPARED_TO:
        raise SpecRenderError(f"{actx.ctx}: invalid compared_to {compared_to!r}", spec_path=actx.spec_path)
    if operator not in ("more_than", "less_than"):
        raise SpecRenderError(
            f"{actx.ctx}: time-relative alerts support operator more_than or less_than, got {operator!r}",
            spec_path=actx.spec_path,
        )
    expected_win = TIME_RELATIVE_WINDOWS[key]
    if win_min != expected_win:
        raise SpecRenderError(
            f"{actx.ctx}: compared_to={compared_to!r} compares a {expected_win}m window, got window_minutes={win_min}",
            spec_path=actx.spec_path,
        )
    try:
        log_filter = compile_filter_query(dataprime)
    except CompileError as exc:
        raise SpecRenderError(f"{actx.ctx}: DataPrime compile error: {exc}", spec_path=actx.spec_path) from exc
    rel_op = (
        "LOGS_TIME_RELATIVE_CONDITION_TYPE_MORE_THAN_OR_UNSPECIFIED"
        if operator == "more_than"
        else "LOGS_TIME_RELATIVE_CONDITION_TYPE_LESS_THAN"
    )
    props = _base_props(
        actx,
        alert_type="ALERT_DEF_TYPE_LOGS_TIME_RELATIVE_THRESHOLD",
        group_by_keys=group_by,
    )
    props["logsTimeRelativeThreshold"] = {
        "logsFilter": log_filter.to_coralogix(),
        "rules": [
            {
                "condition": {
                    "threshold": threshold,
                    "comparedTo": TIME_RELATIVE_COMPARED_TO[key],
                    "conditionType": rel_op,
                },
                "override": {"priority": actx.priority_enum},
            }
        ],
        "ignoreInfinity": False,
        "notificationPayloadFilter": [],
        "undetectedValuesManagement": {
            "triggerUndetectedValues": False,
            "autoRetireTimeframe": "AUTO_RETIRE_TIMEFRAME_NEVER_OR_UNSPECIFIED",
        },
    }
    return props


def _render_custom_count(
    actx: _AlertContext,
    *,
    dataprime: str,
    operator: Any,
    threshold: float,
    win_min: int,
    group_by: list[str],
) -> dict[str, Any]:
    try:
        log_filter = compile_filter_query(dataprime)
    except CompileError as exc:
        raise SpecRenderError(f"{actx.ctx}: DataPrime compile error: {exc}", spec_path=actx.spec_path) from exc
    norm = _normalize_count_condition(operator, threshold, actx.ctx, actx.spec_path)
    win_enum = _logs_window(win_min, actx.ctx, spec_path=actx.spec_path)
    return _build_logs_threshold(
        actx,
        log_filter=log_filter,
        condition_type=norm.condition_type,
        threshold=norm.threshold,
        window_enum=win_enum,
        group_by_keys=group_by,
    )


def _normalize_count_condition(
    operator: Any, threshold: float, ctx: str, spec_path: str
) -> CountCondition:
    if operator == "more_than":
        return CountCondition("LOGS_THRESHOLD_CONDITION_TYPE_MORE_THAN_OR_UNSPECIFIED", threshold)
    if operator == "less_than":
        return CountCondition("LOGS_THRESHOLD_CONDITION_TYPE_LESS_THAN", threshold)
    if operator == "more_than_or_equals":
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
            raise SpecRenderError(
                f"{ctx}: more_than_or_equals on log counts requires an integer threshold >= 1, got {threshold!r}",
                spec_path=spec_path,
            )
        return CountCondition("LOGS_THRESHOLD_CONDITION_TYPE_MORE_THAN_OR_UNSPECIFIED", threshold - 1)
    if operator == "less_than_or_equals":
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 0:
            raise SpecRenderError(
                f"{ctx}: less_than_or_equals on log counts requires an integer threshold >= 0, got {threshold!r}",
                spec_path=spec_path,
            )
        return CountCondition("LOGS_THRESHOLD_CONDITION_TYPE_LESS_THAN", threshold + 1)
    raise SpecRenderError(f"{ctx}: invalid condition.operator {operator!r}", spec_path=spec_path)


def _build_logs_threshold(
    actx: _AlertContext,
    *,
    log_filter: SimpleLogFilter,
    condition_type: str,
    threshold: float,
    window_enum: str,
    group_by_keys: list[str] | None = None,
) -> dict[str, Any]:
    props = _base_props(
        actx,
        alert_type="ALERT_DEF_TYPE_LOGS_THRESHOLD",
        group_by_keys=list(group_by_keys or []),
        notif_group_by_keys=[],
    )
    body: dict[str, Any] = {
        "logsFilter": log_filter.to_coralogix(),
        "rules": [
            {
                "condition": {
                    "threshold": threshold,
                    "timeWindow": {"logsTimeWindowSpecificValue": window_enum},
                    "conditionType": condition_type,
                },
                "override": {"priority": actx.priority_enum},
            }
        ],
        "notificationPayloadFilter": [],
    }
    if condition_type == "LOGS_THRESHOLD_CONDITION_TYPE_LESS_THAN":
        body["undetectedValuesManagement"] = {
            "triggerUndetectedValues": True,
            "autoRetireTimeframe": "AUTO_RETIRE_TIMEFRAME_NEVER_OR_UNSPECIFIED",
        }
    props["logsThreshold"] = body
    return props
