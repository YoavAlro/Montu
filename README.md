<p align="center">
  <img src="assets/logo.svg" alt="" width="104">
</p>

# montu

Named for the falcon-headed Egyptian god; the mark is his watchful eye — which is the
whole job here, watching specs and code for drift.

Config-driven monitoring-spec engine. A consuming repo checks in one `monitoring.yaml`
per service/app (the PR-reviewed source of truth for its alerts + dashboard) and a
`montu.toml` declaring where those specs live and what they may contain; montu then
proves, deterministically and offline, that every spec still matches the code it pins.

**The engine is provider-agnostic and repo-agnostic.** It knows no observability
vendor's query language, no deployment tooling, no framework: spec locations, profiles,
alert kinds, subsystem derivation, registry parsing, and the token patterns queries are
scanned for are all regexes and globs injected from `montu.toml`. The examples below
bind it to a Coralogix + Helm + Celery stack — swap the patterns for yours.

## Commands

```bash
montu lint            # validate ALL specs against the code (exit 1 on drift)
montu lint <paths...> # validate specific specs
montu map             # print the monitoring estate (coverage, gaps, runbooks)
```

`lint` always validates every spec, never fix-on-touch: drift is usually caused by code
changes (a deployment rename, a routing flip, a log-token rename) while the spec itself
sits untouched.

## Checks

| Code | Fails when |
|---|---|
| `E-YAML` | the spec is not parseable YAML |
| `E-SCHEMA` | required fields missing, invalid alert kind for the profile, wrong `env` |
| `E-PATH` | `app.slug` / `app.tenant` disagree with where the spec sits |
| `E-REGISTRY` | the app has no entry in its profile's registry file |
| `E-QUEUE` | `app.queue` disagrees with the registry's routing mode |
| `E-SUBSYSTEM` | `app.subsystem` matches no name extracted from the subsystem sources |
| `E-TOKEN` | an alert references a token no tracked source defines |
| `E-FILEREF` | a spec field naming a sibling file (e.g. a dashboard model) doesn't resolve |
| `W-UNMONITORED` | (warning) a registered app has no spec |
| `W-NO-RUNBOOK` | (warning) an alert carries no triage instructions |

Token existence uses `git grep` over the globs in `[engine].token_search_globs`, so only
tracked sources count and the working tree is what's validated.

## montu.toml

```toml
version = 1

[engine]
# Files whose content names your deployable units, and the regex (MULTILINE; group 1,
# or the whole match when the pattern has no group) that extracts each name.
# Example: helm values files where `app.name` is the k8s deployment / log subsystem.
subsystem_sources_glob = "helm/values/app/*.yaml"
subsystem_pattern = "^app:\\n  name: ([A-Za-z0-9-]+)$"

token_search_globs = ["py/**/*.py"]   # git-grep pathspecs for token existence

# Regexes run against a custom alert's raw query; every match (group 1 if the pattern
# has a group, else the whole match) must exist in tracked sources. Put your query
# language's referenced-identifier shapes here — e.g. for Coralogix DataPrime:
query_token_patterns = [
    "event=tel_[a-z0-9_]+",
    "\\$d\\.codeName\\s*==\\s*'([A-Z0-9_]+)'",
]

# What the custom alert's raw-query field is called in specs (default: "query").
# Name it after your provider's language if you prefer specs to be self-describing:
custom_query_field = "dataprime"

env = "production"                    # the only env specs may declare

[profiles.<name>]
spec_glob = "path/glob/to/*/monitoring.yaml"
subsystem_suffix = "-worker"          # optional: appended to extracted names for matching
registry_glob = "path/glob/registry.py"  # optional: enables E-REGISTRY/E-QUEUE/W-UNMONITORED
# Regex over the registry file: group 1 = app slug, optional group 2 = routing.
registry_entry_pattern = "TelAppSpec\\(\\s*[\"']([a-z0-9_]+)[\"'](?:.*?[\"'](direct|broadcast)[\"'])?"
registry_default_routing = "direct"   # routing when group 2 is absent
path_tenant_package_prefix = "tenant_"   # optional: enables the tenant path check
requires_tenant = true                # app.tenant mandatory in this profile
requires_queue = true                 # app.queue mandatory in this profile
# Spec fields whose value names a file next to the spec; each must exist (E-FILEREF).
file_ref_fields = ["grafana_dashboard"]

[profiles.<name>.queue_suffix]        # routing -> queue name suffix (E-QUEUE)
direct = "events"
broadcast = "broadcast"

[profiles.<name>.kinds.<kind>]        # alert kinds this profile allows (custom is built in)
required = ["window_minutes", "threshold"]
tokens = ["event=tel_handler_failed"] # tokens this kind's query greps for (E-TOKEN)
```

A spec's profile is whichever `spec_glob` discovered it — specs carry no profile field.
The built-in `custom` kind requires `name`, the configured query field, and `condition`;
its query text is scanned with `query_token_patterns`, and every extracted token must
exist in tracked sources.

## Consuming

Not on PyPI. Pin at an exact commit:

```bash
pip install "montu @ git+https://github.com/YoavAlro/montu@<commit>"
# or, ad hoc without installing:
uvx --from git+https://github.com/YoavAlro/montu@<commit> montu lint
```

## Developing

```bash
uv run pytest tests/
```
