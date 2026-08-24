<p align="center">
  <img src="assets/logo.png" alt="montu — watch the watchers" width="340">
</p>

# montu

Named for the falcon-headed Egyptian god — the sharpest eye in the sky, which is the
whole job here: montu doesn't run your monitoring, it watches the watchers, catching the
drift between your specs and your code that no test and no dashboard will show you.

Monitoring config rots silently. You rename a deployment, flip a queue's routing, or
tidy up a log line — and an alert that used to protect you now matches nothing at all.
No test goes red. Nothing fails. You find out during the incident it was supposed to
catch.

montu closes that gap. You check in one `monitoring.yaml` per service; montu proves —
deterministically, offline, on every pull request — that each alert still resolves
against reality: the deployment exists, derived fields agree with your inventory, and
every identifier a query references is still defined somewhere in tracked source.

**The engine is provider- and repo-agnostic.** It knows no observability vendor's query
language, no deployment tool, no framework, and nothing about how your repo models its
services. Spec locations, alert kinds, deployment-name extraction, inventory parsing,
and the identifier shapes queries are scanned for are all globs and regexes you declare
in `montu.toml`.

## Commands

```bash
montu lint            # validate ALL specs against the code (exit 1 on drift)
montu lint <paths...> # validate specific specs
montu map             # print the monitoring estate (coverage, gaps, runbooks)
```

`lint` always validates every spec, never fix-on-touch: drift is usually caused by code
changes while the spec itself sits untouched.

## Checks

| Code | Fails when |
|---|---|
| `E-YAML` | the spec is not parseable YAML |
| `E-SCHEMA` | required fields missing, invalid alert kind for the profile, wrong `env` |
| `E-PATH` | a spec field disagrees with the directory the spec sits in |
| `E-INVENTORY` | the owner has no entry in its profile's inventory file |
| `E-FIELD` | a derived field disagrees with the owner's id + inventory variant |
| `E-UNIT` | the spec's deployable-unit name matches nothing in the unit sources |
| `E-TOKEN` | an alert references an identifier no tracked source defines |
| `E-FILEREF` | a spec field naming a sibling file (e.g. a dashboard model) doesn't resolve |
| `W-UNMONITORED` | (warning) an inventoried owner has no spec |
| `W-NO-RUNBOOK` | (warning) an alert carries no triage instructions |

Identifier existence uses `git grep` over the configured globs, so only tracked sources
count and the working tree is what's validated.

## The spec

One `monitoring.yaml` per owner. The engine fixes only a small core — `version`, `env`,
`slack_channel`, `alerts[].kind`, `alerts[].runbook`, and two `app` fields whose *names*
you choose (`id_field`, `unit_field`). Everything else is yours.

```yaml
version: 1
app:
  id: checkout          # the owner id (field name = id_field)
  unit: checkout-api    # the deployable unit (field name = unit_field)
env: production
slack_channel: "#checkout-alerts"
alerts:
  - kind: error_rate
    window_minutes: 15
    threshold: 10
    runbook: |
      What firing means, first checks, where to go next.
  - kind: custom
    name: checkout-latency
    query: "<your backend's query language, verbatim>"
    condition: "p95 > 2s over 15m"
    runbook: |
      ...
dashboard: true
```

## montu.toml

```toml
version = 1

[engine]
# Files whose content names your deployable units, and the regex (MULTILINE; group 1,
# or the whole match when the pattern has no group) that extracts each name.
unit_sources_glob = "deploy/*.yaml"
unit_pattern = "^service: ([a-z0-9-]+)$"

source_globs = ["src/**/*.py"]   # git-grep pathspecs for identifier existence

# Regexes run against a custom alert's raw query; every match (group 1 if the pattern
# has a group, else the whole match) must exist in the sources above. Put your query
# language's referenced-identifier shapes here.
query_identifier_patterns = ["marker=[a-z0-9_]+", "code == '([A-Z0-9_]+)'"]

custom_query_field = "query"   # what the raw-query field is called in your specs
id_field = "id"                # which app.* field is the owner id
unit_field = "unit"            # which app.* field names the deployable unit
env = "production"             # the only env specs may declare

[profiles.<name>]
spec_glob = "services/*/monitoring.yaml"
unit_suffix = ""                       # appended to extracted unit names when matching
required_fields = ["team"]             # extra app.* fields this profile demands
file_ref_fields = ["dashboard_model"]  # spec fields naming a sibling file (E-FILEREF)

# Optional. An inventory enumerating the owners this profile should cover; enables
# E-INVENTORY, W-UNMONITORED, and variant-derived fields. Group 1 = owner id,
# optional group 2 = variant.
[profiles.<name>.inventory]
glob = "services/inventory.txt"
entry_pattern = "^service ([a-z0-9_]+)(?: ([a-z]+))?$"
default_variant = "steady"

# Optional. Assert a spec field matches an ancestor directory of the spec file
# (ancestor 0 = the spec's own directory).
[[profiles.<name>.path_rules]]
field = "id"

[[profiles.<name>.path_rules]]
field = "team"
ancestor = 2
prefix = "team_"

# Optional. Derive a field's expected value from the owner id and its variant;
# {variant} renders through variant_values when a mapping exists.
[profiles.<name>.field_rules]
channel = "{id}.{variant}"

[profiles.<name>.variant_values]
steady = "stream"
burst  = "batch"

# Alert kinds this profile allows. `custom` is built in and always available.
[profiles.<name>.kinds.error_rate]
required = ["window_minutes", "threshold"]
tokens = ["marker=request_failed"]   # identifiers this kind's query greps for
```

A spec's profile is whichever `spec_glob` discovered it — specs carry no profile field.
The built-in `custom` kind requires `name`, the configured query field, and `condition`;
its query text is scanned with `query_identifier_patterns`.

## Consuming

Not on PyPI. Pin at an exact commit:

```bash
pip install "montu @ git+https://github.com/YoavAlro/Montu@<commit>"
# or, ad hoc without installing:
uvx --from git+https://github.com/YoavAlro/Montu@<commit> montu lint
```

## Developing

```bash
uv run pytest tests/
```
