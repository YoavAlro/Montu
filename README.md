# montu

Config-driven monitoring-spec engine. A consuming repo checks in one `monitoring.yaml`
per service/app (the PR-reviewed source of truth for its alerts + dashboard) and a
`montu.toml` declaring where those specs live and what they may contain; montu then
proves, deterministically and offline, that every spec still matches the code it pins.

The engine is generic — deployment names, routing registries, log-token contracts, and
alert kinds are all injected from `montu.toml`. Nothing repo-specific lives here.

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
| `E-REGISTRY` | the app has no entry in its profile's registry module |
| `E-QUEUE` | `app.queue` disagrees with the registry's routing mode |
| `E-SUBSYSTEM` | `app.subsystem` matches no helm values file's `app.name` |
| `E-TOKEN` | an alert references a log token or `$d.codeName` no tracked source defines |
| `W-UNMONITORED` | (warning) a registered app has no spec |
| `W-NO-RUNBOOK` | (warning) an alert carries no triage instructions |

Token existence uses `git grep` over the globs in `[engine].token_search_globs`, so only
tracked sources count and the working tree is what's validated.

## montu.toml

```toml
version = 1

[engine]
helm_values_glob = "helm/values/app/*.yaml"   # files whose `app.name` defines subsystems
token_search_globs = ["py/**/*.py"]            # git-grep pathspecs for token existence
dataprime_token_patterns = ["event=tel_[a-z0-9_]+"]  # extracted from custom dataprime
env = "production"                             # the only env specs may declare

[profiles.<name>]
spec_glob = "path/glob/to/*/monitoring.yaml"
subsystem_suffix = "-worker"          # optional: appended to helm app.name for matching
registry_glob = "path/glob/registry.py"  # optional: enables E-REGISTRY/E-QUEUE/W-UNMONITORED
path_tenant_package_prefix = "tenant_"   # optional: enables the tenant path check
requires_tenant = true                # app.tenant mandatory in this profile
requires_queue = true                 # app.queue mandatory in this profile

[profiles.<name>.queue_suffix]        # routing -> queue name suffix (E-QUEUE)
direct = "events"
broadcast = "broadcast"

[profiles.<name>.kinds.<kind>]        # alert kinds this profile allows (custom is built in)
required = ["window_minutes", "threshold"]
tokens = ["event=tel_handler_failed"] # tokens this kind's query greps for (E-TOKEN)
```

A spec's profile is whichever `spec_glob` discovered it — specs carry no profile field.
The built-in `custom` kind requires `name`, `dataprime`, `condition`; its `dataprime` is
scanned for `$d.codeName == '<NAME>'` references and for `dataprime_token_patterns`
matches, all of which must exist in tracked sources.

## Consuming

Not on PyPI. Pin at an exact commit:

```bash
pip install "montu @ git+https://github.com/emerixai/montu@<commit>"
# or, ad hoc without installing:
uvx --from git+https://github.com/emerixai/montu@<commit> montu lint
```

The repo is private: CI needs a read token
(`git+https://x-access-token:${TOKEN}@github.com/emerixai/montu@<commit>`); developers'
normal git credentials suffice.

## Developing

```bash
uv run pytest tests/
```
