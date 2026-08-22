"""montu — config-driven monitoring-spec engine.

Lints checked-in monitoring.yaml specs against the code they pin (deployment names,
routing registries, log tokens, metric-code names) so a refactor that silently breaks a
monitor's query fails CI instead. The engine is generic: everything repo-specific —
spec locations, profiles, alert kinds, token contracts — comes from the consuming
repo's montu.toml.
"""

__all__ = ["__version__"]
__version__ = "0.2.0"
