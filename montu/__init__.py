"""montu — config-driven monitoring-spec engine.

Lints checked-in monitoring.yaml specs against the code they pin (deployable-unit
names, inventories, query identifiers) so a refactor that silently breaks a monitor's
query fails CI instead. The engine is provider- and repo-agnostic: spec locations,
profiles, alert kinds, and every name it matches on come from the consuming repo's
montu.toml.
"""

__all__ = ["__version__"]
__version__ = "0.4.0"
