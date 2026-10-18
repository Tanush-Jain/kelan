
from kelan.core.plugin import PluginRegistry, load_plugins_from

DEFAULT_PLUGIN_MODULES = [
    "kelan.plugins.sca",
    "kelan.plugins.ports",
    "kelan.plugins.dast_adapter",
    "kelan.plugins.sast_adapter",
    "kelan.plugins.analyze_ratelimit",
    "kelan.plugins.runtime",
    "kelan.plugins.cloud",
    "kelan.plugins.chains",
]


def register_all(registry: PluginRegistry) -> int:
    return load_plugins_from(DEFAULT_PLUGIN_MODULES, registry)
