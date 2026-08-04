"""
Native engine plugins.

Plugins placed here are discovered automatically by
``PluginRegistry.discover("engine.builtin")``. They take precedence over an
adapted legacy module of the same name when their version is higher, which is
the migration path: rewrite a module as a native plugin, bump the version, and
the engine switches over with no other change.
"""
