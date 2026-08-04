"""
Bridge between the engine and the existing scanner.

The engine deliberately knows nothing about ``core.config``, ``SafetyController``
or the legacy registry. This module is the single place those worlds meet: it
builds a legacy-module factory, registers every discovered module as an engine
plugin, and hands back a configured :class:`~engine.pipeline.ScanPipeline`.

Because the adapter preserves the legacy modules unchanged, existing scans keep
producing exactly what they produced before - they just run inside the new
lifecycle, gain evidence-backed scoring, and skip work that cannot apply.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from engine.adapters import register_legacy_modules
from engine.cache import SharedCache
from engine.events import EventBus
from engine.pipeline import ScanPipeline, ScanResult
from engine.plugins import PluginRegistry

LOG = logging.getLogger(__name__)


def discover_legacy_modules() -> dict[str, type[Any]]:
    """Load every legacy module class the existing registry can find."""
    try:
        from core.plugin_registry import PluginRegistry as LegacyRegistry
    except ImportError as exc:  # pragma: no cover - core is always present
        LOG.error("Could not import the legacy plugin registry: %s", exc)
        return {}

    legacy = LegacyRegistry()
    legacy.load_all()

    modules: dict[str, type[Any]] = {}
    for name in legacy.all_names():
        klass = legacy.get(name)
        if klass is not None:
            modules[name] = klass
    return modules


def build_registry(extra_plugin_paths: list[str] | None = None) -> PluginRegistry:
    """Create an engine registry populated with legacy and native plugins."""
    registry = PluginRegistry()

    adapted = register_legacy_modules(registry, discover_legacy_modules())
    LOG.info("Adapted %d legacy modules into engine plugins.", len(adapted))

    # Native engine plugins, if any are shipped, take precedence by version.
    registry.discover("engine.builtin")

    for path in extra_plugin_paths or []:
        registry.load_from_path(path)

    return registry


def make_legacy_factory(
    config: Any,
    logger: Any,
    rate_limiter: Any,
    safety: Any,
    collector: Any = None,
    cancel_event: threading.Event | None = None,
):
    """Return a callable that instantiates legacy modules with scanner wiring."""

    def factory(legacy_class: type[Any], name: str) -> Any:
        return legacy_class(
            config=config,
            logger=logger,
            rate_limiter=rate_limiter,
            safety=safety,
            collector=collector,
            cancel_event=cancel_event,
        )

    return factory


def build_pipeline(
    config: Any,
    logger: Any,
    *,
    rate_limiter: Any = None,
    safety: Any = None,
    collector: Any = None,
    cancel_event: threading.Event | None = None,
    registry: PluginRegistry | None = None,
    bus: EventBus | None = None,
    cache: SharedCache | None = None,
    force_all: bool = False,
) -> ScanPipeline:
    """Assemble a pipeline wired to the scanner's config and safety controls."""
    from core.findings import FindingCollector
    from core.safety import SafetyController

    resolved_safety = safety or getattr(config, "safety", None) or SafetyController()
    resolved_collector = collector or FindingCollector(
        getattr(config, "redactor", None),
        untrusted=not resolved_safety.policy.results_trusted,
    )

    if rate_limiter is None:
        from core.netclient import RateLimiter

        rate_limiter = RateLimiter(getattr(config, "rate_limit", 10))

    factory = make_legacy_factory(
        config=config,
        logger=logger,
        rate_limiter=rate_limiter,
        safety=resolved_safety,
        collector=resolved_collector,
        cancel_event=cancel_event,
    )

    return ScanPipeline(
        registry or build_registry(),
        bus=bus,
        cache=cache,
        threads=int(getattr(config, "threads", 8) or 8),
        active=bool(resolved_safety.policy.active),
        force_all=force_all,
        plugin_timeout=float(getattr(config, "module_timeout", 300) or 300),
        legacy_factory=factory,
    )


def run_scan(
    config: Any,
    logger: Any,
    **kwargs: Any,
) -> ScanResult:
    """Convenience entry point: build a pipeline and scan ``config.target``."""
    pipeline = build_pipeline(config, logger, **kwargs)
    return pipeline.scan(config.target, cancel_event=kwargs.get("cancel_event"))
