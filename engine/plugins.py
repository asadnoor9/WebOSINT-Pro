"""
Plugin contract, registry and lifecycle management.

A plugin is a self-contained capability. It never imports or calls another
plugin: everything it needs arrives through the :class:`ScanContext` (shared
cache, event bus, config), and everything it learns leaves through returned
findings and published events.

Lifecycle, in order:

    load()        class-level discovery hook, no I/O
    initialize()  bind to a context, prepare clients
    scan()        do the work, return findings
    validate()    drop or downgrade weakly supported findings
    correlate()   enrich using what other plugins published
    report()      contribute a section to the report
    shutdown()    release resources; always called
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import pkgutil
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engine.cache import SharedCache
from engine.confidence import REPORTING_THRESHOLD, score_finding
from engine.events import EventBus
from engine.models import Asset, Finding, PluginOutcome, Surface, Technology

LOG = logging.getLogger(__name__)


@dataclass(slots=True)
class ScanContext:
    """Everything a plugin is allowed to know about the run.

    Deliberately narrow: a plugin gets the target, shared infrastructure and
    configuration, and nothing that would let it reach into a sibling.
    """

    target: str
    bus: EventBus
    cache: SharedCache
    config: Any = None
    active: bool = False
    technologies: list[Technology] = field(default_factory=list)
    surface: Surface = Surface.UNKNOWN
    assets: list[Asset] = field(default_factory=list)
    shared: dict[str, Any] = field(default_factory=dict)
    cancel_event: threading.Event | None = None

    @property
    def cancelled(self) -> bool:
        return bool(self.cancel_event and self.cancel_event.is_set())

    def technology_names(self) -> set[str]:
        return {tech.name.lower() for tech in self.technologies}


class Plugin(ABC):
    """Base class for every capability in the platform."""

    #: Stable identifier used in config, CLI flags and reports.
    name: str = ""
    #: Semantic version of this plugin's detection logic.
    version: str = "1.0.0"
    #: Minimum engine version this plugin is known to work with.
    requires_engine: str = "3.0.0"
    description: str = ""
    category: str = "general"
    #: Whether running this plugin sends traffic beyond passive observation.
    active: bool = False
    #: Third-party imports this plugin needs; missing ones disable it cleanly.
    requires: tuple[str, ...] = ()
    #: Pipeline stage ordering hint (lower runs earlier).
    order: int = 100

    def __init__(self) -> None:
        self.context: ScanContext | None = None
        self.enabled: bool = True
        self._loaded: bool = False

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def load(cls) -> bool:
        """Class-level readiness check. Must not perform I/O.

        Returns False when a required dependency is absent, which makes the
        registry skip the plugin with a clear reason instead of crashing.
        """
        return all(importlib.util.find_spec(dependency) is not None for dependency in cls.requires)

    def initialize(self, context: ScanContext) -> None:
        """Bind the plugin to a scan. Override to prepare clients."""
        self.context = context
        self._loaded = True

    @abstractmethod
    def scan(self, context: ScanContext) -> list[Finding]:
        """Perform the plugin's work and return raw findings."""

    def validate(self, findings: list[Finding], context: ScanContext) -> list[Finding]:
        """Score findings and suppress those below the reporting threshold.

        The default implementation is the multi-indicator gate: anything backed
        by a single weak signal is marked suppressed with a reason rather than
        silently dropped, so an analyst can still audit it.
        """
        return [score_finding(finding, threshold=REPORTING_THRESHOLD) for finding in findings]

    def correlate(self, findings: list[Finding], context: ScanContext) -> list[Finding]:
        """Enrich findings with cross-plugin knowledge. Override as needed."""
        return findings

    def report(self, findings: list[Finding], context: ScanContext) -> dict[str, Any]:
        """Contribute a structured section to the final report."""
        return {
            "plugin": self.name,
            "version": self.version,
            "findings": [finding.to_dict() for finding in findings],
        }

    def shutdown(self) -> None:
        """Release resources. Always invoked, even after a failed scan."""
        self.context = None
        self._loaded = False

    # -- helpers -----------------------------------------------------------

    def should_run(self, context: ScanContext) -> tuple[bool, str]:
        """Last-chance self-veto, evaluated after selection."""
        if not self.enabled:
            return False, "Plugin is disabled."
        if self.active and not context.active:
            return False, "Plugin requires active mode."
        return True, ""

    def execute(self, context: ScanContext) -> PluginOutcome:
        """Run the full lifecycle for one target, isolating all failures."""
        started = time.monotonic()
        outcome = PluginOutcome(plugin=self.name, status="ok")

        allowed, reason = self.should_run(context)
        if not allowed:
            outcome.status = "skipped"
            outcome.skipped_reason = reason
            outcome.duration_ms = 0
            context.bus.publish(
                "plugin.skipped", {"plugin": self.name, "reason": reason}, source=self.name
            )
            return outcome

        context.bus.publish("plugin.started", {"plugin": self.name}, source=self.name)
        try:
            self.initialize(context)
            findings = self.scan(context) or []
            findings = self.validate(findings, context) or []
            findings = self.correlate(findings, context) or []
            outcome.findings = findings
            outcome.raw = self.report(findings, context)
            context.bus.publish(
                "plugin.finished",
                {"plugin": self.name, "findings": len(findings)},
                source=self.name,
            )
        except Exception as exc:
            LOG.exception("Plugin %s failed", self.name)
            outcome.status = "error"
            outcome.error = f"{type(exc).__name__}: {exc}"
            context.bus.publish(
                "plugin.failed", {"plugin": self.name, "error": outcome.error}, source=self.name
            )
        finally:
            try:
                self.shutdown()
            except Exception:
                LOG.exception("Plugin %s failed during shutdown", self.name)
            outcome.duration_ms = int((time.monotonic() - started) * 1000)

        return outcome


@dataclass(slots=True)
class Registration:
    """A plugin class known to the registry, loaded or not."""

    name: str
    plugin_class: type[Plugin]
    version: str
    category: str
    active: bool
    available: bool
    reason: str = ""
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "category": self.category,
            "active": self.active,
            "available": self.available,
            "reason": self.reason,
            "source": self.source,
        }


class PluginRegistry:
    """Discovers, versions, enables and instantiates plugins."""

    def __init__(self) -> None:
        self._registrations: dict[str, Registration] = {}
        self._disabled: set[str] = set()
        self._lock = threading.RLock()

    # -- registration ------------------------------------------------------

    def register(self, plugin_class: type[Plugin], *, source: str = "") -> Registration:
        name = (plugin_class.name or plugin_class.__name__).strip().lower()
        if not name:
            raise ValueError("Plugin classes must define a name.")

        try:
            available = plugin_class.load()
            reason = "" if available else "Missing dependency: " + ", ".join(plugin_class.requires)
        except Exception as exc:
            available, reason = False, f"load() raised {type(exc).__name__}: {exc}"

        registration = Registration(
            name=name,
            plugin_class=plugin_class,
            version=plugin_class.version,
            category=plugin_class.category,
            active=plugin_class.active,
            available=available,
            reason=reason,
            source=source or plugin_class.__module__,
        )
        with self._lock:
            existing = self._registrations.get(name)
            if existing and existing.version > registration.version:
                LOG.debug(
                    "Keeping plugin %s v%s over v%s", name, existing.version, registration.version
                )
                return existing
            self._registrations[name] = registration
        return registration

    def discover(self, package: str = "engine.builtin") -> list[Registration]:
        """Auto-register every Plugin subclass exported by ``package``."""
        found: list[Registration] = []
        try:
            module = importlib.import_module(package)
        except ModuleNotFoundError:
            return found

        paths = list(getattr(module, "__path__", []))
        for info in pkgutil.iter_modules(paths):
            full_name = f"{package}.{info.name}"
            try:
                submodule = importlib.import_module(full_name)
            except Exception as exc:
                LOG.warning("Could not import plugin module %s: %s", full_name, exc)
                continue
            found.extend(self._register_module(submodule, source=full_name))
        return found

    def _register_module(self, module: Any, *, source: str) -> list[Registration]:
        results: list[Registration] = []
        for attribute in vars(module).values():
            if (
                isinstance(attribute, type)
                and issubclass(attribute, Plugin)
                and attribute is not Plugin
                and not getattr(attribute, "__abstractmethods__", None)
            ):
                results.append(self.register(attribute, source=source))
        return results

    def load_from_path(self, path: str | Path) -> list[Registration]:
        """Hot-load plugins from a file or directory outside the package."""
        target = Path(path)
        files = sorted(target.glob("*_plugin.py")) if target.is_dir() else [target]
        results: list[Registration] = []

        for file in files:
            if not file.is_file():
                continue
            module_name = f"webosint_hotplugin_{file.stem}"
            spec = importlib.util.spec_from_file_location(module_name, file)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
            except Exception as exc:
                LOG.warning("Could not hot-load %s: %s", file, exc)
                continue
            results.extend(self._register_module(module, source=str(file)))
        return results

    def reload(self) -> list[Registration]:
        """Re-import every registered plugin module (supports ``reload``)."""
        with self._lock:
            modules = {reg.plugin_class.__module__ for reg in self._registrations.values()}
            self._registrations.clear()

        results: list[Registration] = []
        for module_name in sorted(modules):
            try:
                module = importlib.reload(importlib.import_module(module_name))
            except Exception as exc:
                LOG.warning("Could not reload %s: %s", module_name, exc)
                continue
            results.extend(self._register_module(module, source=module_name))
        return results

    # -- enable / disable --------------------------------------------------

    def disable(self, name: str) -> None:
        with self._lock:
            self._disabled.add(name.strip().lower())

    def enable(self, name: str) -> None:
        with self._lock:
            self._disabled.discard(name.strip().lower())

    def is_enabled(self, name: str) -> bool:
        with self._lock:
            return name.strip().lower() not in self._disabled

    # -- access ------------------------------------------------------------

    def registrations(self) -> list[Registration]:
        with self._lock:
            return sorted(self._registrations.values(), key=lambda item: item.name)

    def available_names(self) -> list[str]:
        return [
            reg.name for reg in self.registrations() if reg.available and self.is_enabled(reg.name)
        ]

    def create(self, name: str) -> Plugin | None:
        key = name.strip().lower()
        with self._lock:
            registration = self._registrations.get(key)
        if registration is None or not registration.available:
            return None
        instance = registration.plugin_class()
        instance.enabled = self.is_enabled(key)
        return instance

    def create_many(self, names: list[str]) -> list[Plugin]:
        instances = [self.create(name) for name in names]
        return sorted((item for item in instances if item is not None), key=lambda item: item.order)


#: Process-wide default registry. Tests build their own.
REGISTRY = PluginRegistry()
