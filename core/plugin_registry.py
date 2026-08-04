"""
WebOSINT Pro - Plugin Registry
Dynamic scanner loading with metadata, versioning, and isolation.

Supports two scanner locations:
  1. Built-in:  scanners/  (ships with the tool)
  2. Community: plugins/   (user-installed)

Usage:
    registry = PluginRegistry()
    registry.load_all()
    module_class = registry.get("dns")
    instance = module_class(config, logger, rate_limiter)
"""

from __future__ import annotations

import importlib.util
import logging
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

from core.module_types import ModuleCategory, ModuleMetadata, ModuleState

logger = logging.getLogger("webosint.plugins")


PluginMeta = ModuleMetadata


class PluginRegistry:
    """
    Central registry for all scan modules.

    Priority (highest first):
      plugins/ directory > scanners/ directory > legacy modules/ directory
    """

    # Built-in scanners — canonical order for sequential-first execution
    BUILTIN_SCAN_ORDER = [
        "dns",
        "ip",
        "whois",
        "subdomains",
        "http",
        "ssl",
        "ports",
        "mail",
        "waf",
        "webapp",
        "dirs",
        "javascript",
        "api",
        "websocket",
        "database",
        "cors",
        "cloud",
        "container",
        "ids",
        "siem",
        "honeypot",
        "cve",
        "osint",
    ]

    def __init__(self) -> None:
        self._registry: dict[str, type[Any]] = {}
        self._meta: dict[str, ModuleMetadata] = {}
        self._disabled: set[str] = set()
        self._root = Path(__file__).parent.parent

    # ── Loading ─────────────────────────────────────────────────────────────────

    def load_all(self) -> None:
        """Load all built-in scanners then community plugins."""
        self._load_directory(self._root / "modules", source="builtin")
        self._load_directory(self._root / "scanners", source="builtin")
        self._load_directory(self._root / "plugins", source="plugin")

    def _load_directory(self, directory: Path, source: str) -> None:
        if not directory.exists():
            return
        for py_file in sorted(directory.glob("*_module.py")):
            mod_name = py_file.stem.replace("_module", "")
            try:
                self._load_module_file(mod_name, py_file, source)
            except Exception as exc:
                logger.warning(f"[plugin-registry] Failed to load {py_file.name}: {exc}")

    def _load_module_file(self, name: str, path: Path, source: str) -> None:
        """Import a module file and register its Module class."""
        spec = importlib.util.spec_from_file_location(f"webosint_plugin_{name}", path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot create spec for {path}")

        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]

        if not hasattr(mod, "Module"):
            raise ImportError(f"No 'Module' class found in {path.name}")

        klass = mod.Module
        raw_category = getattr(klass, "CATEGORY", ModuleCategory.PASSIVE_RECON.value)
        try:
            category = ModuleCategory(raw_category)
        except ValueError:
            category = ModuleCategory.PASSIVE_RECON

        requires = list(getattr(klass, "REQUIRES", []))
        missing = self._missing_dependencies(requires)
        state = ModuleState.MISSING_DEPENDENCIES if missing else ModuleState.ENABLED
        meta = ModuleMetadata(
            name=getattr(klass, "NAME", name),
            description=getattr(klass, "DESCRIPTION", ""),
            version=getattr(klass, "VERSION", "1.0.0"),
            author=getattr(klass, "AUTHOR", "WebOSINT Pro"),
            requires=requires,
            tags=getattr(klass, "TAGS", []),
            source=source,
            module_path=str(path),
            category=category,
            enabled=not missing,
            state=state,
            missing_dependencies=missing,
        )

        # Plugin overrides builtin with same name
        if missing:
            logger.warning(
                "[plugin-registry] %s missing dependencies: %s",
                meta.name,
                ", ".join(missing),
            )

        self._registry[meta.name] = klass
        self._meta[meta.name] = meta
        logger.debug(f"[plugin-registry] Loaded [{source}] {meta.name} from {path.name}")

    def _missing_dependencies(self, requirements: list[str]) -> list[str]:
        missing: list[str] = []
        for requirement in requirements:
            package = str(requirement).split("==")[0].split(">=")[0].split("[")[0].strip()
            if not package:
                continue
            try:
                importlib_metadata.version(package)
            except importlib_metadata.PackageNotFoundError:
                if importlib.util.find_spec(package) is None:
                    missing.append(requirement)
        return missing

    # ── Query API ───────────────────────────────────────────────────────────────

    def get(self, name: str) -> type[Any] | None:
        """Return module class for name, or None if not found."""
        if name in self._disabled:
            return None
        meta = self._meta.get(name)
        if meta and meta.state == ModuleState.MISSING_DEPENDENCIES:
            return None
        return self._registry.get(name)

    def get_meta(self, name: str) -> PluginMeta | None:
        return self._meta.get(name)

    def all_names(self) -> list[str]:
        """Return all registered scanner names, sorted in canonical run order."""
        ordered = [n for n in self.BUILTIN_SCAN_ORDER if n in self._registry]
        extras = [n for n in sorted(self._registry) if n not in ordered]
        return ordered + extras

    def all_meta(self) -> dict[str, PluginMeta]:
        return dict(self._meta)

    def is_registered(self, name: str) -> bool:
        return name in self._registry and name not in self._disabled

    def enable(self, name: str) -> None:
        if name in self._registry:
            self._disabled.discard(name)
            meta = self._meta.get(name)
            if meta and not meta.missing_dependencies:
                meta.enabled = True
                meta.state = ModuleState.ENABLED

    def disable(self, name: str) -> None:
        if name in self._registry:
            self._disabled.add(name)
            meta = self._meta.get(name)
            if meta:
                meta.enabled = False
                meta.state = ModuleState.DISABLED

    def community_plugins(self) -> list[PluginMeta]:
        return [m for m in self._meta.values() if m.source == "plugin"]

    def print_table(self) -> None:
        """Pretty-print all registered modules to stdout."""
        from utils.output import ColorOutput as C

        print(f"\n{C.BOLD}{C.CYAN}Registered Modules:{C.RESET}\n")
        for name in self.all_names():
            meta = self._meta.get(name)
            if meta is None:
                continue
            tag = f"{C.DIM}[plugin]{C.RESET} " if meta.source == "plugin" else ""
            print(f"  {C.GREEN}{name:<18}{C.RESET} {tag}{meta.description}")
        community = self.community_plugins()
        if community:
            print(f"\n  {C.DIM}{len(community)} community plugin(s) loaded{C.RESET}")
        print()
