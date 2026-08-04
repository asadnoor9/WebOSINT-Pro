"""
Shared module metadata types for WebOSINT Pro.

These types give the legacy `class Module(BaseModule)` contract a richer,
Metasploit-style metadata surface without forcing every existing module to be
rewritten in one pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ModuleCategory(str, Enum):
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    VULNERABILITY = "vulnerability"
    INTEGRATION = "integration"
    REPORTING = "reporting"
    AI_ANALYSIS = "ai_analysis"
    DATABASE = "database"
    UTILITY = "utility"


class ModuleState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    MISSING_DEPENDENCIES = "missing_dependencies"
    LOAD_FAILED = "load_failed"


@dataclass(slots=True)
class ModuleMetadata:
    name: str
    description: str = ""
    version: str = "1.0.0"
    author: str = "WebOSINT Pro"
    category: ModuleCategory = ModuleCategory.PASSIVE_RECON
    requires: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source: str = "builtin"
    module_path: str = ""
    enabled: bool = True
    state: ModuleState = ModuleState.ENABLED
    missing_dependencies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "category": self.category.value,
            "requires": list(self.requires),
            "tags": list(self.tags),
            "source": self.source,
            "module_path": self.module_path,
            "enabled": self.enabled,
            "state": self.state.value,
            "missing_dependencies": list(self.missing_dependencies),
        }
