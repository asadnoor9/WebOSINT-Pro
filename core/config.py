"""
WebOSINT Pro - Enterprise Configuration Engine
Supports: JSON, YAML, environment variable overrides, schema validation.

Priority (highest first):
  CLI args > environment variables > config file > profile defaults > hard defaults
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from core.paths import logs_dir, reports_dir

# YAML is optional — graceful fallback to JSON-only
try:
    import yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# ── Profile presets ─────────────────────────────────────────────────────────────

PROFILE_SETTINGS: dict[str, dict[str, Any]] = {
    "safe": {
        "threads": 5,
        "timeout": 15,
        "delay": 1.0,
        "rate_limit": 20,
        "aggressive": False,
        "passive_only": True,
        "stealth": False,
        "jitter": 0.0,
        "randomize_order": False,
        "modules_blacklist": ["ports", "waf", "ids", "dirs"],
    },
    "medium": {
        "threads": 10,
        "timeout": 10,
        "delay": 0.3,
        "rate_limit": 50,
        "aggressive": False,
        "passive_only": False,
        "stealth": False,
        "jitter": 0.0,
        "randomize_order": False,
        "modules_blacklist": [],
    },
    "aggressive": {
        "threads": 25,
        "timeout": 8,
        "delay": 0.0,
        "rate_limit": 200,
        "aggressive": True,
        "passive_only": False,
        "stealth": False,
        "jitter": 0.0,
        "randomize_order": False,
        "modules_blacklist": [],
    },
    "stealth": {
        "threads": 3,
        "timeout": 20,
        "delay": 3.0,
        "rate_limit": 10,
        "aggressive": False,
        "passive_only": False,
        "stealth": True,
        "jitter": 2.0,
        "randomize_order": True,
        "modules_blacklist": [],
    },
    "bugbounty": {
        "threads": 15,
        "timeout": 12,
        "delay": 0.2,
        "rate_limit": 80,
        "aggressive": False,
        "passive_only": False,
        "stealth": False,
        "jitter": 0.0,
        "randomize_order": False,
        "modules_blacklist": [],
    },
    "api-only": {
        "threads": 10,
        "timeout": 10,
        "delay": 0.2,
        "rate_limit": 60,
        "aggressive": False,
        "passive_only": False,
        "stealth": False,
        "jitter": 0.0,
        "randomize_order": False,
        "modules_blacklist": [],
    },
}

ALL_MODULES: list[str] = [
    "dns",
    "ip",
    "whois",
    "subdomains",
    "http",
    "ssl",
    "ports",
    "dirs",
    "webapp",
    "javascript",
    "api",
    "websocket",
    "database",
    "mail",
    "waf",
    "ids",
    "siem",
    "honeypot",
    "cve",
    "osint",
    "cors",
    "cloud",
    "container",
]

DEFAULT_USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

# -- Environment variable prefix ---------------------------------------------
_ENV_PREFIX = "WEBOSINT_"

# Modules that send intrusive traffic. Only scheduled when --active is given.
ACTIVE_MODULES: set[str] = {
    "ports",
    "dirs",
    "waf",
    "ids",
    "siem",
    "honeypot",
    "database",
    "api",
    "websocket",
}

# Passive OSINT modules — the default module set.
PASSIVE_MODULES: list[str] = [
    "dns",
    "ip",
    "whois",
    "subdomains",
    "http",
    "ssl",
    "mail",
    "webapp",
    "javascript",
    "cve",
    "osint",
]


class Config:
    """
    Enterprise configuration object.
    Build from CLI args, file config, env vars, and profile defaults.
    """

    def __init__(self, args: Any) -> None:
        self._args = args
        self._init_from_args(args)
        self._apply_profile()
        self._apply_yaml_profile()
        self._apply_file_config()
        self._apply_env_overrides()
        self._validate()
        self._setup_dirs()

    # ── Initialise from CLI args ─────────────────────────────────────────────────

    def _init_from_args(self, args: Any) -> None:
        self.target: str = str(args.target).strip().lower()
        self.targets_file: str | None = getattr(args, "targets_file", None)
        self.profile: str = getattr(args, "profile", "medium")
        self.verbose: int = getattr(args, "verbose", 0)
        self.no_external: bool = getattr(args, "no_external", False)
        self.authorized: bool = getattr(args, "authorized", False)
        self.lab_mode: bool = getattr(args, "lab_mode", False)

        # Safety / authorization
        self.active: bool = getattr(args, "active", False)
        self.allow_private: bool = getattr(args, "allow_private", False)
        self.insecure_tls: bool = getattr(args, "insecure_tls", False)
        self.allowlist_path: str | None = getattr(args, "allowlist", None)
        self.confirm_target: str | None = getattr(args, "confirm_target", None)
        self.max_redirects: int = int(getattr(args, "max_redirects", 3) or 3)

        # Privacy / data minimization
        self.detail: str = getattr(args, "detail", "standard") or "standard"
        self.keep_raw: bool = getattr(args, "keep_raw", False)
        self.retention_days: int = int(getattr(args, "retention_days", 30) or 0)
        self.log_retention_days: int = int(getattr(args, "log_retention_days", 14) or 0)
        self.cleanup: bool = not getattr(args, "no_cleanup", False)
        # Telemetry is disabled by default and never transmits anything.
        self.telemetry: bool = False

        # Output / logging
        self.quiet: bool = getattr(args, "quiet", False)
        self.json_stdout: bool = getattr(args, "json_stdout", False)
        self.write_log_file: bool = not getattr(args, "no_log_file", False)

        # Network
        self.proxy: str | None = getattr(args, "proxy", None)
        self.dns_server: str | None = getattr(args, "dns_server", None)
        self.privacy_mode: bool = getattr(args, "privacy_mode", False)

        # API keys come from the environment only, never from argv, so they
        # cannot leak through shell history or the process list.
        self.shodan_key: str | None = os.environ.get(_ENV_PREFIX + "SHODAN_KEY") or None
        self.nvd_key: str | None = os.environ.get(_ENV_PREFIX + "NVD_KEY") or None

        # Output
        self.output_dir: str = getattr(args, "output_dir", None) or str(reports_dir())
        self.report_format: str = getattr(args, "output", "json")
        self.report_name: str | None = getattr(args, "report_name", None)
        self.log_dir: str = getattr(args, "log_dir", None) or str(logs_dir())

        # Performance (will be overridden by profile)
        self._cli_threads: int | None = getattr(args, "threads", None)
        self._cli_timeout: int | None = getattr(args, "timeout", None)
        self._cli_delay: float | None = getattr(args, "delay", None)
        self._cli_rate_limit: int | None = getattr(args, "rate_limit", None)
        self.retries: int = getattr(args, "retries", 2)
        self.concurrency: int | None = getattr(args, "concurrency", None)

        # Modules
        mod_arg: str = getattr(args, "modules", "all")
        skip_arg: str = getattr(args, "skip_modules", "") or ""
        self._requested_modules: str = mod_arg
        self._skip_modules: str = skip_arg

        # Wordlists
        self.wordlist: str | None = getattr(args, "wordlist", None)
        self.dir_wordlist: str | None = getattr(args, "dir_wordlist", None)

        # User agent
        self._cli_user_agent: str | None = getattr(args, "user_agent", None)

        # Config file path
        self._config_file: str = getattr(args, "config", "config.json")

        # Session ID (unique per scan)
        import uuid

        self.session_id: str = str(uuid.uuid4())[:8]

    # ── Profile application ──────────────────────────────────────────────────────

    def _apply_profile(self) -> None:
        profile = PROFILE_SETTINGS.get(self.profile, PROFILE_SETTINGS["medium"])
        self.threads: int = self._cli_threads or profile["threads"]
        self.timeout: int = self._cli_timeout or profile["timeout"]
        self.delay: float = self._cli_delay if self._cli_delay is not None else profile["delay"]
        self.rate_limit: int = self._cli_rate_limit or profile["rate_limit"]
        self.aggressive: bool = profile["aggressive"]
        self.passive_only: bool = profile["passive_only"]
        self.stealth: bool = profile["stealth"]
        self.jitter: float = profile.get("jitter", 0.0)
        self.randomize_order: bool = profile.get("randomize_order", False)
        self.profile_modules_blacklist: list[str] = profile.get("modules_blacklist", [])

        # Concurrency cap
        if self.concurrency:
            self.threads = min(self.threads, self.concurrency)

        # Module list
        if self._requested_modules == "all":
            self.modules = list(ALL_MODULES)
        else:
            self.modules = [m.strip() for m in self._requested_modules.split(",") if m.strip()]

        skip = [m.strip() for m in self._skip_modules.split(",") if m.strip()]
        skip += self.profile_modules_blacklist
        self.modules = [m for m in self.modules if m not in skip]

        # Passive by default: intrusive modules are dropped unless --active.
        if not self.active:
            self.skipped_active_modules = [m for m in self.modules if m in ACTIVE_MODULES]
            self.modules = [m for m in self.modules if m not in ACTIVE_MODULES]
        else:
            self.skipped_active_modules = []

        # Wordlists
        if not self.wordlist:
            self.wordlist = self._default_wordlist("subdomains.txt")
        if not self.dir_wordlist:
            self.dir_wordlist = self._default_wordlist("directories.txt")

        # User agent
        self.user_agent: str = self._cli_user_agent or DEFAULT_USER_AGENTS[0]

    def _apply_yaml_profile(self) -> None:
        """Merge optional configs/profiles/<profile>.yaml settings."""
        profile_path = (
            Path(__file__).parent.parent / "configs" / "profiles" / f"{self.profile}.yaml"
        )
        if not profile_path.exists():
            return
        try:
            data = self._read_config_file(profile_path)
        except Exception:
            return

        profile_modules = data.pop("modules", None)
        blacklist = data.pop("modules_blacklist", None)
        self._merge_config(data)

        if self._requested_modules == "all" and profile_modules:
            self.modules = [str(m).strip() for m in profile_modules if str(m).strip()]
        if blacklist:
            blocked = {str(m).strip() for m in blacklist}
            self.modules = [m for m in self.modules if m not in blocked]

    # ── File config ──────────────────────────────────────────────────────────────

    def _apply_file_config(self) -> None:
        cfg_path = Path(self._config_file)

        # Try configured file, then YAML variants for operator profiles.
        for candidate in [cfg_path, cfg_path.with_suffix(".yaml"), cfg_path.with_suffix(".yml")]:
            if candidate.exists():
                try:
                    data = self._read_config_file(candidate)
                    self._merge_config(data)
                    return
                except Exception:
                    pass

    def _read_config_file(self, path: Path) -> dict[str, Any]:
        text = path.read_text(encoding="utf-8")
        suffix = path.suffix.lower()
        if suffix in (".yaml", ".yml") and _YAML_AVAILABLE:
            return yaml.safe_load(text) or {}
        return json.loads(text)

    def _merge_config(self, data: dict[str, Any]) -> None:
        """Merge file config. CLI args always win."""
        string_keys = {
            "shodan_key",
            "nvd_key",
            "proxy",
            "dns_server",
            "user_agent",
            "output_dir",
            "log_dir",
        }
        int_keys = {"threads", "timeout", "retries", "rate_limit"}
        float_keys = {"delay", "jitter"}
        bool_keys = {
            "aggressive",
            "passive_only",
            "stealth",
            "randomize_order",
            "no_external",
            "privacy_mode",
        }

        for k, v in data.items():
            if k.startswith("_"):
                continue
            if k in string_keys and v and not getattr(self, k, None):
                setattr(self, k, str(v))
            elif k in int_keys and v is not None:
                setattr(self, k, int(v))
            elif k in float_keys and v is not None:
                setattr(self, k, float(v))
            elif k in bool_keys and v is not None:
                setattr(self, k, bool(v))

    # ── Environment overrides ────────────────────────────────────────────────────

    def _apply_env_overrides(self) -> None:
        """
        WEBOSINT_SHODAN_KEY, WEBOSINT_NVD_KEY, WEBOSINT_PROXY, etc.
        Environment variables override file config but not CLI args.
        """
        env_map = {
            "SHODAN_KEY": "shodan_key",
            "NVD_KEY": "nvd_key",
            "PROXY": "proxy",
            "DNS_SERVER": "dns_server",
            "THREADS": ("threads", int),
            "TIMEOUT": ("timeout", int),
            "RATE_LIMIT": ("rate_limit", int),
            "DELAY": ("delay", float),
        }
        for env_suffix, attr in env_map.items():
            env_key = _ENV_PREFIX + env_suffix
            val = os.environ.get(env_key)
            if val:
                if isinstance(attr, tuple):
                    name, cast = attr
                    try:
                        setattr(self, name, cast(val))
                    except ValueError:
                        pass
                else:
                    if not getattr(self, attr, None):
                        setattr(self, attr, val)

    # ── Validation ───────────────────────────────────────────────────────────────

    def _validate(self) -> None:
        # Clamp thread / rate limits
        self.threads = max(1, min(self.threads, 50))
        self.rate_limit = max(1, min(self.rate_limit, 500))
        self.timeout = max(1, min(self.timeout, 120))
        self.retries = max(0, min(self.retries, 5))
        self.delay = max(0.0, min(self.delay, 60.0))

        # Validate profile
        if self.profile not in PROFILE_SETTINGS:
            self.profile = "medium"

        # Validate report format
        valid_formats = (
            "json",
            "html",
            "markdown",
            "csv",
            "docx",
            "pdf",
            "all",
            "both",
            "none",
        )
        if self.report_format not in valid_formats:
            self.report_format = "json"

        # Validate privacy settings
        if self.detail not in ("minimal", "standard", "detailed"):
            self.detail = "standard"
        self.retention_days = max(0, min(self.retention_days, 3650))
        self.log_retention_days = max(0, min(self.log_retention_days, 3650))
        self.max_redirects = max(0, min(self.max_redirects, 10))

        # A proxy must be a local/explicit http(s) endpoint
        if self.proxy and not str(self.proxy).lower().startswith(("http://", "https://")):
            raise ValueError("Proxy must be an http:// or https:// URL")

    def _setup_dirs(self) -> None:
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)

    # ── Helpers ──────────────────────────────────────────────────────────────────

    def _default_wordlist(self, name: str) -> str | None:
        base = Path(__file__).parent.parent / "wordlists" / name
        return str(base) if base.exists() else None

    def get_temp_file(self, suffix: str = ".tmp") -> str:
        """
        Return a safe temp file path — cross-platform, no /tmp/ hardcoding.
        Each call returns a unique path.
        """
        fd, path = tempfile.mkstemp(suffix=suffix, prefix="webosint_")
        os.close(fd)
        os.chmod(path, 0o600)
        return path

    def to_dict(self) -> dict[str, Any]:
        """Serializable config with all secrets and local paths removed."""
        from core.redaction import REDACTED

        secret_keys = {"shodan_key", "nvd_key", "proxy"}
        path_keys = {"wordlist", "dir_wordlist", "allowlist_path", "_config_file"}
        out: dict[str, Any] = {}
        for k, v in self.__dict__.items():
            if k.startswith("_") or callable(v):
                continue
            if k in secret_keys:
                out[k] = REDACTED if v else None
            elif k in path_keys and v:
                out[k] = os.path.basename(str(v))
            else:
                out[k] = v
        return out

    def __repr__(self) -> str:
        return (
            f"Config(target={self.target!r}, profile={self.profile!r}, "
            f"threads={self.threads}, modules={len(self.modules)})"
        )
