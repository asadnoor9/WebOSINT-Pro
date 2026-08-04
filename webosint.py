#!/usr/bin/env python3
"""
WebOSINT Pro - Passive-first Web OSINT & Reconnaissance Framework

For AUTHORIZED security testing only.

Execution order (the safety gate always comes first):
    parse args -> build config -> safety gate -> logger -> scan -> report -> cleanup

No network action of any kind happens before SafetyController.validate() passes.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading

# Force UTF-8 safe console output regardless of the host locale.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.cli import MODULE_HELP, parse_args
from core.config import Config
from core.logger import setup_logger
from core.redaction import DetailLevel, Redactor
from core.retention import RetentionPolicy
from core.safety import SafetyController, SafetyPolicy, normalize_host
from utils.output import ColorOutput as C

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_AUTHORIZED = 3
EXIT_ERROR = 1
EXIT_INTERRUPTED = 130


def list_modules() -> None:
    from core.config import ACTIVE_MODULES

    print(
        f"\n{C.BOLD}Available modules{C.RESET}  "
        f"({C.GREEN}passive{C.RESET} by default, {C.YELLOW}active{C.RESET} needs --active)\n"
    )
    for name, desc in MODULE_HELP.items():
        tag = (
            f"{C.YELLOW}[active]{C.RESET}"
            if name in ACTIVE_MODULES
            else f"{C.GREEN}[passive]{C.RESET}"
        )
        print(f"  {name:<12} {tag:<20} {desc}")
    print()


def build_policy(cfg: Config) -> SafetyPolicy:
    allowlist: tuple[str, ...] = ()
    if cfg.allowlist_path:
        try:
            data = json.loads(open(cfg.allowlist_path, encoding="utf-8").read())
            entries = data.get("targets", []) if isinstance(data, dict) else data
            allowlist = tuple(str(e).strip().lower() for e in entries if str(e).strip())
        except (OSError, ValueError):
            print(f"{C.RED}[!] Could not read the allowlist file.{C.RESET}")
            raise SystemExit(EXIT_USAGE) from None

    return SafetyPolicy(
        authorized=cfg.authorized,
        confirmed=False,
        active=cfg.active,
        allow_private=cfg.allow_private,
        insecure_tls=cfg.insecure_tls,
        max_redirects=cfg.max_redirects,
        allowlist=allowlist,
        telemetry=False,
    )


def authorization_gate(cfg: Config, policy: SafetyPolicy) -> SafetyController | None:
    """Run the mandatory authorization + target validation gate."""
    controller = SafetyController(policy)

    if not cfg.authorized:
        print(
            f"\n{C.RED}[!] Authorization required.{C.RESET}\n"
            f"    Re-run with {C.BOLD}--authorized{C.RESET} and "
            f"{C.BOLD}--confirm-target {cfg.target}{C.RESET} to confirm that you have\n"
            f"    explicit written permission to test this target.\n"
        )
        return None

    # Target confirmation: non-interactive flag, or an interactive typed prompt.
    if cfg.confirm_target:
        if normalize_host(cfg.confirm_target) != normalize_host(cfg.target):
            print(f"\n{C.RED}[!] --confirm-target does not match --target. Aborting.{C.RESET}\n")
            return None
        policy.confirmed = True
    elif sys.stdin.isatty():
        policy.confirmed = controller.confirm_interactive(cfg.target, active=cfg.active)
    else:
        print(
            f"\n{C.RED}[!] Target confirmation required in non-interactive runs.{C.RESET}\n"
            f"    Add {C.BOLD}--confirm-target {cfg.target}{C.RESET}\n"
        )
        return None

    if not policy.confirmed:
        return None

    result = controller.validate(cfg.target)
    for warning in result.warnings:
        print(f"  {C.YELLOW}[warn]{C.RESET} {warning}")
    if not result.allowed:
        for error in result.errors:
            print(f"  {C.RED}[!]{C.RESET} {error}")
        print()
        return None

    if cfg.active:
        print(
            f"\n{C.RED}{C.BOLD}  ACTIVE MODE ENABLED{C.RESET} — intrusive probes will be sent "
            f"to {C.CYAN}{cfg.target}{C.RESET}.\n"
            f"  {C.DIM}Only proceed with written authorization covering active testing.{C.RESET}"
        )
    if cfg.insecure_tls:
        print(
            f"\n{C.YELLOW}{C.BOLD}  TLS VERIFICATION DISABLED{C.RESET} — every finding from this "
            f"run is labelled {C.BOLD}UNTRUSTED{C.RESET}."
        )

    return controller


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.no_color or args.json_stdout:
        C.disable()

    if args.list_modules:
        list_modules()
        return EXIT_OK

    if not args.target:
        print(f"{C.RED}[!] A target is required. Use -t example.com or --list-modules.{C.RESET}")
        return EXIT_USAGE

    try:
        cfg = Config(args)
    except ValueError as exc:
        print(f"{C.RED}[!] Invalid configuration: {exc}{C.RESET}")
        return EXIT_USAGE

    # ── Safety gate (must pass before anything touches the network) ────────────
    policy = build_policy(cfg)
    controller = authorization_gate(cfg, policy)
    if controller is None:
        return EXIT_NOT_AUTHORIZED

    cfg.safety = controller
    cfg.redactor = Redactor(
        level=DetailLevel.parse(cfg.detail),
        keep_raw=cfg.keep_raw,
        extra_secrets=tuple(s for s in (cfg.shodan_key, cfg.nvd_key) if s),
    )
    cfg.retention = RetentionPolicy(
        reports_days=cfg.retention_days,
        logs_days=cfg.log_retention_days,
        enabled=cfg.cleanup,
    )

    logger = setup_logger(
        verbose=cfg.verbose,
        quiet=cfg.quiet,
        log_dir=cfg.log_dir,
        session_id=cfg.session_id,
        redactor=cfg.redactor,
        write_files=cfg.write_log_file,
    )
    logger.info(f"starting | target={cfg.target} | mode={'active' if cfg.active else 'passive'}")

    cancel_event = threading.Event()

    def _handle_interrupt(signum, frame):
        cancel_event.set()

    signal.signal(signal.SIGINT, _handle_interrupt)

    from core.controller import ScanController

    exit_code = EXIT_OK
    try:
        scan = ScanController(cfg, logger, safety=controller, cancel_event=cancel_event)
        results = scan.run()

        if cfg.json_stdout:
            json.dump(results, sys.stdout, indent=2, sort_keys=True, ensure_ascii=False)
            sys.stdout.write("\n")

        if cancel_event.is_set():
            exit_code = EXIT_INTERRUPTED
    except KeyboardInterrupt:
        cancel_event.set()
        print(f"\n{C.YELLOW}[!] Cancelled by user.{C.RESET}")
        exit_code = EXIT_INTERRUPTED
    except Exception as exc:
        # Never surface a stack trace, path or secret to the console.
        logger.error(cfg.redactor.exception(exc))
        print(f"{C.RED}[!] Scan failed: {cfg.redactor.exception(exc)}{C.RESET}")
        exit_code = EXIT_ERROR
    finally:
        if cfg.cleanup:
            removed = cfg.retention.run(cfg.output_dir, cfg.log_dir)
            if any(removed.values()):
                logger.debug(f"retention cleanup: {removed}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
