"""
WebOSINT Pro - Central Scan Controller
Verbosity-aware orchestration of all modules.

Console output per verbosity level
───────────────────────────────────────────────────────────────────
v=0  Scan header, progress bar, final summary table  (default)
v=1  + module START/DONE banners, risk findings inline
v=2  + every HTTP request URL + status + timing
v=3  + raw response headers, body snippets, internal state
"""

import time
import random
import importlib
import traceback
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.output import ColorOutput as C, print_section, print_finding
from utils.rate_limiter import RateLimiter
from reports.json_report import JSONReport
from reports.html_report import HTMLReport


MODULE_MAP = {
    'dns':        'modules.dns_module',
    'ip':         'modules.ip_module',
    'whois':      'modules.whois_module',
    'subdomains': 'modules.subdomain_module',
    'http':       'modules.http_module',
    'ssl':        'modules.ssl_module',
    'ports':      'modules.port_module',
    'dirs':       'modules.directory_module',
    'webapp':     'modules.webapp_module',
    'javascript': 'modules.javascript_module',
    'api':        'modules.api_module',
    'websocket':  'modules.websocket_module',
    'database':   'modules.database_module',
    'mail':       'modules.mail_module',
    'waf':        'modules.waf_module',
    'ids':        'modules.ids_module',
    'siem':       'modules.siem_module',
    'honeypot':   'modules.honeypot_module',
    'cve':        'modules.cve_module',
    'osint':      'modules.osint_module',
}

RISK_ORDER   = ['critical', 'high', 'medium', 'low', 'info']
RISK_COLORS  = {
    'critical': C.RED + C.BOLD,
    'high':     C.RED,
    'medium':   C.YELLOW,
    'low':      C.CYAN,
    'info':     C.DIM,
}


class ScanController:
    def __init__(self, config, logger):
        self.cfg          = config
        self.logger       = logger
        self.verbose      = config.verbose
        self.rate_limiter = RateLimiter(config.rate_limit)
        self.results = {
            'meta': {
                'target':      config.target,
                'profile':     config.profile,
                'verbose':     config.verbose,
                'start_time':  datetime.now().isoformat(),
                'modules_run': [],
            },
            'findings': {},
            'errors':   {},
            'summary':  {},
        }
        self.start_time      = time.time()
        self._completed      = 0
        self._total_modules  = 0

    # ──────────────────────────────────────────────────────────────────
    # Public entry
    # ──────────────────────────────────────────────────────────────────
    def run(self):
        modules = list(self.cfg.modules)
        if self.cfg.randomize_order:
            random.shuffle(modules)
        self._total_modules = len(modules)

        self._print_scan_header(modules)

        # Sequential first (dns, ip, whois, http, ssl depend on each other)
        sequential_first = ['dns', 'ip', 'whois', 'http', 'ssl']
        seq_mods  = [m for m in sequential_first if m in modules]
        para_mods = [m for m in modules if m not in sequential_first]

        for mod_name in seq_mods:
            self._run_module(mod_name)
            if self.cfg.delay > 0:
                jitter = random.uniform(0, self.cfg.jitter) if self.cfg.stealth else 0
                time.sleep(self.cfg.delay + jitter)

        if para_mods:
            with ThreadPoolExecutor(max_workers=self.cfg.threads) as ex:
                futures = {ex.submit(self._run_module_threaded, m): m for m in para_mods}
                for fut in as_completed(futures):
                    mod_name = futures[fut]
                    try:
                        fut.result()
                    except Exception as e:
                        self.logger.error(f"Thread error [{mod_name}]: {e}")

        # Finalise
        elapsed = time.time() - self.start_time
        self.results['meta']['end_time']        = datetime.now().isoformat()
        self.results['meta']['elapsed_seconds'] = round(elapsed, 2)
        self._build_summary()
        reports = self._generate_reports()

        self._print_final_summary(elapsed, reports)

        return {
            'elapsed':        elapsed,
            'total_findings': self.results['summary'].get('total_findings', 0),
            'reports':        reports,
        }

    # ──────────────────────────────────────────────────────────────────
    # Module execution
    # ──────────────────────────────────────────────────────────────────
    def _run_module_threaded(self, mod_name):
        if self.cfg.delay > 0:
            jitter = random.uniform(0, self.cfg.jitter) if self.cfg.stealth else 0
            time.sleep(self.cfg.delay + jitter)
        self._run_module(mod_name)

    def _run_module(self, mod_name):
        if mod_name not in MODULE_MAP:
            self.logger.warning(f"Unknown module: {mod_name}")
            return

        # v=0: one-line progress indicator
        if self.verbose == 0:
            self._print_progress(mod_name)

        # v>=1: section header
        if self.verbose >= 1:
            print_section(mod_name)

        self.logger.module_start(mod_name)
        t0 = time.perf_counter()

        try:
            mod          = importlib.import_module(MODULE_MAP[mod_name])
            instance     = mod.Module(self.cfg, self.logger, self.rate_limiter)
            findings     = instance.run()
            elapsed_ms   = (time.perf_counter() - t0) * 1000
            finding_count = self._count_findings(findings)

            self.results['findings'][mod_name] = findings
            self.results['meta']['modules_run'].append(mod_name)
            self._completed += 1

            self.logger.module_done(mod_name, finding_count, elapsed_ms)

            # v=0: tick progress
            if self.verbose == 0:
                self._print_progress(mod_name, done=True, count=finding_count)

            # v>=1: print findings
            if self.verbose >= 1:
                self._print_findings(mod_name, findings)

            # v>=2: print timing line
            if self.verbose >= 2:
                print(f"  {C.DIM}↳ elapsed: {elapsed_ms:.0f}ms  findings: {finding_count}{C.RESET}",
                      file=sys.stderr)

            # v=3: dump raw findings dict
            if self.verbose >= 3:
                self.logger.trace(f"[{mod_name}] raw findings: {str(findings)[:800]}")

        except ImportError as e:
            self._handle_error(mod_name, f"Import failed: {e}")
        except Exception as e:
            self._handle_error(mod_name, f"{type(e).__name__}: {e}",
                               tb=traceback.format_exc())

    def _handle_error(self, mod_name, msg, tb=None):
        self.results['errors'][mod_name] = msg
        self._completed += 1
        print(f"  {C.RED}[!] [{mod_name}] {msg}{C.RESET}")
        if tb and self.verbose >= 2:
            print(f"{C.DIM}{tb}{C.RESET}", file=sys.stderr)
        self.logger.error(f"[{mod_name}] {msg}")
        if tb:
            self.logger.debug(tb)

    # ──────────────────────────────────────────────────────────────────
    # Print helpers
    # ──────────────────────────────────────────────────────────────────
    def _print_scan_header(self, modules):
        verbose_label = {0: 'quiet', 1: 'info (-v)', 2: 'debug (-vv)', 3: 'trace (-vvv)'}
        W = 62
        print(f"\n{C.BOLD}{'═'*W}{C.RESET}")
        print(f"  {C.BOLD}Target   {C.RESET} {C.CYAN}{self.cfg.target}{C.RESET}")
        print(f"  {C.BOLD}Profile  {C.RESET} {C.YELLOW}{self.cfg.profile}{C.RESET}")
        vtext = verbose_label.get(self.verbose, 'trace')
        print(f"  {C.BOLD}Verbosity{C.RESET} {vtext}")
        print(f"  {C.BOLD}Threads  {C.RESET} {self.cfg.threads}  "
              f"{C.DIM}rate-limit: {self.cfg.rate_limit}/min{C.RESET}")
        print(f"  {C.BOLD}Modules  {C.RESET} {len(modules)}")
        # wrap module list at 55 chars
        line, parts = '  ' + C.DIM, []
        for m in modules:
            parts.append(m)
        chunk_size = 8
        for i in range(0, len(parts), chunk_size):
            print(f"  {C.DIM}  {', '.join(parts[i:i+chunk_size])}{C.RESET}")
        if self.cfg.stealth:
            print(f"\n  {C.YELLOW}⚠  Stealth mode — slow + randomised order{C.RESET}")
        print(f"{C.BOLD}{'═'*W}{C.RESET}\n")

        # v=0: progress table header
        if self.verbose == 0:
            print(f"  {C.BOLD}{'MODULE':<16} {'FINDINGS':>8}   {'PROGRESS'}{C.RESET}")
            print(f"  {C.DIM}{'─'*56}{C.RESET}")

    def _print_progress(self, mod_name: str, done: bool = False, count: int = 0):
        """
        Single-line progress row at v=0.
        FIX: ANSI codes inflate str width → use plain chars for column math,
             apply colour only in the final print, keep bar width fixed at 20.
        """
        if done:
            pct  = int(self._completed / self._total_modules * 100)
            filled = pct // 5                     # 0-20
            bar  = '█' * filled + '░' * (20 - filled)   # always 20 chars wide

            # risk indicator from last module's findings
            risk_sym = ' '
            findings = self.results['findings'].get(mod_name, {})
            if isinstance(findings, dict):
                levels = [str(v) for k, v in findings.items() if str(k).startswith('_risk')]
                if 'critical' in levels:  risk_sym = f'{C.RED}●{C.RESET}'
                elif 'high'   in levels:  risk_sym = f'{C.YELLOW}●{C.RESET}'
                elif 'medium' in levels:  risk_sym = f'{C.YELLOW}◐{C.RESET}'
                elif levels:              risk_sym = f'{C.CYAN}○{C.RESET}'

            cnt_str  = f"{C.GREEN}{count}{C.RESET}" if count else f"{C.DIM}0{C.RESET}"
            pct_str  = f"{pct:>3}%"
            # fixed-width plain text columns; colour only on status + bar
            print(
                f"  {mod_name:<16} {cnt_str:>8}   "
                f"{C.DIM}[{C.RESET}{C.CYAN}{bar}{C.RESET}{C.DIM}]{C.RESET} "
                f"{pct_str} {risk_sym}"
            )
        else:
            # spinning "scanning" indicator — overwrite with \r, clear to EOL
            print(f"  {C.YELLOW}{mod_name:<16}{C.RESET} {C.DIM}scanning…{C.RESET}\033[K",
                  end='\r', flush=True)

    def _print_findings(self, mod_name: str, findings):
        """Print findings at verbosity ≥ 1."""
        if not findings:
            print(f"  {C.DIM}no findings{C.RESET}")
            return

        if isinstance(findings, dict):
            # Show risk-tagged items first
            risk_items = {k: v for k, v in findings.items() if k.startswith('_risk')}
            normal     = {k: v for k, v in findings.items()
                         if not k.startswith('_') and v not in (None, '', [], {})}

            for key, risk_level in risk_items.items():
                label = key[6:].replace('_', ' ').title()
                rc    = RISK_COLORS.get(risk_level, C.RESET)
                badge = f"[{risk_level.upper()}]"
                print(f"  {rc}{badge}{C.RESET} {label}")

            for key, val in list(normal.items())[:30 if self.verbose >= 2 else 15]:
                print_finding(key, val)

            hidden = max(0, len(normal) - (30 if self.verbose >= 2 else 15))
            if hidden:
                print(f"  {C.DIM}  … {hidden} more fields (use -vv to show all){C.RESET}")

        elif isinstance(findings, list):
            cap = 50 if self.verbose >= 2 else 10
            for item in findings[:cap]:
                print(f"  {C.GREEN}→{C.RESET} {item}")
            if len(findings) > cap:
                print(f"  {C.DIM}  … {len(findings)-cap} more (use -vv){C.RESET}")

    def _print_final_summary(self, elapsed: float, reports: list):
        summary   = self.results.get('summary', {})
        risks     = summary.get('risk_counts', {})
        total     = summary.get('total_findings', 0)
        n_modules = summary.get('modules_run', 0)
        n_errors  = summary.get('errors', 0)
        W = 62

        print(f"\n{C.BOLD}{'═'*W}{C.RESET}")
        print(f"  {C.BOLD}{C.GREEN}✔ SCAN COMPLETE{C.RESET}")
        print(f"  {C.DIM}{'─'*58}{C.RESET}")
        print(f"  {C.BOLD}Target   {C.RESET} {C.CYAN}{self.cfg.target}{C.RESET}")
        print(f"  {C.BOLD}Duration {C.RESET} {elapsed:.1f}s")
        err_str = f"  {C.RED}({n_errors} error{'s' if n_errors!=1 else ''}){C.RESET}" if n_errors else ''
        print(f"  {C.BOLD}Modules  {C.RESET} {C.GREEN}{n_modules}{C.RESET}/{self._total_modules}{err_str}")
        print(f"  {C.BOLD}Findings {C.RESET} {C.GREEN}{total}{C.RESET}")
        print()

        # Risk breakdown — only print non-zero rows at v=0, all at v>=1
        max_count = max((risks.get(l, 0) for l in RISK_ORDER), default=1) or 1
        BAR_W = 24
        ICONS = {'critical':'🔴','high':'🟠','medium':'🟡','low':'🟢','info':'⚪'}
        print(f"  {C.BOLD}{'SEVERITY':<10} {'COUNT':>5}   {'DISTRIBUTION'}{C.RESET}")
        print(f"  {C.DIM}{'─'*50}{C.RESET}")
        any_printed = False
        for level in RISK_ORDER:
            count = risks.get(level, 0)
            if count == 0 and self.verbose == 0:
                continue
            any_printed = True
            rc      = RISK_COLORS.get(level, C.RESET)
            filled  = int(count / max_count * BAR_W)
            bar     = '█' * filled + '░' * (BAR_W - filled)
            icon    = ICONS.get(level, ' ')
            print(f"  {icon} {rc}{level.upper():<8}{C.RESET}  {count:>5}   {rc}{bar}{C.RESET}")
        if not any_printed:
            print(f"  {C.DIM}  No risk findings recorded{C.RESET}")

        # Per-module finding counts (always shown)
        print(f"\n  {C.BOLD}Module Breakdown:{C.RESET}")
        print(f"  {C.DIM}{'─'*50}{C.RESET}")
        for mod in self.results['meta'].get('modules_run', []):
            data  = self.results['findings'].get(mod, {})
            cnt   = self._count_findings(data)
            # detect highest risk in this module
            risk_label = ''
            if isinstance(data, dict):
                lvls = [str(v) for k, v in data.items() if str(k).startswith('_risk')]
                for rl in RISK_ORDER:
                    if rl in lvls:
                        rc = RISK_COLORS.get(rl, C.RESET)
                        risk_label = f" {rc}[{rl}]{C.RESET}"
                        break
            cnt_c = f"{C.GREEN}{cnt}{C.RESET}" if cnt else f"{C.DIM}0{C.RESET}"
            print(f"  {C.DIM}·{C.RESET} {mod:<16} {cnt_c:>3} findings{risk_label}")

        if self.errors:
            print(f"\n  {C.RED}Errors:{C.RESET}")
            for mod, err in self.errors.items():
                print(f"  {C.RED}✘{C.RESET} {mod}: {C.DIM}{err[:80]}{C.RESET}")

        print(f"\n  {C.BOLD}Reports:{C.RESET}")
        for rp in reports:
            ext   = rp.rsplit('.', 1)[-1].upper()
            label = f"{C.CYAN}[{ext}]{C.RESET}"
            print(f"    {label} {C.DIM}{rp}{C.RESET}")
        print(f"{C.BOLD}{'═'*W}{C.RESET}\n")

    # ──────────────────────────────────────────────────────────────────
    # Aggregation
    # ──────────────────────────────────────────────────────────────────
    def _count_findings(self, data) -> int:
        if isinstance(data, dict):
            return sum(1 for k, v in data.items()
                       if not k.startswith('_') and v not in (None, '', [], {}))
        if isinstance(data, list):
            return len(data)
        return 1 if data else 0

    def _build_summary(self):
        total = 0
        risks = {k: 0 for k in RISK_ORDER}

        for mod, data in self.results['findings'].items():
            if isinstance(data, dict):
                for k, v in data.items():
                    if k.startswith('_risk') and isinstance(v, str):
                        lvl = v.lower()
                        if lvl in risks:
                            risks[lvl] += 1
                    if not k.startswith('_') and v not in (None, '', [], {}):
                        total += 1
            elif isinstance(data, list):
                total += len(data)

        self.results['summary'] = {
            'target':         self.cfg.target,
            'profile':        self.cfg.profile,
            'verbose_level':  self.verbose,
            'modules_run':    len(self.results['meta']['modules_run']),
            'total_findings': total,
            'risk_counts':    risks,
            'errors':         len(self.results['errors']),
        }

    def _generate_reports(self) -> list:
        import os
        ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
        name = (self.cfg.report_name
                or f"webosint_{self.cfg.target.replace('.','_')}_{ts}")
        os.makedirs(self.cfg.output_dir, exist_ok=True)
        paths = []

        if self.cfg.report_format in ('json', 'both'):
            jp = os.path.join(self.cfg.output_dir, f"{name}.json")
            JSONReport(self.results).save(jp)
            paths.append(jp)

        if self.cfg.report_format in ('html', 'both'):
            hp = os.path.join(self.cfg.output_dir, f"{name}.html")
            HTMLReport(self.results).save(hp)
            paths.append(hp)

        self.results['reports'] = paths
        return paths
