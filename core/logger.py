"""
WebOSINT Pro - Verbose Logger
Verbosity levels:
  0 (default) : WARN  - errors + scan summary only
  1 (-v)      : INFO  - module start/stop, key findings, counts
  2 (-vv)     : DEBUG - every request URL, response code, timing
  3 (-vvv)    : TRACE - raw headers, body snippets, internal state
"""

import logging
import os
import sys
from datetime import datetime

# Custom TRACE level (below DEBUG=10)
TRACE = 5
logging.addLevelName(TRACE, 'TRACE')


def _c(code):
    """Return ANSI escape or empty string if stdout is not a tty."""
    return code if sys.stderr.isatty() else ''


RESET   = _c('\033[0m')
BOLD    = _c('\033[1m')
DIM     = _c('\033[2m')
RED     = _c('\033[91m')
GREEN   = _c('\033[92m')
YELLOW  = _c('\033[93m')
CYAN    = _c('\033[96m')
MAGENTA = _c('\033[95m')


class _ColorFormatter(logging.Formatter):
    STYLES = {
        'TRACE':    DIM,
        'DEBUG':    DIM,
        'INFO':     CYAN,
        'WARNING':  YELLOW,
        'ERROR':    RED,
        'CRITICAL': RED + BOLD,
    }
    ICONS = {
        'TRACE':    '·',
        'DEBUG':    '·',
        'INFO':     '›',
        'WARNING':  '!',
        'ERROR':    '✗',
        'CRITICAL': '✗',
    }

    def format(self, record):
        lvl   = record.levelname
        color = self.STYLES.get(lvl, RESET)
        icon  = self.ICONS.get(lvl, '›')
        ts    = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        msg   = record.getMessage()
        # Strip redundant [module] bracket duplicates when not needed
        return f"{DIM}{ts}{RESET} {color}{icon}{RESET} {msg}"


class WebOSINTLogger(logging.Logger):
    """Drop-in logger with extra helpers used throughout scan modules."""

    # ── Custom level helpers ─────────────────────────────────────────────
    def trace(self, msg, *args, **kwargs):
        if self.isEnabledFor(TRACE):
            self._log(TRACE, msg, args, **kwargs)

    # ── Scan-aware helpers ───────────────────────────────────────────────
    def request(self, method: str, url: str, status: int = None,
                elapsed_ms: float = None):
        """v=2 (-vv): log every HTTP request with status + timing."""
        if not self.isEnabledFor(logging.DEBUG):
            return
        s = ''
        if status is not None:
            sc = GREEN if status < 400 else (YELLOW if status < 500 else RED)
            s = f" {sc}{status}{RESET}"
        t = f" {DIM}{elapsed_ms:.0f}ms{RESET}" if elapsed_ms is not None else ''
        self.debug(f"{DIM}{method}{RESET} {url}{s}{t}")

    def finding(self, module: str, key: str, value, risk: str = 'info'):
        """v=1 (-v): surface a notable finding inline."""
        if not self.isEnabledFor(logging.INFO):
            return
        RCOLORS = {
            'critical': RED + BOLD,
            'high':     RED,
            'medium':   YELLOW,
            'low':      CYAN,
            'info':     DIM,
        }
        rc   = RCOLORS.get(risk.lower(), RESET)
        vstr = str(value)[:120]
        self.info(f"[{BOLD}{module}{RESET}] {rc}{key}{RESET}: {vstr}")

    def module_start(self, name: str):
        """v=1: announce module begin."""
        if self.isEnabledFor(logging.INFO):
            self.info(f"{DIM}{'─'*4}{RESET} {BOLD}{name.upper()}{RESET} ▶ started")

    def module_done(self, name: str, count: int, elapsed_ms: float):
        """v=1: announce module end with stats."""
        if self.isEnabledFor(logging.INFO):
            self.info(
                f"{DIM}{'─'*4}{RESET} {BOLD}{name.upper()}{RESET} ■ done "
                f"| {GREEN}{count}{RESET} findings "
                f"| {DIM}{elapsed_ms:.0f}ms{RESET}"
            )

    def raw(self, label: str, data):
        """v=3 (-vvv): dump raw data (headers, body snippets)."""
        if self.isEnabledFor(TRACE):
            snippet = str(data)[:600].replace('\n', '\\n')
            self.trace(f"  {DIM}[RAW {label}]{RESET} {snippet}")

    def req_headers(self, headers: dict):
        """v=3: dump request/response headers."""
        if self.isEnabledFor(TRACE):
            for k, v in list(headers.items())[:20]:
                self.trace(f"  {DIM}  {k}: {v}{RESET}")


logging.setLoggerClass(WebOSINTLogger)


# ── Verbosity legend (printed when -v or higher) ─────────────────────────
_LEVEL_LABEL = {
    0: f"{DIM}WARN{RESET}  – errors & final summary only",
    1: f"{CYAN}INFO{RESET}  – module events, key findings",
    2: f"{CYAN}DEBUG{RESET} – every HTTP request + timing",
    3: f"{MAGENTA}TRACE{RESET} – raw headers, body, internal state",
}


def setup_logger(verbose: int, log_dir: str = 'logs') -> 'WebOSINTLogger':
    """
    Build and return the singleton WebOSINT logger.

    Console levels:
      0  → WARNING   (quiet, only errors/summary)
      1  → INFO      (-v)
      2  → DEBUG     (-vv, requests)
      3  → TRACE     (-vvv, raw data)

    File always captures DEBUG (or TRACE at -vvv).
    """
    os.makedirs(log_dir, exist_ok=True)
    ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, f'webosint_{ts}.log')

    console_level = {0: logging.WARNING,
                     1: logging.INFO,
                     2: logging.DEBUG,
                     3: TRACE}.get(verbose, TRACE)
    file_level = TRACE if verbose >= 3 else logging.DEBUG

    logger = logging.getLogger('webosint')
    logger.setLevel(TRACE)
    logger.handlers.clear()
    logger.propagate = False

    # File handler ──────────────────────────────────────────────────────
    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setLevel(file_level)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s  [%(levelname)-8s]  %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(fh)

    # Console handler ───────────────────────────────────────────────────
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(console_level)
    ch.setFormatter(_ColorFormatter())
    logger.addHandler(ch)

    # Print legend to stderr so it doesn't pollute stdout/reports
    if verbose >= 1:
        print(
            f"\n{DIM}[verbosity]{RESET} level={verbose} "
            f"→ {_LEVEL_LABEL[min(verbose, 3)]}\n"
            f"{DIM}[log file ]{RESET} {log_file}\n",
            file=sys.stderr
        )

    return logger  # type: WebOSINTLogger
