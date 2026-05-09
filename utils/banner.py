"""
WebOSINT Pro - Banner & Warning Display
"""

import sys
from utils.output import ColorOutput as C


BANNER = r"""
 __        __   _      ___  ____  ___ _   _ _____   ____
 \ \      / /__| |__  / _ \/ ___|_ _| \ | |_   _| |  _ \ _ __ ___
  \ \ /\ / / _ \ '_ \| | | \___ \| ||  \| | | |   | |_) | '__/ _ \
   \ V  V /  __/ |_) | |_| |___) | || |\  | | |   |  __/| | | (_) |
    \_/\_/ \___|_.__/ \___/|____/___|_| \_| |_|   |_|   |_|  \___/

     Web OSINT & Reconnaissance Framework  |  v1.0.0
     For Authorized Security Testing Only
"""

WARNING = """
╔══════════════════════════════════════════════════════════════╗
║                    ⚠  LEGAL WARNING ⚠                       ║
╠══════════════════════════════════════════════════════════════╣
║  This tool is intended for AUTHORIZED security testing ONLY. ║
║  Unauthorized scanning may violate laws including:           ║
║   • Computer Fraud and Abuse Act (CFAA)                     ║
║   • Computer Misuse Act (UK)                                ║
║   • EU Directive on Attacks Against Information Systems     ║
║                                                              ║
║  Only scan systems you OWN or have EXPLICIT PERMISSION to   ║
║  test. The authors assume NO responsibility for misuse.      ║
╚══════════════════════════════════════════════════════════════╝
"""


def print_banner():
    print(f"{C.CYAN}{BANNER}{C.RESET}")
    print(f"{C.DIM}  github.com/yourorg/webosint-pro{C.RESET}\n")


def print_warning(target: str):
    print(f"{C.YELLOW}{WARNING}{C.RESET}")
    print(f"{C.BOLD}  Target: {C.CYAN}{target}{C.RESET}")
    print(f"\n{C.BOLD}  Do you have EXPLICIT AUTHORIZATION to scan {C.CYAN}{target}{C.RESET}{C.BOLD}? [y/N]{C.RESET} ", end='')

    try:
        ans = input().strip().lower()
    except (KeyboardInterrupt, EOFError):
        ans = 'n'

    if ans not in ('y', 'yes'):
        print(f"\n{C.RED}[!] Authorization not confirmed. Exiting.{C.RESET}\n")
        sys.exit(1)

    print()
