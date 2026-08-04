"""
WebOSINT Pro - Output & Color Utilities
"""


class ColorOutput:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"

    _enabled = True

    @classmethod
    def disable(cls):
        cls._enabled = False
        for attr in [
            "RESET",
            "BOLD",
            "DIM",
            "RED",
            "GREEN",
            "YELLOW",
            "BLUE",
            "MAGENTA",
            "CYAN",
            "WHITE",
            "BG_RED",
            "BG_GREEN",
            "BG_YELLOW",
        ]:
            setattr(cls, attr, "")


RISK_COLORS = {
    "critical": ColorOutput.RED + ColorOutput.BOLD,
    "high": ColorOutput.RED,
    "medium": ColorOutput.YELLOW,
    "low": ColorOutput.CYAN,
    "info": ColorOutput.DIM,
}


def print_section(name: str):
    C = ColorOutput
    label = name.upper().replace("_", " ")
    print(f"\n{C.BOLD}{C.BLUE}[{label}]{C.RESET}")
    print(f"{C.DIM}{'─' * 50}{C.RESET}")


def print_finding(key: str, value, risk: str = "info"):
    C = ColorOutput
    color = RISK_COLORS.get(risk, C.RESET)
    key_clean = key.replace("_", " ").title()

    if isinstance(value, list):
        if len(value) == 0:
            return
        print(f"  {C.BOLD}{key_clean}:{C.RESET}")
        for item in value[:10]:
            print(f"    {color}• {item}{C.RESET}")
        if len(value) > 10:
            print(f"    {C.DIM}... +{len(value) - 10} more{C.RESET}")

    elif isinstance(value, dict):
        print(f"  {C.BOLD}{key_clean}:{C.RESET}")
        for k, v in list(value.items())[:8]:
            if v:
                print(f"    {C.GREEN}{k}:{C.RESET} {v}")

    else:
        if str(value).strip():
            print(f"  {C.BOLD}{key_clean}:{C.RESET} {color}{value}{C.RESET}")


def print_table(headers: list, rows: list):
    """Simple ASCII table."""
    try:
        from tabulate import tabulate

        print(tabulate(rows, headers=headers, tablefmt="rounded_outline"))
    except ImportError:
        # Fallback
        widths = [
            max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
            for i, h in enumerate(headers)
        ]
        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        print(fmt.format(*headers))
        print("-" * sum(widths))
        for row in rows:
            print(fmt.format(*[str(c) for c in row]))
