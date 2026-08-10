#!/usr/bin/env python3
"""Mirror a release tree onto an existing checkout, applying deletions.

Unzipping a release over a checkout overwrites changed files but never removes
files deleted upstream. Stale modules and stale tests survive, get imported,
and fail in ways that look like new bugs. This mirrors the release instead, so
removals are applied too, while protecting local state that must never be
touched: the virtualenv, generated output, local config and git metadata.

Standard library only, deliberately: the recovery path must not depend on
anything that might be missing on the machine being recovered (rsync is not
installed by default everywhere).

Invoked by scripts/sync-upgrade.sh; usable directly:

    python3 scripts/sync_upgrade.py <source-tree> <checkout> [--dry-run]
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

# Top-level entries that are local state, never shipped in a release, and never
# removed or overwritten by an upgrade.
PROTECTED_ROOT = frozenset(
    {
        "venv",
        ".venv",
        "env",
        ".env",
        "output",
        "config.json",
        ".git",
        ".runtime",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
    }
)

# Names protected at any depth.
PROTECTED_ANY = frozenset({"__pycache__"})


def is_protected(rel: Path) -> bool:
    """True when a path relative to the checkout root is local state."""
    parts = rel.parts
    if not parts:
        return True
    if parts[0] in PROTECTED_ROOT:
        return True
    if any(part in PROTECTED_ANY for part in parts):
        return True
    # Editable-install metadata: webosint_pro.egg-info, *.dist-info, etc.
    if parts[0].endswith((".egg-info", ".dist-info", ".egg-link")):
        return True
    return parts[-1].endswith(".pyc")


def walk(root: Path) -> tuple[set[Path], set[Path]]:
    """Return (files, dirs) as paths relative to root, skipping protected ones."""
    files: set[Path] = set()
    dirs: set[Path] = set()
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if is_protected(rel):
            continue
        if path.is_symlink() or path.is_file():
            files.add(rel)
        elif path.is_dir():
            dirs.add(rel)
    return files, dirs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="extracted release tree")
    parser.add_argument("checkout", type=Path, help="existing checkout to update")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report the changes that would be made and exit",
    )
    args = parser.parse_args(argv)

    src = args.source.resolve()
    dst = args.checkout.resolve()

    for label, root in (("source", src), ("checkout", dst)):
        if not (root / "pyproject.toml").is_file():
            print(f"{label} is not a WebOSINT Pro tree: {root}", file=sys.stderr)
            return 1
    if src == dst:
        print("source and checkout are the same directory", file=sys.stderr)
        return 1

    src_files, src_dirs = walk(src)
    dst_files, dst_dirs = walk(dst)

    added = sorted(src_files - dst_files)
    removed = sorted(dst_files - src_files)
    changed = sorted(
        rel for rel in src_files & dst_files if not filecmp.cmp(src / rel, dst / rel, shallow=False)
    )

    for rel in removed:
        print(f"  delete  {rel}")
    for rel in added:
        print(f"  add     {rel}")
    for rel in changed:
        print(f"  update  {rel}")
    if not (added or removed or changed):
        print("  already up to date")

    print(
        f"\n{len(added)} added, {len(changed)} updated, {len(removed)} removed"
        f"{' (dry run, nothing written)' if args.dry_run else ''}"
    )
    if args.dry_run:
        return 0

    # Deletions first so a file replaced by a directory of the same name works.
    for rel in removed:
        (dst / rel).unlink(missing_ok=True)

    for rel in sorted(src_dirs):
        (dst / rel).mkdir(parents=True, exist_ok=True)

    for rel in added + changed:
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink() or target.exists():
            target.unlink()
        # copy2 preserves the executable bit, which install scripts need.
        shutil.copy2(src / rel, target, follow_symlinks=False)

    # Prune directories the release no longer has, deepest first. Only empty
    # ones are removed, so a directory still holding protected local state and
    # any unexpected local file both survive.
    for rel in sorted(dst_dirs - src_dirs, key=lambda p: len(p.parts), reverse=True):
        path = dst / rel
        try:
            next(path.iterdir())
        except StopIteration:
            path.rmdir()
            print(f"  rmdir   {rel}")
        except FileNotFoundError:
            continue

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
