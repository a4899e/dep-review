#!/usr/bin/env python3
"""Register a git repo's lockfiles in repos.json for backfill-repo-deps.py.

Lists the lockfiles tracked at *ref* (never the working tree) and records them,
so later inventory runs read an explicit list. A lock that stopped being found
would otherwise shrink the coverage denominator without anyone noticing.

Root lockfiles are registered by default. Nested ones (a deploy CLI pinned in
infra/cdk/, a workspace package) are listed and registered only with --nested,
because vendored test fixtures look identical to real nested locks.

Usage: register-repo.py PATH [--name NAME] [--ref origin/HEAD] [--nested]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

LOCK_ECOSYSTEM = {
    "uv.lock": "pypi",
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "npm",
}
SKIP_PARTS = {"node_modules", ".venv", "venv", "cdk.out", "vendor", "fixtures", "testdata"}


def config_path() -> Path:
    if os.environ.get("DEP_REVIEW_CONFIG"):
        return Path(os.environ["DEP_REVIEW_CONFIG"])
    xdg = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    home = Path(os.environ.get("DEP_REVIEW_HOME") or Path(xdg) / "dep-review")
    return home / "repos.json"


def tracked_locks(repo: Path, ref: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", ref],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return sorted(
        p
        for p in out
        if Path(p).name in LOCK_ECOSYSTEM and not SKIP_PARTS & set(Path(p).parts)
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", type=Path)
    ap.add_argument("--name", help="Repo name in the DB (default: directory name)")
    ap.add_argument("--ref", default="origin/HEAD")
    ap.add_argument("--nested", action="store_true", help="Also register nested lockfiles")
    args = ap.parse_args()

    repo = args.path.expanduser().resolve()
    name = args.name or repo.name
    try:
        locks = tracked_locks(repo, args.ref)
    except subprocess.CalledProcessError as e:
        print(f"cannot list {args.ref} in {repo}: {e.stderr.strip()}", file=sys.stderr)
        return 2

    chosen = [p for p in locks if args.nested or "/" not in p]
    for p in locks:
        if p not in chosen:
            print(f"  nested, not registered (use --nested): {p}")
    if not chosen:
        print(f"no supported lockfile tracked at {args.ref} in {repo}", file=sys.stderr)
        return 1

    cfg_file = config_path()
    cfg = json.loads(cfg_file.read_text()) if cfg_file.is_file() else {"repos": []}
    cfg["repos"] = [r for r in cfg["repos"] if r["name"] != name]
    cfg["repos"].append(
        {
            "name": name,
            "path": str(repo),
            "lockfiles": [{"ecosystem": LOCK_ECOSYSTEM[Path(p).name], "path": p} for p in chosen],
        }
    )
    cfg_file.parent.mkdir(parents=True, exist_ok=True)
    cfg_file.write_text(json.dumps(cfg, indent=2) + "\n")
    for p in chosen:
        print(f"  registered {name}: {p}")
    print(f"wrote {cfg_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
