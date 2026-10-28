#!/usr/bin/env python3
"""Resolve the ``--hash`` values in a pip lock to real artifact identities.

A ``--require-hashes`` requirements file states SHA-256 hashes and nothing
else: no filename, and no way to tell a wheel hash from an sdist hash.
``repo_dep_artifacts`` requires both, and ``artifact_kind`` carries a CHECK
constraint, so the inventory cannot be populated from the lock alone.

Rather than invent those two fields -- in a database whose only purpose is
audit evidence -- this fetches them from the registry that published the
files, once, and checks the result in. The manifest is therefore generated
data, reviewable in a diff, and regenerable by re-running this script.

Only ``filename`` and ``packagetype`` are taken from PyPI. The hash itself
always comes from the lock, never from the registry: the point of the lock is
that it, not the registry, decides which bytes are admitted.

Usage:
    generate-pip-lock-manifest.py \\
        ~/code/api/tools/requirements.txt \\
        --source api/tools/requirements.txt \\
        -o ~/.local/share/dep-review/manifests/api-tools.json

Then register it in repos.json as that lockfile's "manifest".
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import urllib.request
from pathlib import Path


# PyPI's packagetype -> repo_dep_artifacts.artifact_kind. Anything else is an
# error rather than a guess: a kind this script has not seen before must be
# looked at, not silently filed under "wheel".
KINDS = {"sdist": "sdist", "bdist_wheel": "wheel"}


def pep503(name: str) -> str:
    """Normalise a distribution name per PEP 503.

    :param name: Distribution name as written in the lock.
    :returns: Runs of ``-``, ``_`` and ``.`` collapsed to one hyphen, lowercased.
    :rtype: str
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock(path: Path) -> dict[tuple[str, str], list[str]]:
    """Return {(package, version): [hash, ...]} for a pinned requirements file.

    :param path: Requirements file written with ``--generate-hashes``.
    :returns: Hashes grouped by the pin they belong to, in file order.
    :rtype: dict[tuple[str, str], list[str]]
    """
    # The same fail-closed parser the inventory uses, so a line one of them
    # cannot represent is rejected by both rather than dropped by either.
    spec = importlib.util.spec_from_file_location(
        "backfill", Path(__file__).resolve().parent / "backfill-repo-deps.py"
    )
    bf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bf)
    return {
        (pep503(name), version): hashes
        for (name, version), (hashes, _) in bf.requirements_entries(
            path.read_text(encoding="utf-8")
        ).items()
    }


def registry_files(package: str, version: str) -> dict[str, tuple[str, str]]:
    """Return {hash: (filename, kind)} for one release, from PyPI.

    :param package: Distribution name.
    :param version: Exact version.
    :returns: Every file PyPI published for that release, keyed by sha256.
    :rtype: dict[str, tuple[str, str]]
    :raises SystemExit: If the release, or a file's packagetype, is unknown.
    """
    url = f"https://pypi.org/pypi/{package}/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
        meta = json.load(response)

    files: dict[str, tuple[str, str]] = {}
    for entry in meta.get("urls", []):
        digest = entry.get("digests", {}).get("sha256")
        packagetype = entry.get("packagetype", "")
        if not digest:
            continue
        if packagetype not in KINDS:
            sys.exit(f"unknown packagetype {packagetype!r} for {package} {version}")
        files[f"sha256:{digest}"] = (entry["filename"], KINDS[packagetype])
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lockfile", type=Path)
    parser.add_argument("-o", "--out", type=Path, required=True)
    parser.add_argument(
        "--source",
        required=True,
        help=(
            "Logical identity of the lock, as registered in repos.json "
            "(e.g. api/tools/requirements.txt). "
            "Recorded instead of the local path, which is generation-machine "
            "scratch state and changes with where the generator was run."
        ),
    )
    args = parser.parse_args()

    pins = parse_lock(args.lockfile)
    artifacts: dict[str, dict[str, str]] = {}
    unresolved: list[str] = []

    for (package, version), hashes in sorted(pins.items()):
        published = registry_files(package, version)
        for digest in hashes:
            if digest not in published:
                # The lock admits a hash the registry does not publish for this
                # version. That is exactly the tampering this file exists to
                # make visible, so it is fatal, not a skipped row.
                unresolved.append(f"{package}=={version} {digest}")
                continue
            name, kind = published[digest]
            artifacts[digest] = {"package": package, "version": version,
                                 "name": name, "kind": kind}
        print(f"  {package}=={version}: {len(hashes)} hashes resolved",
              file=sys.stderr)

    if unresolved:
        for item in unresolved:
            print(f"UNRESOLVED: {item}", file=sys.stderr)
        sys.exit("a locked hash is not published by the registry -- refusing")

    args.out.write_text(
        json.dumps(
            {
                "generated_by": "scripts/generate-pip-lock-manifest.py",
                "source": args.source,
                "note": (
                    "Generated. Hashes come from the lock; name and kind come "
                    "from PyPI. Regenerate by re-running the script."
                ),
                "artifacts": dict(sorted(artifacts.items())),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(artifacts)} artifacts to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
