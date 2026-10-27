#!/usr/bin/env python3
"""Populate repo_deps table from each repo's lockfiles at a named git ref.

Walks each known repo, parses its lockfile (uv.lock for Python, package-lock.json
or pnpm-lock.yaml for Node.js), and inserts a row per (repo, ecosystem, package,
version) into the repo_deps table. Direct deps are marked with is_direct=1 and a
dep_type.

**Reads from a git ref, not the working tree.** These checkouts are shared and
routinely sit on feature branches, so inventorying whatever happened to be
checked out produced a coverage number for a revision nobody deployed and that
nothing recorded. Every row now carries `snapshot_ref`, the resolved commit it
came from, so a coverage claim can be tied to a revision.

**Git-sourced packages carry `source_ref`.** A first-party package pinned by git
is identified by its commit, not by the version string it declares. Two commits can declare the same version,
so joining coverage on version alone lets a review of one authorize the other.

Re-runnable: deletes prior rows for each repo before re-inserting, so the
DB always reflects the state at the requested ref.

Repos and their lockfiles come from repos.json (see load_config); add them
with register-repo.py.

Usage: backfill-repo-deps.py [--ref origin/HEAD] [--repo REPO ...]
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

# tomllib is stdlib in Python 3.11+
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore

def _home() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(os.environ.get("DEP_REVIEW_HOME") or Path(xdg) / "dep-review")


DB_PATH = Path(
    os.environ.get("DEP_REVIEW_DB") or os.environ.get("REVIEWS_DB") or _home() / "reviews.db"
)
CONFIG_PATH = Path(os.environ.get("DEP_REVIEW_CONFIG") or _home() / "repos.json")
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


def load_config(path: Path) -> tuple[Path, list[tuple[str, str, str]], dict, dict]:
    """Read repos.json into (root, lockfiles, manifests, repo_paths).

    Shape::

        {
          "root": "~/code",                      # optional; relative repo paths resolve here
          "repos": [
            {"name": "api", "path": "api",       # path optional, defaults to name
             "lockfiles": [                      # optional; register-repo.py fills it in
               {"ecosystem": "pypi", "path": "uv.lock"},
               {"ecosystem": "pypi", "path": "tools/requirements.txt",
                "manifest": "manifests/api-tools.json"}   # relative to repos.json
             ]}
          ]
        }

    Lockfiles are listed explicitly rather than discovered on each run: a lock
    that silently stops being found would shrink the coverage denominator while
    the repo still reported as covered.
    """
    if not path.is_file():
        return Path.home(), [], {}, {}
    cfg = json.loads(path.read_text())
    root = Path(cfg.get("root") or path.parent).expanduser()
    lockfiles: list[tuple[str, str, str]] = []
    manifests: dict[tuple[str, str], str] = {}
    repo_paths: dict[str, Path] = {}
    for repo in cfg.get("repos", []):
        name = repo["name"]
        repo_paths[name] = (root / Path(repo.get("path") or name).expanduser()).resolve()
        for lock in repo.get("lockfiles", []):
            lockfiles.append((name, lock["ecosystem"], lock["path"]))
            if lock.get("manifest"):
                manifests[(name, lock["path"])] = str(
                    (path.parent / lock["manifest"]).resolve()
                )
    return root, lockfiles, manifests, repo_paths


# (repo_name, ecosystem, relative lockfile path), (repo, lockfile) -> manifest
# path, and repo_name -> checkout. A --require-hashes requirements lock states
# hashes with no filename and no wheel/sdist distinction, both of which
# repo_dep_artifacts requires; generate-pip-lock-manifest.py resolves them from
# the registry once, and the manifest is registered alongside the lock.
REPO_ROOT, LOCKFILES, MANIFESTS, REPO_PATHS = load_config(CONFIG_PATH)


def repo_dir_for(repo: str) -> Path:
    return REPO_PATHS.get(repo, REPO_ROOT / repo)


def git_resolve(repo_dir: Path, ref: str) -> str | None:
    """Resolve *ref* to a commit SHA, or None if the repo/ref is unusable."""
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", f"{ref}^{{commit}}"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return out.stdout.strip() or None


def materialise(repo_dir: Path, ref: str, paths: list[str], dest: Path) -> bool:
    """Write *paths* as they exist at *ref* into *dest*.

    The parsers read files from a directory, so rather than rewrite them to take
    content, the needed files are extracted from the ref into a temp dir. The
    working tree is never read: that is the whole point of the change.

    Missing optional files (pyproject.toml) are skipped; a missing lockfile
    makes the repo unusable and returns False.
    """
    ok = False
    for rel in paths:
        try:
            blob = subprocess.run(
                ["git", "-C", str(repo_dir), "show", f"{ref}:{rel}"],
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob.stdout)
        ok = True
    return ok


#: uv records the resolved commit as the fragment: `...?rev=<pin>#<resolved>`.
#: The fragment is authoritative -- `rev=` may be a branch or tag that moves.
_GIT_SOURCE_RE = re.compile(r"#([0-9a-f]{40})\b")


class AmbiguousSourceRef(Exception):
    """One (package, version) locked at two different commits.

    repo_deps holds a single source_ref per (repo, ecosystem, package, version),
    so it cannot represent this. npm can produce it: the same name@version at two
    nested node_modules paths resolving to different commits. parse_npm then
    dedupes them into one row, and whichever commit survived would authorise the
    dependency while the other stayed locked and unreviewed -- the exact
    version-only authorization source_ref exists to prevent.

    Raised rather than resolved, because there is no correct single answer. The
    backfill treats it like any other parse failure: the repo/ecosystem pair is
    skipped, the run is recorded incomplete, and every guarded report refuses.
    Fail closed beats picking a commit.
    """


def pep503(name: str) -> str:
    """Normalise a Python distribution name per PEP 503.

    Every run of ``-``, ``_`` or ``.`` collapses to a single hyphen, then the
    result is lowercased, so ``zope.interface``, ``zope-interface`` and
    ``Zope__Interface`` compare equal.

    Used for *comparing* identities, not for the keys written to the database.
    The stored keys keep this module's older ``lower().replace("_", "-")``
    because `reviews` holds names that were never normalised on write --
    `aws-cdk.asset-awscli-v1` is there today -- and normalising one side of
    that join without the other would turn a reviewed dependency into an
    unreviewed one. That inconsistency is real but is not this change's to
    make.

    :param name: Distribution name as written in a lockfile or manifest.
    :returns: PEP 503 normalised name.
    :rtype: str
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def git_source_refs(lock_path: Path) -> dict[tuple[str, str], str]:
    """Map normalised package name -> resolved commit, for git-sourced packages."""
    if not lock_path.exists():
        return {}
    with lock_path.open("rb") as handle:
        lock = tomllib.load(handle)
    refs: dict[tuple[str, str], str] = {}
    for pkg in lock.get("package", []) or []:
        source = pkg.get("source") or {}
        git_url = source.get("git") if isinstance(source, dict) else None
        if not git_url:
            continue
        found = _GIT_SOURCE_RE.search(str(git_url))
        if found:
            name = str(pkg.get("name", "")).lower().replace("_", "-")
            version = str(pkg.get("version", ""))
            if not name or not version:
                continue
            # Keyed by (name, version), not name. A lockfile can hold the same
            # package at two versions from two commits; keying by name alone let
            # the later entry's commit be applied to both rows.
            key = (name, version)
            if key in refs and refs[key] != found.group(1):
                raise AmbiguousSourceRef(f"{name} {version}: two commits locked")
            refs[key] = found.group(1)
    return refs


def npm_source_refs(lock_path: Path) -> dict[tuple[str, str], str]:
    """Map npm package name -> resolved commit, for git-sourced packages.

    Counterpart to git_source_refs for uv.lock. Without it an npm dependency
    classified `source_kind='git'` carries source_ref=NULL, and the git coverage
    path compares a review's sha256 against NULL -- which never matches, leaving
    those dependencies permanently uncovered no matter what anyone reviews.

    Keys are the raw npm name, NOT lowercased: npm names are case-sensitive and
    scoped (`@scope/pkg`), and parse_npm records them unchanged. Normalising here
    the way the pypi side does would silently fail to join.
    """
    if not lock_path.exists():
        return {}
    with lock_path.open() as handle:
        lock = json.load(handle)

    refs: dict[tuple[str, str], str] = {}
    for path, info in lock.get("packages", {}).items():
        if not path:
            continue
        name = path.split("node_modules/")[-1]
        if "node_modules/" in name:
            continue
        version = info.get("version") or ""
        resolved = info.get("resolved") or ""
        if not resolved.startswith(("git+", "git:")):
            continue
        found = _GIT_SOURCE_RE.search(resolved)
        if found and name and version:
            key = (name, version)
            # Same name@version at two nested paths, different commits. parse_npm
            # collapses those into one row, so one commit would vanish while
            # still being locked. Nothing here can choose correctly.
            if key in refs and refs[key] != found.group(1):
                raise AmbiguousSourceRef(f"{name} {version}: two commits locked")
            refs[key] = found.group(1)
    return refs


def parse_npm(
    repo_dir: Path, lockfile: Path | None = None
) -> list[tuple[str, str, int, str | None]]:
    """Return list of (package, version, is_direct, dep_type) for an npm repo.

    *lockfile* defaults to ``package-lock.json`` at the repo root, but may name a
    nested lock, e.g. ``infra/cdk/package-lock.json`` pinning only a deploy CLI --
    an executable that often runs holding cloud credentials, so it has to be in
    the inventory rather than reviewed-but-unattributed.
    """
    lockfile = lockfile if lockfile is not None else repo_dir / "package-lock.json"
    with lockfile.open() as f:
        lock = json.load(f)

    # Direct deps from root entry
    root = lock.get("packages", {}).get("", {})
    direct: dict[str, str] = {}
    for section, dep_type in (
        ("dependencies", "prod"),
        ("devDependencies", "dev"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
    ):
        for name in root.get(section, {}):
            # prod beats dev beats optional beats peer
            if name not in direct or dep_type == "prod":
                direct[name] = dep_type

    # Walk all packages, dedupe by (name, version)
    seen: dict[tuple[str, str], tuple[int, str | None]] = {}
    for path, info in lock.get("packages", {}).items():
        if not path:
            continue
        # path looks like "node_modules/foo" or "node_modules/foo/node_modules/bar"
        # take everything after the last "node_modules/"
        name = path.split("node_modules/")[-1]
        if "node_modules/" in name:
            continue
        version = info.get("version", "")
        if not version:
            continue
        key = (name, version)
        is_direct = 1 if name in direct else 0
        dep_type = direct.get(name)
        # If already seen, merge: prefer direct
        if key in seen:
            prev_direct, prev_type = seen[key]
            if prev_direct or is_direct:
                seen[key] = (
                    1 if (prev_direct or is_direct) else 0,
                    prev_type or dep_type,
                )
        else:
            seen[key] = (is_direct, dep_type)

    return [(n, v, d, t) for (n, v), (d, t) in seen.items()]


def parse_pnpm(repo_dir: Path) -> list[tuple[str, str, int, str | None]]:
    """Return list of (package, version, is_direct, dep_type) for a pnpm repo."""
    lockfile = repo_dir / "pnpm-lock.yaml"
    lines = lockfile.read_text().splitlines()

    direct: dict[str, str] = {}
    in_root_importer = False
    current_dep_type: str | None = None
    for line in lines:
        if line == "  .:":
            in_root_importer = True
            current_dep_type = None
            continue
        if in_root_importer and line and not line.startswith(" "):
            break
        if not in_root_importer:
            continue

        stripped = line.strip()
        if line.startswith("    ") and not line.startswith("      "):
            current_dep_type = {
                "dependencies:": "prod",
                "devDependencies:": "dev",
                "optionalDependencies:": "optional",
                "peerDependencies:": "peer",
            }.get(stripped)
            continue

        if (
            current_dep_type
            and line.startswith("      ")
            and not line.startswith("        ")
        ):
            name = stripped.rstrip(":").strip("'\"")
            if name:
                direct.setdefault(name, current_dep_type)

    seen: dict[tuple[str, str], tuple[int, str | None]] = {}
    in_packages = False
    for line in lines:
        if line == "packages:":
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            break
        if not in_packages or not line.startswith("  ") or line.startswith("    "):
            continue

        key = line.strip().rstrip(":").strip("'\"")
        key = key.split("(", 1)[0]
        if "@" not in key:
            continue
        if key.startswith("@"):
            name, version = key.rsplit("@", 1)
        else:
            name, version = key.split("@", 1)
        if not name or not version:
            continue

        is_direct = 1 if name in direct else 0
        dep_type = direct.get(name)
        seen[(name, version)] = (is_direct, dep_type)

    return [(n, v, d, t) for (n, v), (d, t) in seen.items()]


def parse_requirements(repo_dir: Path, lockpath: Path) -> list[tuple[str, str, int, str | None]]:
    """Return list of (package, version, is_direct, dep_type) for a pip lock.

    Parses a ``pip-compile``/``uv pip compile --generate-hashes`` requirements
    file: fully pinned ``name==version`` lines, each followed by ``--hash=``
    continuations and a ``# via`` provenance comment.

    Registered because such a file can be the *only* declaration of an
    executable toolchain, such as a CI security gate installed from a
    hash-locked file. Leaving it out of the inventory puts the gate's own code
    outside the coverage denominator while the repo still reports as covered.

    Only ``==`` pins are inventoried. A range or an unpinned name resolves at
    install time to a version this function cannot know, and recording a guess
    would put a version in the inventory that was never installed.

    :param repo_dir: Checkout root, present for signature parity with the
        other parsers.
    :param lockpath: Path to the requirements file inside *repo_dir*.
    :returns: One row per distinct pinned distribution.
    :rtype: list[tuple[str, str, int, str | None]]
    """
    del repo_dir  # signature parity with parse_npm/parse_pnpm/parse_uv
    text = lockpath.read_text(encoding="utf-8")

    pin_re = re.compile(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;\\]+)")
    rows: list[tuple[str, str, int, str | None]] = []
    seen: set[tuple[str, str]] = set()
    current: tuple[str, str] | None = None
    direct_names: set[tuple[str, str]] = set()

    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            # `# via -r <file>` means the package was named by the input file
            # rather than pulled in by another package. A package can carry
            # several `# via` lines; any one naming `-r` makes it direct.
            if current is not None and "-r " in line:
                direct_names.add(current)
            continue
        match = pin_re.match(line)
        if not match:
            continue
        # PEP 503 normalisation, matching parse_uv, or the rows will not join.
        norm = match.group(1).lower().replace("_", "-")
        key = (norm, match.group(2))
        current = key
        if key in seen:
            continue
        seen.add(key)
        rows.append(key)

    return [
        (name, version, 1 if (name, version) in direct_names else 0, "main")
        for name, version in rows
    ]


def artifacts_requirements(
    lock_path: Path, manifest_path: Path
) -> dict[tuple[str, str], list[tuple[str, str, str]]]:
    """Map (package, version) -> [(artifact_id, filename, kind)] for a pip lock.

    The hashes come from the lock; the filename and kind come from the
    checked-in manifest, which was generated from the registry. A hash the
    manifest cannot name raises rather than being dropped: a silently missing
    artifact row is indistinguishable from a dependency with nothing to review,
    and that shape is what let the gate's own toolchain sit outside the
    coverage denominator in the first place.

    :param lock_path: The ``--require-hashes`` requirements file.
    :param manifest_path: Generated hash -> identity manifest.
    :returns: Artifact rows grouped by the pin that admits them.
    :rtype: dict[tuple[str, str], list[tuple[str, str, str]]]
    :raises KeyError: If the lock admits a hash the manifest does not name.
    """
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))["artifacts"]

    out: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    current: tuple[str, str] | None = None
    hash_re = re.compile(r"--hash=(sha256:[0-9a-f]{64})")

    for raw in lock_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;\\]+)", line)
        if match:
            current = (match.group(1).lower().replace("_", "-"), match.group(2))
            out.setdefault(current, [])
        if current is None:
            continue
        for digest in hash_re.findall(line):
            entry = manifest.get(digest)
            if entry is None:
                raise KeyError(
                    f"{current[0]}=={current[1]} admits {digest}, which "
                    f"{manifest_path.name} does not name -- regenerate it"
                )
            # The digest alone is not enough. A stale, hand-edited or badly
            # merged manifest can carry an entry whose package/version disagree
            # with the pin that admits it, and taking name/kind on the digest
            # match alone would write that contradiction into the audit
            # database as provenance. The manifest states which pin each digest
            # belongs to; check it.
            # Compared under full PEP 503, not the weaker normalisation used
            # for the stored key: an equivalent spelling of the same
            # distribution must not be rejected as a provenance mismatch.
            entry_id = (pep503(entry["package"]), entry["version"])
            if entry_id != (pep503(current[0]), current[1]):
                raise ValueError(
                    f"{manifest_path.name} attributes {digest} to "
                    f"{entry_id[0]}=={entry_id[1]}, but the lock admits it "
                    f"under {current[0]}=={current[1]} -- regenerate it"
                )
            out[current].append((digest, entry["name"], entry["kind"]))
    return out


def parse_uv(repo_dir: Path) -> list[tuple[str, str, int, str | None]]:
    """Return list of (package, version, is_direct, dep_type) for a uv repo."""
    lockfile = repo_dir / "uv.lock"
    with lockfile.open("rb") as f:
        lock = tomllib.load(f)

    # Direct deps from pyproject.toml
    direct: dict[str, str] = {}
    pyproject = repo_dir / "pyproject.toml"
    if pyproject.exists():
        with pyproject.open("rb") as f:
            pp = tomllib.load(f)
        # PEP 621 [project] dependencies
        for dep in pp.get("project", {}).get("dependencies", []) or []:
            name = _extract_name(dep)
            if name:
                direct.setdefault(name, "main")
        # optional-dependencies (extras)
        for extra, deps in (
            pp.get("project", {}).get("optional-dependencies") or {}
        ).items():
            for dep in deps:
                name = _extract_name(dep)
                if name:
                    direct.setdefault(name, f"extra:{extra}")
        # PEP 735 dependency-groups
        for group, deps in (pp.get("dependency-groups") or {}).items():
            for dep in deps:
                if isinstance(dep, str):
                    name = _extract_name(dep)
                    if name:
                        direct.setdefault(name, f"group:{group}")
        # tool.uv dev-dependencies (legacy)
        for dep in pp.get("tool", {}).get("uv", {}).get("dev-dependencies", []) or []:
            name = _extract_name(dep)
            if name:
                direct.setdefault(name, "dev")

    # All packages from uv.lock
    out: list[tuple[str, str, int, str | None]] = []
    seen: set[tuple[str, str]] = set()
    for pkg in lock.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if not name or not version:
            continue
        # Normalize package name: PEP 503 — lower, hyphens
        norm = name.lower().replace("_", "-")
        key = (norm, version)
        if key in seen:
            continue
        seen.add(key)
        is_direct = 1 if norm in {k.lower().replace("_", "-") for k in direct} else 0
        # Find original-case dep_type lookup
        dep_type = None
        for k, v in direct.items():
            if k.lower().replace("_", "-") == norm:
                dep_type = v
                break
        out.append((norm, version, is_direct, dep_type))

    return out


def _extract_name(dep: str) -> str | None:
    """Extract package name from a PEP 508 dep string like 'foo>=1.0; sys_platform=="linux"'."""
    # Strip env marker
    s = dep.split(";")[0].strip()
    # Strip extras: foo[bar,baz]
    if "[" in s:
        s = s[: s.index("[")]
    # Strip version specifiers
    for op in ("===", "==", ">=", "<=", "!=", "~=", ">", "<", "@"):
        if op in s:
            s = s.split(op)[0]
            break
    name = s.strip()
    return name.lower().replace("_", "-") if name else None


# ---------------------------------------------------------------------------
# Artifact identity
#
# The parsers above answer "which package versions does this repo lock?". These
# answer "which specific blobs can that lock install?" -- the question a review
# keyed only by version cannot address. A single locked version routinely admits
# many wheels (charset-normalizer 3.5.1 publishes 171), and which one installs
# depends on the platform, so a dependency's artifact set is a set, not a value.
#
# artifact_id keeps the lockfile's own integrity string verbatim -- 'sha256:...'
# for pypi, 'sha512-...' for npm -- because that is the value the installer
# itself verifies. Re-hashing into a common algorithm would create a second
# source of truth that can disagree with the package manager.
# ---------------------------------------------------------------------------


def artifacts_uv(lock_path: Path) -> dict[tuple[str, str], list[tuple[str, str, str]]]:
    """Map (package, version) -> [(artifact_id, filename, kind)] from uv.lock."""
    with lock_path.open("rb") as f:
        lock = tomllib.load(f)

    out: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for pkg in lock.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if not name or not version:
            continue
        # Match parse_uv's PEP 503 normalisation, or the rows will not join.
        key = (name.lower().replace("_", "-"), version)
        found: list[tuple[str, str, str]] = []

        sdist = pkg.get("sdist")
        if isinstance(sdist, dict) and sdist.get("hash"):
            found.append(
                (
                    sdist["hash"],
                    _basename(sdist.get("url", "")) or f"{name}-{version}.tar.gz",
                    "sdist",
                )
            )

        for wheel in pkg.get("wheels", []) or []:
            if isinstance(wheel, dict) and wheel.get("hash"):
                found.append(
                    (
                        wheel["hash"],
                        _basename(wheel.get("url", "")) or f"{name}-{version}.whl",
                        "wheel",
                    )
                )

        # A package with neither is a git or local source. repo_deps already
        # pins those by commit via source_ref, so recording no artifact here is
        # correct rather than missing data -- but it must not then read as
        # covered, which is why the coverage query treats an empty artifact set
        # as unverified.
        if found:
            out[key] = found
    return out


def artifacts_npm(lock_path: Path) -> dict[tuple[str, str], list[tuple[str, str, str]]]:
    """Map (package, version) -> [(integrity, filename, kind)] from package-lock.json."""
    with lock_path.open() as f:
        lock = json.load(f)

    out: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for path, info in lock.get("packages", {}).items():
        if not path:
            continue
        name = path.split("node_modules/")[-1]
        if "node_modules/" in name:
            continue
        version = info.get("version", "")
        integrity = info.get("integrity", "")
        if not version or not integrity:
            continue
        # npm publishes exactly one tarball per version, so the set is a
        # singleton -- but it is still recorded as a set so the coverage rule is
        # the same shape for every ecosystem.
        filename = _basename(info.get("resolved", "")) or f"{name}-{version}.tgz"
        # Union, not assignment. Two nested paths can hold the same name@version
        # with different integrity values; overwriting dropped one, shrinking the
        # admitted set so a dependency could read as fully reviewed while a blob
        # it can still install was never inspected.
        entry = (integrity, filename, "tarball")
        bucket = out.setdefault((name, version), [])
        if entry not in bucket:
            bucket.append(entry)
    return out


def artifacts_pnpm(
    lock_path: Path,
) -> dict[tuple[str, str], list[tuple[str, str, str]]]:
    """Map (package, version) -> [(integrity, filename, kind)] from pnpm-lock.yaml."""
    lines = lock_path.read_text().splitlines()
    out: dict[tuple[str, str], list[tuple[str, str, str]]] = {}

    in_packages = False
    current: tuple[str, str] | None = None
    for line in lines:
        if line == "packages:":
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            break
        if not in_packages:
            continue

        # A package key sits at exactly two spaces of indent.
        if (
            line.startswith("  ")
            and not line.startswith("    ")
            and line.rstrip().endswith(":")
        ):
            key = line.strip().rstrip(":").strip("'\"")
            key = key.split("(", 1)[0]
            if "@" not in key:
                current = None
                continue
            if key.startswith("@"):
                name, _, version = key.rpartition("@")
            else:
                name, _, version = key.partition("@")
            current = (name, version) if name and version else None
            continue

        if current and "integrity:" in line:
            integrity = line.split("integrity:", 1)[1].strip().strip("{}").strip()
            if integrity:
                out[current] = [
                    (integrity, f"{current[0]}-{current[1]}.tgz", "tarball")
                ]
            current = None
    return out


def source_kinds_uv(lock_path: Path) -> dict[tuple[str, str], str]:
    """Map (package, version) -> 'registry' | 'git' | 'local' from uv.lock.

    uv states this outright, so nothing is inferred: `source = {registry = ...}`,
    `{git = ...}`, and the workspace forms `{editable = ...}`, `{virtual = ...}`,
    `{directory = ...}`. Anything unrecognised falls through to 'registry',
    which is the fail-closed direction -- a registry dependency with no artifact
    rows is reported as uncovered, whereas 'local' would exempt it.
    """
    with lock_path.open("rb") as f:
        lock = tomllib.load(f)

    out: dict[tuple[str, str], str] = {}
    for pkg in lock.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if not name or not version:
            continue
        src = pkg.get("source", {}) or {}
        # Git first here too. uv's source keys are disjoint so ordering cannot
        # currently matter, but both classifiers are kept in the same shape so a
        # reader need not re-verify that claim per ecosystem.
        if "git" in src:
            kind = "git"
        elif any(k in src for k in ("editable", "virtual", "directory", "path")):
            kind = "local"
        else:
            kind = "registry"
        out[(name.lower().replace("_", "-"), version)] = kind
    return out


def source_kinds_npm(lock_path: Path) -> dict[tuple[str, str], str]:
    """Map (package, version) -> kind from package-lock.json.

    A workspace entry is marked `link: true`, or resolves to a relative path
    rather than a URL. Everything else is treated as registry, including an
    entry whose `integrity` failed to extract -- that is the case that used to
    masquerade as local and escape the gate entirely.
    """
    with lock_path.open() as f:
        lock = json.load(f)

    out: dict[tuple[str, str], str] = {}
    for path, info in lock.get("packages", {}).items():
        if not path:
            continue
        name = path.split("node_modules/")[-1]
        if "node_modules/" in name:
            continue
        version = info.get("version", "")
        if not version:
            continue
        resolved = info.get("resolved") or ""
        # Git FIRST. The `git:` form carries no "://", so any generic non-URL
        # test placed ahead of this one swallows it and marks a remote
        # dependency local -- which exempts it from the gate entirely.
        if resolved.startswith(("git+", "git:")):
            kind = "git"
        # Local only in the two proven workspace forms. A bare relative path is
        # deliberately NOT enough: unknown shapes record as registry, where a
        # missing artifact surfaces as an inventory defect instead of an
        # exemption.
        elif info.get("link") is True or resolved.startswith("file:"):
            kind = "local"
        else:
            kind = "registry"
        out[(name, version)] = kind
    return out


def source_kinds_pnpm(lock_path: Path) -> dict[tuple[str, str], str]:
    """Map (package, version) -> kind from pnpm-lock.yaml.

    pnpm keeps workspace packages in `importers:`, not `packages:`, so every key
    under `packages:` is remote. Kept explicit rather than assumed so the
    classification is uniform across ecosystems.
    """
    kinds: dict[tuple[str, str], str] = {}
    for name, version in artifacts_pnpm(lock_path):
        kinds[(name, version)] = "registry"
    return kinds


def _basename(url: str) -> str:
    return url.rsplit("/", 1)[-1] if url else ""


def backfill(
    conn: sqlite3.Connection, ref: str, only_repos: set[str] | None = None
) -> int:
    """Inventory every repo at *ref*. Returns the number of repos skipped.

    Records an ``inventory_runs`` row in the same transaction as the data. A
    non-zero exit protects only the caller that happens to be watching it; the
    committed database has to carry its own completeness. A skipped group
    leaves either stale rows (deletion happens only after a successful parse)
    or no rows at all, and neither is distinguishable later from a clean
    result -- so query-coverage.sh refuses to report against an incomplete run.
    """
    cur = conn.cursor()
    now = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
    skipped = 0
    skipped_pairs: list[str] = []
    expected = 0
    completed = 0

    for repo, ecosystem, lockname in LOCKFILES:
        if only_repos and repo not in only_repos:
            continue
        expected += 1
        repo_dir = repo_dir_for(repo)

        # A repo whose ref cannot be resolved is SKIPPED, never silently
        # inventoried from the working tree -- that fallback is what produced a
        # coverage number for revisions nobody deployed.
        if not repo_dir.is_dir():
            print(
                f"  SKIP {repo} ({ecosystem}): no checkout at {repo_dir}",
                file=sys.stderr,
            )
            skipped += 1
            skipped_pairs.append(f"{repo}/{ecosystem}")
            continue
        snapshot_ref = git_resolve(repo_dir, ref)
        if snapshot_ref is None:
            print(f"  SKIP {repo} ({ecosystem}): cannot resolve {ref}", file=sys.stderr)
            skipped += 1
            skipped_pairs.append(f"{repo}/{ecosystem}")
            continue

        tmp = Path(tempfile.mkdtemp(prefix="repo-deps-"))
        try:
            # Dispatch on the basename, not the whole relative path: a nested
            # lock such as infra/cdk/package-lock.json must still route to the
            # npm parser rather than falling through to parse_uv.
            kind = Path(lockname).name
            # pyproject.toml is only fetched for a ROOT uv.lock; a nested one
            # would need its sibling, which no repo has today.
            wanted = [lockname] + (["pyproject.toml"] if lockname == "uv.lock" else [])
            if not materialise(repo_dir, snapshot_ref, wanted, tmp):
                print(
                    f"  SKIP {repo} ({ecosystem}): no {lockname} at {snapshot_ref[:8]}",
                    file=sys.stderr,
                )
                skipped += 1
                skipped_pairs.append(f"{repo}/{ecosystem}")
                continue

            try:
                if kind == "package-lock.json":
                    rows = parse_npm(tmp, tmp / lockname)
                elif kind == "pnpm-lock.yaml":
                    rows = parse_pnpm(tmp)
                elif kind.endswith(".txt"):
                    rows = parse_requirements(tmp, tmp / lockname)
                else:
                    rows = parse_uv(tmp)
                if kind == "uv.lock":
                    source_refs = git_source_refs(tmp / lockname)
                elif kind == "package-lock.json":
                    source_refs = npm_source_refs(tmp / lockname)
                else:
                    # pnpm records a git dependency's commit in the package key
                    # rather than a resolved URL; not extracted yet, so such a
                    # dependency stays uncovered rather than wrongly covered.
                    source_refs = {}
                # Must happen here: the finally below removes tmp before the
                # database writes.
                if kind == "package-lock.json":
                    artifacts = artifacts_npm(tmp / lockname)
                    kinds = source_kinds_npm(tmp / lockname)
                elif kind == "pnpm-lock.yaml":
                    artifacts = artifacts_pnpm(tmp / lockname)
                    kinds = source_kinds_pnpm(tmp / lockname)
                elif kind.endswith(".txt"):
                    manifest_rel = MANIFESTS.get((repo, lockname))
                    if manifest_rel is None:
                        raise KeyError(
                            f"{repo}/{lockname} has no manifest in repos.json; a "
                            "pip lock cannot name its artifacts without one"
                        )
                    artifacts = artifacts_requirements(tmp / lockname, Path(manifest_rel))
                    kinds = {k: "registry" for k in {(r[0], r[1]) for r in rows}}
                else:
                    artifacts = artifacts_uv(tmp / lockname)
                    kinds = source_kinds_uv(tmp / lockname)
            except Exception as e:  # noqa: BLE001 -- one bad repo must not abort the sweep
                print(f"  ERROR {repo} ({ecosystem}): {e}", file=sys.stderr)
                skipped += 1
                skipped_pairs.append(f"{repo}/{ecosystem}")
                continue
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        # Replace existing rows for this (repo, ecosystem)
        cur.execute(
            "DELETE FROM repo_deps WHERE repo=? AND ecosystem=?", (repo, ecosystem)
        )
        cur.executemany(
            """
            INSERT OR REPLACE INTO repo_deps
              (repo, ecosystem, package, version, is_direct, dep_type,
               snapshot_at, snapshot_ref, source_ref, source_kind)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    repo,
                    ecosystem,
                    n,
                    v,
                    d,
                    t,
                    now,
                    snapshot_ref,
                    source_refs.get((n, v)),
                    # Unrecognised falls to 'registry', never 'local'.
                    kinds.get((n, v), "registry"),
                )
                for n, v, d, t in rows
            ],
        )
        # Replace artifact rows for this (repo, ecosystem) too. Both tables are
        # rewritten in one transaction so an inventory can never leave a
        # dependency present with a stale artifact set -- which would let a
        # superseded artifact keep authorising a current dependency.
        cur.execute(
            "DELETE FROM repo_dep_artifacts WHERE repo=? AND ecosystem=?",
            (repo, ecosystem),
        )
        locked = {(n, v) for n, v, _, _ in rows}
        cur.executemany(
            """
            INSERT OR REPLACE INTO repo_dep_artifacts
              (repo, ecosystem, package, version, artifact_id, artifact_name,
               artifact_kind)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (repo, ecosystem, pkg, ver, aid, aname, kind)
                for (pkg, ver), items in artifacts.items()
                if (pkg, ver) in locked
                for aid, aname, kind in items
            ],
        )

        completed += 1
        direct_count = sum(1 for _, _, d, _ in rows if d)
        git_count = sum(1 for n, v, _, _ in rows if (n, v) in source_refs)
        extra = f", {git_count} git-sourced" if git_count else ""
        art_count = sum(len(v) for k, v in artifacts.items() if k in locked)
        no_artifacts = len(locked) - len([k for k in artifacts if k in locked])
        art = f", {art_count} artifacts"
        if no_artifacts:
            art += f", {no_artifacts} pkgs w/o artifact"
        print(
            f"  {repo:<32} {ecosystem:<5} {len(rows):>5} pkgs "
            f"({direct_count} direct{extra}{art}) @ {snapshot_ref[:8]}"
        )

    # Plain INSERT against an AUTOINCREMENT run_id. `INSERT OR REPLACE` keyed on
    # (run_at, ref) silently overwrote a run that shared a second with an
    # earlier one, destroying exactly the history the gate reads.
    cur.execute(
        """
        INSERT INTO inventory_runs
          (run_at, ref, expected_pairs, completed_pairs, skipped, status)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            now,
            ref,
            expected,
            completed,
            ",".join(skipped_pairs)
            or ("scoped to " + ",".join(sorted(only_repos)) if only_repos else ""),
            # A --repo run inventories a subset by design, so it establishes
            # nothing about the estate. Recording it as complete would clear
            # the gate at 2/2 for a 12-pair estate -- the same hole as a
            # skipped group, arrived at from the other direction.
            "incomplete" if (skipped or only_repos) else "complete",
        ),
    )
    conn.commit()
    return skipped


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--ref",
        default="origin/HEAD",
        help="Git ref to inventory (default origin/HEAD, the remote's default branch). "
        "Never the working tree.",
    )
    ap.add_argument("--repo", action="append", default=[], help="Limit to these repos")
    args = ap.parse_args()

    if not LOCKFILES:
        print(
            f"No lockfiles registered in {CONFIG_PATH}. Add repos with register-repo.py.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    only = set(args.repo) if args.repo else None
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA_PATH.read_text())
    try:
        skipped = backfill(conn, args.ref, only)
    finally:
        conn.close()
    if skipped:
        # Non-zero so a caller cannot read a partial inventory as a complete one.
        print(
            f"\n{skipped} repo/ecosystem pair(s) skipped -- inventory is incomplete",
            file=sys.stderr,
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
