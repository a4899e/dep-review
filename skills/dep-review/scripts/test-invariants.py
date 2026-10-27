#!/usr/bin/env python3
"""Invariant tests for the review database's authorization rules.

Why this exists
---------------
Coverage decides which dependencies are authorised to be in the tree. Until now
every change to that decision was verified by hand in a shell and then forgotten,
so each round of review found a hole opened by the previous round's fix: the
local-classification rule was corrected and re-broke on branch ordering; the
audit was widened twice and still certified an inventory_runs append as "nothing
security-relevant moved"; a commit message claimed a regression test that was
never committed.

Ad-hoc verification does not survive the next edit. These do.

Everything runs against a temporary database and temporary git repositories.
Nothing here touches your real review database.

Usage: ./scripts/test-invariants.py [-v]
Exit:  0 all passed, 1 any failed
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
REPO = SCRIPTS.parent

_spec = importlib.util.spec_from_file_location("bf", SCRIPTS / "backfill-repo-deps.py")
bf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bf)

FAILURES: list[str] = []
VERBOSE = "-v" in sys.argv


def check(name: str, got, want) -> None:
    if got == want:
        if VERBOSE:
            print(f"  ok   {name}")
    else:
        FAILURES.append(f"{name}: got {got!r}, want {want!r}")
        print(f"  FAIL {name}: got {got!r}, want {want!r}")


def section(title: str) -> None:
    print(f"\n{title}")


# ---------------------------------------------------------------------------
# Source classification. Every entry here is a shape that has either caused a
# fail-open or is one branch reorder away from causing one.
# ---------------------------------------------------------------------------


def test_npm_classification() -> None:
    section("npm source classification")
    cases = [
        # (resolved, link, expected)
        ("git:github.com/org/repo", None, "git"),  # no "://" -- was read as local
        ("git+https://github.com/o/r.git#" + "a" * 40, None, "git"),
        ("git+ssh://git@github.com/o/r", None, "git"),
        ("file:../local-pkg", None, "local"),
        ("packages/foo", True, "local"),  # workspace, proven by link
        ("packages/foo", None, "registry"),  # bare path alone is NOT proof
        ("https://registry.npmjs.org/x/-/x-1.tgz", None, "registry"),
        ("", None, "registry"),  # bundled dep: no resolved, still remote
    ]
    pkgs: dict = {"": {}}
    for i, (resolved, link, _) in enumerate(cases):
        entry = {"version": "1.0.0", "resolved": resolved, "integrity": "sha512-x"}
        if link is not None:
            entry["link"] = link
        pkgs[f"node_modules/p{i}"] = entry

    with tempfile.TemporaryDirectory() as d:
        lock = Path(d) / "package-lock.json"
        lock.write_text(json.dumps({"packages": pkgs}))
        got = bf.source_kinds_npm(lock)
    for i, (resolved, link, want) in enumerate(cases):
        check(f"resolved={resolved!r} link={link}", got.get((f"p{i}", "1.0.0")), want)


def test_uv_classification() -> None:
    section("uv source classification")
    lock = """
[[package]]
name = "reg"
version = "1.0"
source = {{ registry = "https://pypi.org/simple" }}

[[package]]
name = "gitdep"
version = "2.0"
source = {{ git = "https://github.com/o/r?rev=abc#{sha}" }}

[[package]]
name = "editable-pkg"
version = "0.1"
source = {{ editable = "." }}

[[package]]
name = "virtual-pkg"
version = "0.1"
source = {{ virtual = "." }}
""".format(sha="b" * 40)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "uv.lock"
        p.write_text(lock)
        got = bf.source_kinds_uv(p)
        refs = bf.git_source_refs(p)
    check("registry", got.get(("reg", "1.0")), "registry")
    check("git", got.get(("gitdep", "2.0")), "git")
    check("editable -> local", got.get(("editable-pkg", "0.1")), "local")
    check("virtual -> local", got.get(("virtual-pkg", "0.1")), "local")
    check("git commit extracted", refs.get(("gitdep", "2.0")), "b" * 40)


def test_npm_source_refs() -> None:
    section("npm git commit extraction")
    sha = "c" * 40
    pkgs = {
        "": {},
        "node_modules/gitdep": {
            "version": "1.0.0",
            "resolved": f"git+https://github.com/o/r.git#{sha}",
        },
        "node_modules/@scope/scoped": {
            "version": "2.0.0",
            "resolved": f"git+ssh://git@github.com/o/s.git#{sha}",
        },
        "node_modules/normal": {
            "version": "1.0.0",
            "resolved": "https://registry.npmjs.org/n/-/n-1.tgz",
            "integrity": "sha512-x",
        },
    }
    with tempfile.TemporaryDirectory() as d:
        lock = Path(d) / "package-lock.json"
        lock.write_text(json.dumps({"packages": pkgs}))
        refs = bf.npm_source_refs(lock)
    check("git dep commit", refs.get(("gitdep", "1.0.0")), sha)
    # Scoped names must not be normalised, or they will never join to repo_deps.
    check("scoped name preserved", refs.get(("@scope/scoped", "2.0.0")), sha)
    check("registry dep absent", ("normal", "1.0.0") in refs, False)


def _npm_lock(entries: dict) -> dict:
    return {"packages": {"": {}, **entries}}


def test_npm_nested_git_identities() -> None:
    """Nested node_modules paths must not collapse two commits into one."""
    section("npm nested git identities")
    a, b = "a" * 40, "b" * 40

    # Different versions, different commits. Keying by name alone applied the
    # later commit to BOTH rows.
    lock = _npm_lock(
        {
            "node_modules/gitdep": {
                "version": "1.0.0",
                "resolved": f"git+https://github.com/o/r.git#{a}",
            },
            "node_modules/other/node_modules/gitdep": {
                "version": "2.0.0",
                "resolved": f"git+https://github.com/o/r.git#{b}",
            },
        }
    )
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "package-lock.json"
        f.write_text(json.dumps(lock))
        refs = bf.npm_source_refs(f)
    check("nested v1 keeps its own commit", refs.get(("gitdep", "1.0.0")), a)
    check("nested v2 keeps its own commit", refs.get(("gitdep", "2.0.0")), b)

    # Same version, two commits. repo_deps cannot represent this and parse_npm
    # dedupes the rows, so one commit would vanish while still locked. Must
    # refuse rather than choose.
    lock = _npm_lock(
        {
            "node_modules/gitdep": {
                "version": "1.0.0",
                "resolved": f"git+https://github.com/o/r.git#{a}",
            },
            "node_modules/other/node_modules/gitdep": {
                "version": "1.0.0",
                "resolved": f"git+https://github.com/o/r.git#{b}",
            },
        }
    )
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "package-lock.json"
        f.write_text(json.dumps(lock))
        try:
            bf.npm_source_refs(f)
            raised = False
        except bf.AmbiguousSourceRef:
            raised = True
    check("same version + two commits refuses", raised, True)


def test_uv_same_name_two_versions() -> None:
    section("uv git identity per version")
    a, b = "1" * 40, "2" * 40
    lock = f"""
[[package]]
name = "dup"
version = "1.0"
source = {{ git = "https://github.com/o/r#{a}" }}

[[package]]
name = "dup"
version = "2.0"
source = {{ git = "https://github.com/o/r#{b}" }}
"""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "uv.lock"
        f.write_text(lock)
        refs = bf.git_source_refs(f)
    check("uv v1 keeps its commit", refs.get(("dup", "1.0")), a)
    check("uv v2 keeps its commit", refs.get(("dup", "2.0")), b)


def test_npm_artifact_union() -> None:
    """Two nested entries at one version admit BOTH blobs, not the last one."""
    section("npm artifact union")
    lock = _npm_lock(
        {
            "node_modules/dup": {
                "version": "1.0.0",
                "integrity": "sha512-AAA",
                "resolved": "https://r/a.tgz",
            },
            "node_modules/other/node_modules/dup": {
                "version": "1.0.0",
                "integrity": "sha512-BBB",
                "resolved": "https://r/b.tgz",
            },
        }
    )
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "package-lock.json"
        f.write_text(json.dumps(lock))
        arts = bf.artifacts_npm(f)
    ids = sorted(a[0] for a in arts.get(("dup", "1.0.0"), []))
    check("both integrities admitted", ids, ["sha512-AAA", "sha512-BBB"])


def test_npm_artifacts() -> None:
    section("npm artifact extraction")
    pkgs = {
        "": {},
        "node_modules/a": {
            "version": "1.0.0",
            "integrity": "sha512-AAA",
            "resolved": "https://r/a.tgz",
        },
        "node_modules/b": {"version": "1.0.0"},  # no integrity -> no artifact row
    }
    with tempfile.TemporaryDirectory() as d:
        lock = Path(d) / "package-lock.json"
        lock.write_text(json.dumps({"packages": pkgs}))
        arts = bf.artifacts_npm(lock)
        kinds = bf.source_kinds_npm(lock)
    check("integrity captured", arts.get(("a", "1.0.0"))[0][0], "sha512-AAA")
    check("one artifact per npm package", len(arts.get(("a", "1.0.0"))), 1)
    # The pair that used to fail open: no artifact row, but still classified
    # remote, so it lands in no_artifact rather than being exempted as local.
    check("no-integrity has no artifact", ("b", "1.0.0") in arts, False)
    check("no-integrity still registry", kinds.get(("b", "1.0.0")), "registry")


def test_nested_npm_lockfile() -> None:
    """A lockfile below the repo root must be parsed, and routed by basename.

    Regression: a Python repo that also pins the CDK CLI at
    infra/cdk/package-lock.json. Two things
    used to break that: parse_npm hardcoded ``repo_dir / "package-lock.json"``,
    and the sweep dispatched on the whole relative path, so a nested lock fell
    through to the uv parser. The consequence was not a crash -- the CLI simply
    never entered repo_deps, leaving an executable that runs with credentials for
    the CDK bootstrap roles outside the coverage denominator while the repo still
    reported as covered.
    """
    section("nested npm lockfile")
    lock = {
        "packages": {
            "": {"devDependencies": {"aws-cdk": "2.1128.1"}},
            "node_modules/aws-cdk": {
                "version": "2.1128.1",
                "integrity": "sha512-NESTED",
                "resolved": "https://registry.npmjs.org/aws-cdk/-/aws-cdk-2.1128.1.tgz",
            },
        }
    }
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        nested = root / "infra" / "cdk" / "package-lock.json"
        nested.parent.mkdir(parents=True)
        nested.write_text(json.dumps(lock))

        rows = bf.parse_npm(root, nested)
        check("nested lock is parsed", [(r[0], r[1]) for r in rows], [("aws-cdk", "2.1128.1")])
        check("recorded as a direct dependency", rows[0][2], 1)
        check("dep_type preserved", rows[0][3], "dev")

        arts = bf.artifacts_npm(nested)
        check(
            "nested artifact identity captured",
            arts.get(("aws-cdk", "2.1128.1"))[0][0],
            "sha512-NESTED",
        )

        # And the root default still works, so registered root locks are unaffected.
        (root / "package-lock.json").write_text(json.dumps(lock))
        check("root default still resolves", len(bf.parse_npm(root)), 1)

    # ---- End to end through the production dispatcher -------------------------
    #
    # The checks above exercise parse_npm directly, which is not enough: the
    # sweep chooses a parser before ever calling one. An earlier version of this
    # test asserted `Path("infra/cdk/package-lock.json").name == "package-lock.json"`,
    # which is a fact about the standard library and stays true no matter what
    # backfill() does -- so reverting `kind = Path(lockname).name` to comparisons
    # against the full lockname would have left this test green while the
    # registered nested lock silently fell through to parse_uv again.
    #
    # Drive the real backfill instead and assert the row lands.
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        repo = root / "fakerepo"
        nested = repo / "infra" / "cdk" / "package-lock.json"
        nested.parent.mkdir(parents=True)
        nested.write_text(json.dumps(lock))
        env = dict(
            os.environ,
            GIT_AUTHOR_NAME="t",
            GIT_AUTHOR_EMAIL="t@t",
            GIT_COMMITTER_NAME="t",
            GIT_COMMITTER_EMAIL="t@t",
        )
        for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "x"]):
            subprocess.run(
                ["git", "-C", str(repo), *cmd], check=True, env=env, capture_output=True
            )

        db = root / "t.db"
        build_db(db).close()
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM inventory_runs")
        conn.commit()

        orig_root, orig_locks, orig_paths = bf.REPO_ROOT, bf.LOCKFILES, bf.REPO_PATHS
        try:
            bf.REPO_ROOT, bf.REPO_PATHS = root, {}
            bf.LOCKFILES = [("fakerepo", "npm", "infra/cdk/package-lock.json")]
            bf.backfill(conn, "HEAD")
            conn.commit()
        finally:
            bf.REPO_ROOT, bf.LOCKFILES, bf.REPO_PATHS = orig_root, orig_locks, orig_paths

        status = conn.execute(
            "SELECT status FROM inventory_runs ORDER BY run_id DESC LIMIT 1"
        ).fetchone()[0]
        deps = conn.execute(
            "SELECT ecosystem, package, version, is_direct FROM repo_deps"
        ).fetchall()
        arts = conn.execute(
            "SELECT artifact_id, artifact_kind FROM repo_dep_artifacts"
        ).fetchall()
        conn.close()

    # A revert routes the nested lock to parse_uv, which finds no uv.lock, errors,
    # and the pair is skipped -- so the run is incomplete and no rows exist.
    check("nested lock produces a COMPLETE inventory run", status, "complete")
    check("dispatcher emitted the npm dependency", deps, [("npm", "aws-cdk", "2.1128.1", 1)])
    check("dispatcher emitted its artifact identity", arts, [("sha512-NESTED", "tarball")])


# ---------------------------------------------------------------------------
# Coverage truth table, run against the real query-coverage.sh.
# ---------------------------------------------------------------------------

SCHEMA_SRC = SCRIPTS / "schema.sql"


def build_db(path: Path) -> sqlite3.Connection:
    """Empty database with the shipped schema."""
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA_SRC.read_text())
    conn.execute(
        "INSERT INTO inventory_runs (run_at,ref,expected_pairs,completed_pairs,skipped,status)"
        " VALUES ('2026-01-01','abc',1,1,'','complete')"
    )
    conn.commit()
    return conn


def add_dep(conn, pkg, ver, kind, source_ref=None, repo="r1") -> None:
    conn.execute(
        "INSERT INTO repo_deps (repo,ecosystem,package,version,is_direct,dep_type,"
        "snapshot_at,snapshot_ref,source_ref,source_kind) VALUES (?,?,?,?,1,'main','t','deadbeef',?,?)",
        (repo, "pypi", pkg, ver, source_ref, kind),
    )


def add_review(conn, pkg, ver, verdict, sha256="x") -> None:
    conn.execute(
        "INSERT INTO reviews (ecosystem,package,version,sha256,verdict,notes,reviewed_at,reviewer)"
        " VALUES ('pypi',?,?,?,?,'n','t','test')",
        (pkg, ver, sha256, verdict),
    )


def add_artifact(conn, pkg, ver, aid, reviewed: bool, repo="r1") -> None:
    conn.execute(
        "INSERT INTO repo_dep_artifacts VALUES (?,?,?,?,?,?,?)",
        (repo, "pypi", pkg, ver, aid, "f.whl", "wheel"),
    )
    if reviewed:
        conn.execute(
            "INSERT INTO review_artifacts (ecosystem,package,version,artifact_id,"
            "artifact_name,artifact_kind,source_read,verdict,notes,reviewed_at,reviewer)"
            " VALUES ('pypi',?,?,?,'f.whl','wheel',1,'pass','n','t','test')",
            (pkg, ver, aid),
        )


def run_coverage(db: Path) -> tuple[int, str]:
    env = dict(os.environ, DEP_REVIEW_DB=str(db))
    proc = subprocess.run(
        [str(SCRIPTS / "query-coverage.sh")],
        capture_output=True,
        text=True,
        env=env,
        check=False,  # a non-zero exit IS the assertion here
    )
    return proc.returncode, proc.stdout + proc.stderr


def covered_count(db: Path) -> int:
    _, out = run_coverage(db)
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0] == "r1":
            return int(parts[4])  # repo ecosystem total local covered
    return -1


def test_coverage_truth_table() -> None:
    section("coverage truth table")
    scenarios = [
        # (name, verdict, artifacts_reviewed, expect_covered)
        ("pass + complete artifacts", "pass", True, 1),
        ("partial + complete artifacts", "partial", True, 1),
        ("fail + complete artifacts (veto)", "fail", True, 0),
        ("pass + incomplete artifacts", "pass", False, 0),
        ("no version review + complete artifacts", None, True, 0),
    ]
    for name, verdict, reviewed, want in scenarios:
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "t.db"
            conn = build_db(db)
            add_dep(conn, "pkg", "1.0", "registry")
            if verdict:
                add_review(conn, "pkg", "1.0", verdict)
            add_artifact(conn, "pkg", "1.0", "sha256:a", reviewed)
            conn.commit()
            conn.close()
            check(name, covered_count(db), want)


def test_coverage_source_paths() -> None:
    section("coverage by source kind")
    sha = "d" * 40

    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "t.db"
        conn = build_db(db)
        add_dep(conn, "gitpkg", "1.0", "git", source_ref=sha)
        add_review(conn, "gitpkg", "1.0", "pass", sha256=sha)
        conn.commit()
        conn.close()
        check("git: review names the same commit", covered_count(db), 1)

    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "t.db"
        conn = build_db(db)
        add_dep(conn, "gitpkg", "1.0", "git", source_ref=sha)
        add_review(conn, "gitpkg", "1.0", "pass", sha256="e" * 40)
        conn.commit()
        conn.close()
        check("git: different commit, same version", covered_count(db), 0)

    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "t.db"
        conn = build_db(db)
        add_dep(conn, "own", "0.1", "local")
        conn.commit()
        conn.close()
        rc, out = run_coverage(db)
        row = next(ln.split() for ln in out.splitlines() if ln.startswith("r1"))
        check("local: excluded from denominator", row[3], "1")  # local column
        check("local: not counted covered", row[4], "0")
        check("local only -> gate passes", rc, 0)

    # Remote with no artifact identity. The shape that used to be read as
    # first-party and skipped the gate entirely.
    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "t.db"
        conn = build_db(db)
        add_dep(conn, "pkg", "1.0", "registry")
        add_review(conn, "pkg", "1.0", "pass")
        conn.commit()
        conn.close()
        rc, out = run_coverage(db)
        check("registry with no artifacts: uncovered", covered_count(db), 0)
        check("registry with no artifacts: gate fails", rc, 1)
        check("surfaced in no_artifact", "no_artifact" in out, True)


def test_guards() -> None:
    section("guards")
    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "t.db"
        conn = build_db(db)
        add_dep(conn, "pkg", "1.0", "registry")
        conn.execute("UPDATE repo_deps SET source_kind=NULL")
        conn.commit()
        conn.close()
        rc, out = run_coverage(db)
        check("NULL source_kind refuses", rc, 1)
        check("NULL source_kind says why", "no source_kind" in out, True)

    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "t.db"
        conn = build_db(db)
        add_dep(conn, "pkg", "1.0", "registry")
        conn.execute(
            "INSERT INTO inventory_runs (run_at,ref,expected_pairs,completed_pairs,skipped,status)"
            " VALUES ('2026-01-02','def',12,11,'x/pypi','incomplete')"
        )
        conn.commit()
        conn.close()
        env = dict(os.environ, DEP_REVIEW_DB=str(db))
        for script in (
            "query-coverage.sh",
            "query-artifact-gap.sh",
            "query-stale.sh",
            "query-mismatches.sh",
        ):
            proc = subprocess.run(
                [str(SCRIPTS / script)],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            check(f"{script} refuses incomplete inventory", proc.returncode, 1)
        proc = subprocess.run(
            [str(SCRIPTS / "query-impact.sh"), "pypi", "pkg"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        check("query-impact.sh refuses incomplete inventory", proc.returncode, 1)


# ---------------------------------------------------------------------------
# The binary-diff audit, run as a real git repo so it exercises `git show`.
# ---------------------------------------------------------------------------


def git_fixture(tmp: Path) -> Path:
    repo = tmp / "repo"
    (repo / "scripts").mkdir(parents=True)
    for f in ("check-uncommitted.sh", "lib-inventory-guard.sh", "lib-db.sh", "schema.sql"):
        shutil.copy(SCRIPTS / f, repo / "scripts" / f)
    conn = build_db(repo / "reviews.db")
    add_dep(conn, "pkg", "1.0", "registry")
    add_review(conn, "pkg", "1.0", "pass")
    add_artifact(conn, "pkg", "1.0", "sha256:a", True)
    conn.commit()
    conn.close()
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@t",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@t",
    )
    for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "base"]):
        subprocess.run(
            ["git", "-C", str(repo), *cmd], check=True, env=env, capture_output=True
        )
    return repo


def run_audit(repo: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [str(repo / "scripts" / "check-uncommitted.sh")],
        capture_output=True,
        text=True,
        cwd=repo,
        env=dict(os.environ, DEP_REVIEW_DB=str(repo / "reviews.db")),
        check=False,  # a non-zero exit IS the assertion here
    )
    return proc.returncode, proc.stdout + proc.stderr


def test_audit_detects() -> None:
    section("binary-diff audit")
    mutations = [
        (
            "relabel a reviewed wheel as an sdist",
            "UPDATE review_artifacts SET artifact_kind='sdist'",
        ),
        (
            "flip a registry dependency to local",
            "UPDATE repo_deps SET source_kind='local'",
        ),
        (
            "repoint a git dependency's commit",
            "UPDATE repo_deps SET source_ref='f'",
        ),
        (
            "swap an admitted artifact id",
            "UPDATE repo_dep_artifacts SET artifact_id='sha256:z'",
        ),
        (
            "forge a review verdict",
            "UPDATE reviews SET verdict='fail'",
        ),
        (
            "append an inventory run (guard state flip)",
            (
                "INSERT INTO inventory_runs (run_at,ref,expected_pairs,"
                "completed_pairs,skipped,status) "
                "VALUES ('2026-02-02','zzz',1,0,'x','incomplete')"
            ),
        ),
    ]
    with tempfile.TemporaryDirectory() as d:
        repo = git_fixture(Path(d))
        rc, _ = run_audit(repo)
        check("unmodified repo is clean", rc, 0)

        for name, sql in mutations:
            backup = (repo / "reviews.db").read_bytes()
            conn = sqlite3.connect(repo / "reviews.db")
            conn.execute(sql)
            conn.commit()
            conn.close()
            rc, _ = run_audit(repo)
            check(name, rc, 1)
            (repo / "reviews.db").write_bytes(backup)


def test_ambiguous_lock_fails_closed() -> None:
    """The reviewer's reproduction: an ambiguous lock must not yield coverage.

    Function-level refusal is not enough on its own. What matters is what the
    whole pipeline does with it: the pair must be skipped, the run recorded
    incomplete, and every report must then refuse -- rather than the backfill
    quietly emitting one row and coverage reporting 100%.
    """
    section("ambiguous lock fails closed end to end")
    a, b = "a" * 40, "b" * 40
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        repo = root / "fakerepo"
        repo.mkdir()
        (repo / "package-lock.json").write_text(
            json.dumps(
                _npm_lock(
                    {
                        "node_modules/gitdep": {
                            "version": "1.0.0",
                            "resolved": f"git+https://github.com/o/r.git#{a}",
                        },
                        "node_modules/x/node_modules/gitdep": {
                            "version": "1.0.0",
                            "resolved": f"git+https://github.com/o/r.git#{b}",
                        },
                    }
                )
            )
        )
        env = dict(
            os.environ,
            GIT_AUTHOR_NAME="t",
            GIT_AUTHOR_EMAIL="t@t",
            GIT_COMMITTER_NAME="t",
            GIT_COMMITTER_EMAIL="t@t",
        )
        for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "x"]):
            subprocess.run(
                ["git", "-C", str(repo), *cmd], check=True, env=env, capture_output=True
            )

        db = root / "t.db"
        build_db(db).close()
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM inventory_runs")
        conn.commit()

        orig_root, orig_locks, orig_paths = bf.REPO_ROOT, bf.LOCKFILES, bf.REPO_PATHS
        try:
            bf.REPO_ROOT, bf.REPO_PATHS = root, {}
            bf.LOCKFILES = [("fakerepo", "npm", "package-lock.json")]
            bf.backfill(conn, "HEAD")
            conn.commit()
        finally:
            bf.REPO_ROOT, bf.LOCKFILES, bf.REPO_PATHS = orig_root, orig_locks, orig_paths

        status = conn.execute(
            "SELECT status FROM inventory_runs ORDER BY run_id DESC LIMIT 1"
        ).fetchone()[0]
        deps = conn.execute("SELECT COUNT(*) FROM repo_deps").fetchone()[0]
        conn.close()

        check("run recorded incomplete", status, "incomplete")
        check("no dependency rows emitted", deps, 0)
        rc, out = run_coverage(db)
        check("coverage refuses", rc, 1)
        check("refusal names the incomplete run", "incomplete" in out, True)


# ---------------------------------------------------------------------------
# pip lock manifest. A --require-hashes file states hashes with no filename and
# no wheel/sdist distinction, so those come from a generated manifest. Both
# ways that mapping can go wrong write false provenance into the audit
# database, so both must raise rather than degrade.
# ---------------------------------------------------------------------------


def test_requirements_manifest_fails_closed() -> None:
    section("pip lock manifest fails closed")

    digest = "sha256:" + "a" * 64
    lock = (
        "target==1 \\\n"
        f"    --hash={digest}\n"
        "    # via -r requirements.in\n"
    )

    def run(manifest_artifacts):
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "requirements.txt"
            lock_path.write_text(lock, encoding="utf-8")
            man_path = Path(tmp) / "manifest.json"
            man_path.write_text(
                json.dumps({"artifacts": manifest_artifacts}), encoding="utf-8"
            )
            return bf.artifacts_requirements(lock_path, man_path)

    # The digest belongs to a DIFFERENT release than the pin that admits it.
    # Looking up by digest alone accepted this and emitted the wrong filename
    # under target==1.
    try:
        run({digest: {"package": "different-project", "version": "9",
                      "name": "different-9.whl", "kind": "wheel"}})
        check("mismatched package/version raises", "no exception", "ValueError")
    except ValueError:
        check("mismatched package/version raises", "ValueError", "ValueError")

    # Same package, wrong version.
    try:
        run({digest: {"package": "target", "version": "2",
                      "name": "target-2.whl", "kind": "wheel"}})
        check("mismatched version raises", "no exception", "ValueError")
    except ValueError:
        check("mismatched version raises", "ValueError", "ValueError")

    # A digest the manifest does not name must raise, never be dropped: a
    # silently missing artifact row is indistinguishable from a dependency with
    # nothing to review.
    try:
        run({})
        check("unnamed digest raises", "no exception", "KeyError")
    except KeyError:
        check("unnamed digest raises", "KeyError", "KeyError")

    # Falsify by inversion: the correct manifest must still be accepted, or the
    # checks above would pass by rejecting everything.
    rows = run({digest: {"package": "target", "version": "1",
                         "name": "target-1.whl", "kind": "wheel"}})
    check("matching entry accepted", rows, {("target", "1"): [(digest, "target-1.whl", "wheel")]})

    # PEP 503 equivalence, in full: every run of -, _ or . collapses to one
    # hyphen. A weaker `lower().replace("_", "-")` passes the underscore case
    # while still rejecting `zope.interface` vs `zope-interface`, so each
    # separator class is exercised separately rather than by one example.
    def equivalent(lock_name, manifest_name):
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "requirements.txt"
            lock_path.write_text(
                f"{lock_name}==1 \\\n    --hash={digest}\n", encoding="utf-8"
            )
            man_path = Path(tmp) / "manifest.json"
            man_path.write_text(
                json.dumps({"artifacts": {digest: {
                    "package": manifest_name, "version": "1",
                    "name": "x-1.whl", "kind": "wheel"}}}),
                encoding="utf-8",
            )
            try:
                bf.artifacts_requirements(lock_path, man_path)
                return "accepted"
            except ValueError:
                return "rejected"

    for lock_name, manifest_name, label in (
        ("target-project", "Target_Project", "underscore vs hyphen"),
        ("zope-interface", "zope.interface", "dot vs hyphen"),
        ("a-b", "a__b", "repeated underscore"),
        ("a-b", "a..b", "repeated dot"),
        ("a-b", "a-_.b", "mixed separators"),
        ("RUAMEL.YAML.CLIB", "ruamel-yaml-clib", "dotted and uppercased"),
    ):
        check(f"PEP 503 equivalent accepted ({label})",
              equivalent(lock_name, manifest_name), "accepted")

    # Inversion: normalisation must not collapse genuinely different names.
    for lock_name, manifest_name, label in (
        ("target", "targets", "different name"),
        ("a-b", "ab", "separator is not nothing"),
    ):
        check(f"genuinely different name rejected ({label})",
              equivalent(lock_name, manifest_name), "rejected")


def main() -> None:
    test_npm_classification()
    test_uv_classification()
    test_npm_source_refs()
    test_npm_nested_git_identities()
    test_uv_same_name_two_versions()
    test_npm_artifact_union()
    test_ambiguous_lock_fails_closed()
    test_npm_artifacts()
    test_nested_npm_lockfile()
    test_coverage_truth_table()
    test_coverage_source_paths()
    test_guards()
    test_audit_detects()
    test_requirements_manifest_fails_closed()

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("all invariants hold")


if __name__ == "__main__":
    main()
