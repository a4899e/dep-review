#!/usr/bin/env bash
# Show review coverage for each tracked repo/ecosystem inventory.
#
# Coverage is reported against the revision recorded in repo_deps.snapshot_ref,
# not against whatever is checked out. Run backfill-repo-deps.py first.
#
# COVERAGE IS ARTIFACT-AUTHORITATIVE. A dependency counts as covered only when
# every artifact it can actually install has a passing review. This used to be a
# version-level question -- does (ecosystem, package, version) have a passing
# `reviews` row -- which cannot distinguish "we read these bytes" from "we read
# some bytes published under this version number". For a release publishing many
# platform wheels those are very different claims: charset-normalizer 3.5.1
# publishes 171 wheels, and a review earned on one authorised all of them.
#
# Three ways a dependency can be covered, matching the three ways one can be
# sourced:
#
#   registry    a version-level review that is not a fail, AND every artifact in
#               repo_dep_artifacts has a passing review_artifacts row
#   git-pinned  source_ref is set, and a passing review names that same commit
#               in its sha256 -- identity is the commit, not the version string
#   local       the workspace's own package, as RECORDED in repo_deps.source_kind
#               from the lockfile. Never inferred from missing data: a remote
#               dependency whose artifact identity failed to extract also has no
#               artifact rows, and treating that shape as local exempted it from
#               the gate. Unrecognised source kinds record as registry so the
#               unknown case fails closed.
#
# An explicit version-level `fail` vetoes coverage under every path. Artifact
# rows say individual blobs looked clean; a fail is a judgement about the
# release, and complete artifact evidence must not outvote it. `partial` is
# accepted on the registry path only, where it means "some artifacts unreviewed"
# -- a question complete artifact rows have since answered.
#
# The script EXITS NON-ZERO when a dependency holds a version-level pass but is
# not artifact-covered. That state is the false authorization this whole
# mechanism exists to prevent, so it has to fail rather than annotate: a gate
# that reports a problem and exits 0 is one that callers keep passing.
#
# Usage: query-coverage.sh
set -euo pipefail

# shellcheck source=scripts/lib-db.sh
source "$(cd "$(dirname "$0")" && pwd)/lib-db.sh"
DB="$(dep_review_db)"

# shellcheck source=scripts/lib-inventory-guard.sh
source "$(cd "$(dirname "$0")" && pwd)/lib-inventory-guard.sh"
require_complete_inventory "$DB"

# A NULL source_kind is an inventory predating the column. Coverage treats it as
# uncovered, which is the safe direction, but it is invisible in the no_artifact
# column and would read as ordinary unreviewed work. Refuse rather than report a
# number whose shape nobody can see.
NULL_KIND=$(sqlite3 "$DB" "SELECT COUNT(*) FROM repo_deps WHERE source_kind IS NULL;")
if [ "$NULL_KIND" != "0" ]; then
    echo "REFUSING: ${NULL_KIND} repo_deps row(s) have no source_kind." >&2
    echo "That inventory predates the column, so local/git/registry cannot be" >&2
    echo "told apart. Re-run backfill-repo-deps.py." >&2
    exit 1
fi

for t in repo_dep_artifacts review_artifacts; do
    if [ "$(sqlite3 "$DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='${t}';")" != "1" ]; then
        echo "REFUSING: ${t} does not exist. The database predates schema.sql; re-run any script to apply it." >&2
        exit 1
    fi
done

# Covered, expressed once and reused, so the table and the gate below cannot
# drift into disagreeing about what the word means.
COVERED_SQL="
    CASE
      -- An explicit version-level fail vetoes everything. Artifact rows record
      -- that individual blobs looked clean; a fail records a judgement about the
      -- release. Letting complete artifact evidence outvote it would mean a
      -- package could be marked malicious and still authorise itself.
      --
      -- REDUNDANT ON PURPOSE, and mutation-tested to confirm it: 'fail' is also
      -- excluded by the registry branch's IN ('pass','partial') and by the git
      -- branch's ='pass'. Removing either mechanism alone leaves behaviour
      -- correct, so a reader can easily mistake this for dead code. Removing
      -- both makes a failed package authorise itself, which is why the second
      -- mechanism stays. test-invariants.py pins the behaviour, not the branch.
      WHEN EXISTS (SELECT 1 FROM reviews r
                    WHERE r.ecosystem=d.ecosystem AND r.package=d.package
                      AND r.version=d.version AND r.verdict='fail') THEN 0
      -- A failing artifact vetoes its whole release, not just itself. A
      -- malicious sdist says the release (or its maintainer) is compromised;
      -- a clean-looking wheel beside it must not stay authorised.
      WHEN EXISTS (SELECT 1 FROM review_artifacts a
                    WHERE a.ecosystem=d.ecosystem AND a.package=d.package
                      AND a.version=d.version AND a.verdict='fail') THEN 0
      WHEN d.source_kind='local' THEN 0
      WHEN d.source_kind='git' THEN
        EXISTS (SELECT 1 FROM reviews r
                 WHERE r.ecosystem=d.ecosystem AND r.package=d.package
                   AND r.version=d.version AND r.verdict='pass'
                   AND r.sha256 = d.source_ref)
      -- Registry. Needs BOTH: a version-level review that is not a fail (that
      -- row is where the source review lives), and complete artifact evidence.
      -- 'partial' is accepted here and only here -- it means some artifacts were
      -- unreviewed, which complete artifact rows have since answered.
      WHEN EXISTS (SELECT 1 FROM repo_dep_artifacts x
                    WHERE x.repo=d.repo AND x.ecosystem=d.ecosystem
                      AND x.package=d.package AND x.version=d.version) THEN
        EXISTS (SELECT 1 FROM reviews r
                 WHERE r.ecosystem=d.ecosystem AND r.package=d.package
                   AND r.version=d.version AND r.verdict IN ('pass','partial'))
        AND NOT EXISTS (
          SELECT 1 FROM repo_dep_artifacts x
           WHERE x.repo=d.repo AND x.ecosystem=d.ecosystem
             AND x.package=d.package AND x.version=d.version
             AND NOT EXISTS (
               SELECT 1 FROM review_artifacts ra
                WHERE ra.ecosystem=x.ecosystem AND ra.package=x.package
                  AND ra.version=x.version AND ra.artifact_id=x.artifact_id
                  AND ra.verdict='pass'))
      -- Remote, but no artifact identity was extracted. Previously this shape
      -- was read as first-party and skipped the gate entirely. It is an
      -- inventory defect, and it reads as uncovered.
      ELSE 0
    END"

# Local is now RECORDED, not inferred. It used to mean "no source_ref and no
# artifact row", which a remote dependency whose artifact extraction failed also
# satisfies -- so an extraction gap silently exempted a real dependency from the
# gate. source_kind comes from the lockfile itself (uv: editable/virtual/
# directory; npm: link:true or a non-URL resolved), and anything unrecognised is
# recorded as registry, so the unknown case fails closed instead of open.
LOCAL_SQL="(d.source_kind = 'local')"

# Remote dependencies carrying no artifact identity. Not a coverage question but
# an inventory one: the lockfile had no integrity value, or the parser missed it.
# Surfaced so it cannot sit quietly at zero coverage looking like unreviewed work.
NO_ARTIFACT_SQL="
    (d.source_kind IN ('registry') AND NOT EXISTS (
        SELECT 1 FROM repo_dep_artifacts x
         WHERE x.repo=d.repo AND x.ecosystem=d.ecosystem
           AND x.package=d.package AND x.version=d.version))"

sqlite3 -header -column "$DB" <<SQL
SELECT
    d.repo,
    d.ecosystem,
    COUNT(*) AS total,
    SUM(CASE WHEN ${LOCAL_SQL} THEN 1 ELSE 0 END) AS local,
    SUM(CASE WHEN ${COVERED_SQL} THEN 1 ELSE 0 END) AS covered,
    printf(
        '%d%%',
        CASE WHEN COUNT(*) - SUM(CASE WHEN ${LOCAL_SQL} THEN 1 ELSE 0 END) = 0 THEN 100
        ELSE 100 * SUM(CASE WHEN ${COVERED_SQL} THEN 1 ELSE 0 END)
             / (COUNT(*) - SUM(CASE WHEN ${LOCAL_SQL} THEN 1 ELSE 0 END)) END
    ) AS coverage,
    -- Dependencies holding a version-level pass that artifact evidence does not
    -- support. Shown so the gap is attributable per repo rather than a single
    -- global number, and so a reviewer can see it shrink.
    SUM(CASE WHEN NOT (${COVERED_SQL}) AND NOT ${LOCAL_SQL} AND EXISTS (
          SELECT 1 FROM reviews r
           WHERE r.ecosystem=d.ecosystem AND r.package=d.package
             AND r.version=d.version AND r.verdict='pass'
        ) THEN 1 ELSE 0 END) AS version_only,
    SUM(CASE WHEN ${NO_ARTIFACT_SQL} THEN 1 ELSE 0 END) AS no_artifact,
    SUM(CASE WHEN d.source_ref IS NOT NULL THEN 1 ELSE 0 END) AS git_pinned,
    COALESCE(substr(MAX(d.snapshot_ref), 1, 8), 'UNPINNED') AS at_ref
FROM repo_deps d
GROUP BY d.repo, d.ecosystem
ORDER BY d.repo, d.ecosystem;
SQL

UNPINNED=$(sqlite3 "$DB" "SELECT COUNT(*) FROM repo_deps WHERE snapshot_ref IS NULL;")
if [ "$UNPINNED" != "0" ]; then
    echo
    echo "WARNING: ${UNPINNED} inventory row(s) have no snapshot_ref."
    echo "Coverage for those is not tied to any revision. Re-run backfill-repo-deps.py."
fi

VERSION_ONLY=$(sqlite3 "$DB" "
SELECT COUNT(*) FROM repo_deps d
 WHERE NOT (${COVERED_SQL}) AND NOT ${LOCAL_SQL}
   AND EXISTS (SELECT 1 FROM reviews r
                WHERE r.ecosystem=d.ecosystem AND r.package=d.package
                  AND r.version=d.version AND r.verdict='pass');")

# Every non-local dependency that is not covered, for any reason. version_only is
# a subset of this: a false authorization. The rest are honest gaps -- no review,
# or a `partial` whose artifacts are still incomplete. The gate fails on the
# whole set, because a gate that exits 0 while coverage is under 100% invites
# the same "reported but not enforced" reading that made artifact_ok advisory.
UNCOVERED=$(sqlite3 "$DB" "
SELECT COUNT(*) FROM repo_deps d
 WHERE NOT (${COVERED_SQL}) AND NOT ${LOCAL_SQL};")

echo
echo "covered      = every artifact this dependency admits has a passing review"
echo "               (git-pinned: a passing review names the same commit)"
echo "local        = first-party workspace package; nothing fetched, excluded"
echo "version_only = has a version-level pass, but the artifacts were not reviewed"
echo "no_artifact  = remote dependency with no artifact identity extracted"
echo "               (an inventory defect, not unreviewed work)"

if [ "$UNCOVERED" != "0" ]; then
    echo
    echo "FAIL: ${UNCOVERED} non-local dependencies are not covered." >&2
    echo "  of which ${VERSION_ONLY} hold a version-level pass their artifacts do not" >&2
    echo "  support -- reviews speaking for bytes nobody inspected, which is the" >&2
    echo "  condition this gate exists to catch." >&2
    echo "  the remainder are honest gaps: no review, or a 'partial' still awaiting" >&2
    echo "  complete artifact evidence." >&2
    echo >&2
    echo "Run query-artifact-gap.sh for the worklist -- it lists both" >&2
    echo "unreviewed artifacts and git-pinned commit mismatches, which have no" >&2
    echo "artifact rows and would otherwise be absent from it." >&2
    exit 1
fi
