#!/usr/bin/env bash
# Show, per package version, how many of the artifacts a lockfile admits have
# actually been reviewed.
#
# query-coverage.sh is the gate: it fails when a dependency holds a version-level
# pass its artifacts do not support. This is the worklist for clearing that --
# of the specific blobs each locked version can install, how many did anyone
# actually look at?
#
# admitted and reviewed diverge whenever a release publishes more than one
# artifact. A package shipping native wheels publishes one per platform
# (charset-normalizer 3.5.1 publishes 171), and before artifact identity a
# review earned on any one of them authorised all of them. Rows with
# reviewed < admitted are the releases where that happened.
#
# Ordered by how much is unreviewed, so the worst over-claims come first.
#
# Usage: query-artifact-gap.sh [--covered] [LIMIT]
#   --covered  also list versions where every artifact is reviewed
set -euo pipefail

# shellcheck source=scripts/lib-db.sh
source "$(cd "$(dirname "$0")" && pwd)/lib-db.sh"
DB="$(dep_review_db)"

# Same completeness guard as query-coverage.sh. Without it this script would
# print a plausible worklist and totals from a mixed-revision inventory that
# query-coverage.sh refuses outright -- two reports over the same tables
# disagreeing about whether the data is reportable.
# shellcheck source=scripts/lib-inventory-guard.sh
source "$(cd "$(dirname "$0")" && pwd)/lib-inventory-guard.sh"
require_complete_inventory "$DB"

SHOW_COVERED=0
LIMIT=40
for arg in "$@"; do
    case "$arg" in
        --covered) SHOW_COVERED=1 ;;
        *) LIMIT="$arg" ;;
    esac
done

if [ "$(sqlite3 "$DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='repo_dep_artifacts';")" != "1" ]; then
    echo "REFUSING: repo_dep_artifacts does not exist." >&2
    echo "The database predates schema.sql; re-run any script to apply it. then backfill-repo-deps.py." >&2
    exit 1
fi

if [ "$(sqlite3 "$DB" "SELECT COUNT(*) FROM repo_dep_artifacts;")" = "0" ]; then
    echo "REFUSING: no artifact inventory recorded." >&2
    echo "Run backfill-repo-deps.py to populate repo_dep_artifacts." >&2
    exit 1
fi

HAVING="HAVING reviewed < admitted"
[ "$SHOW_COVERED" = "1" ] && HAVING=""

sqlite3 -header -column "$DB" <<SQL
SELECT
    a.ecosystem,
    a.package,
    a.version,
    COUNT(DISTINCT a.artifact_id) AS admitted,
    COUNT(DISTINCT CASE WHEN ra.artifact_id IS NOT NULL THEN a.artifact_id END) AS reviewed,
    COALESCE(v.verdict, '-') AS version_verdict,
    (SELECT COUNT(DISTINCT repo) FROM repo_dep_artifacts x
      WHERE x.ecosystem=a.ecosystem AND x.package=a.package AND x.version=a.version) AS repos
FROM repo_dep_artifacts a
LEFT JOIN review_artifacts ra
       ON ra.ecosystem = a.ecosystem AND ra.package = a.package
      AND ra.version = a.version AND ra.artifact_id = a.artifact_id
      AND ra.verdict = 'pass'
LEFT JOIN reviews v
       ON v.ecosystem = a.ecosystem AND v.package = a.package AND v.version = a.version
GROUP BY a.ecosystem, a.package, a.version
${HAVING}
ORDER BY (admitted - reviewed) DESC, a.package
LIMIT ${LIMIT};
SQL

echo
TOTAL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM (SELECT 1 FROM repo_dep_artifacts GROUP BY ecosystem,package,version);")
GAP=$(sqlite3 "$DB" "
SELECT COUNT(*) FROM (
  SELECT 1 FROM repo_dep_artifacts a
  LEFT JOIN review_artifacts ra
         ON ra.ecosystem=a.ecosystem AND ra.package=a.package
        AND ra.version=a.version AND ra.artifact_id=a.artifact_id AND ra.verdict='pass'
  GROUP BY a.ecosystem,a.package,a.version
  HAVING COUNT(DISTINCT CASE WHEN ra.artifact_id IS NOT NULL THEN a.artifact_id END)
       < COUNT(DISTINCT a.artifact_id));")
echo "${GAP} of ${TOTAL} locked package versions have at least one unreviewed artifact."

# A version_verdict of 'pass' on a row with reviewed < admitted is what
# query-coverage.sh now fails on: a review authorising bytes nobody inspected.
# This count and the gate's are the same population, so they should move
# together -- if they ever disagree, one of the two queries is wrong.
OVERCLAIM=$(sqlite3 "$DB" "
SELECT COUNT(*) FROM (
  SELECT 1 FROM repo_dep_artifacts a
  JOIN reviews v ON v.ecosystem=a.ecosystem AND v.package=a.package
                AND v.version=a.version AND v.verdict='pass'
  LEFT JOIN review_artifacts ra
         ON ra.ecosystem=a.ecosystem AND ra.package=a.package
        AND ra.version=a.version AND ra.artifact_id=a.artifact_id AND ra.verdict='pass'
  GROUP BY a.ecosystem,a.package,a.version
  HAVING COUNT(DISTINCT CASE WHEN ra.artifact_id IS NOT NULL THEN a.artifact_id END)
       < COUNT(DISTINCT a.artifact_id));")
echo "${OVERCLAIM} of those carry a version-level 'pass' over artifacts nobody"
echo "inspected. query-coverage.sh fails while that count is above zero."

# Git-pinned dependencies have no repo_dep_artifacts rows -- their identity is a
# commit, not a published artifact -- so everything above is blind to them. The
# gate rejects a commit mismatch but used to point only at the artifact
# worklist, leaving the operator with a failure and no row explaining it.
echo
echo "Source-identity failures (git-pinned; identity is the commit, not the version):"
sqlite3 -header -column "$DB" <<SQL
SELECT
    d.repo,
    d.package,
    d.version,
    substr(d.source_ref, 1, 10) AS locked_commit,
    COALESCE((SELECT substr(r.sha256, 1, 10) FROM reviews r
               WHERE r.ecosystem=d.ecosystem AND r.package=d.package
                 AND r.version=d.version AND r.verdict='pass'), 'NO REVIEW') AS reviewed_commit
FROM repo_deps d
WHERE d.source_kind = 'git'
  AND NOT EXISTS (SELECT 1 FROM reviews r
                   WHERE r.ecosystem=d.ecosystem AND r.package=d.package
                     AND r.version=d.version AND r.verdict='pass'
                     AND r.sha256 = d.source_ref)
ORDER BY d.repo;
SQL

GITFAIL=$(sqlite3 "$DB" "
SELECT COUNT(*) FROM repo_deps d
 WHERE d.source_kind='git'
   AND NOT EXISTS (SELECT 1 FROM reviews r
                    WHERE r.ecosystem=d.ecosystem AND r.package=d.package
                      AND r.version=d.version AND r.verdict='pass'
                      AND r.sha256 = d.source_ref);")
if [ "$GITFAIL" = "0" ]; then
    echo "  (none)"
else
    echo
    echo "${GITFAIL} git-pinned dependency(ies) run a commit no passing review names."
    echo "Two commits can declare the same version, so the version string alone"
    echo "cannot authorise these. Review the locked commit."
fi
