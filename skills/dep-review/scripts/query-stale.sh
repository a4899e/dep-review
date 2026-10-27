#!/usr/bin/env bash
# Show tracked packages whose current repo version has not been reviewed.
# Usage: query-stale.sh [repo-name]
set -euo pipefail

# shellcheck source=scripts/lib-db.sh
source "$(cd "$(dirname "$0")" && pwd)/lib-db.sh"
DB="$(dep_review_db)"

# Same completeness guard as every other report over repo_deps: a stale-version report over a partial inventory understates what is stale.
# shellcheck source=scripts/lib-inventory-guard.sh
source "$(cd "$(dirname "$0")" && pwd)/lib-inventory-guard.sh"
require_complete_inventory "$DB"

REPO_FILTER=""
if [ "$#" -gt 0 ]; then
    quoted=""
    for repo in "$@"; do
        repo=${repo//\'/\'\'}
        if [ -n "$quoted" ]; then
            quoted+=", "
        fi
        quoted+="'${repo}'"
    done
    REPO_FILTER="AND d.repo IN (${quoted})"
fi

sqlite3 -header -column "$DB" <<SQL
SELECT
    d.ecosystem,
    d.package,
    d.version AS lock_version,
    COALESCE(
        (
            SELECT r.version
            FROM reviews r
            WHERE r.ecosystem = d.ecosystem
              AND r.package = d.package
              AND r.verdict = 'pass'
            ORDER BY r.reviewed_at DESC
            LIMIT 1
        ),
        '(not reviewed)'
    ) AS reviewed_version,
    d.repo,
    CASE d.is_direct WHEN 1 THEN 'direct' ELSE 'transitive' END AS kind,
    COALESCE(d.dep_type, '-') AS dep_type
FROM repo_deps d
LEFT JOIN reviews exact
  ON exact.ecosystem = d.ecosystem
 AND exact.package = d.package
 AND exact.version = d.version
 AND exact.verdict = 'pass'
WHERE exact.package IS NULL
${REPO_FILTER}
ORDER BY d.ecosystem, d.repo, d.is_direct DESC, d.package, d.version;
SQL
