#!/usr/bin/env bash
# Find packages used at multiple versions across our repos.
# Useful for planning unified upgrades.
#
# Usage:
#   query-mismatches.sh                  # all ecosystems
#   query-mismatches.sh npm              # npm only
#   query-mismatches.sh pypi             # pypi only
#   query-mismatches.sh pypi boto3       # detail for one package
set -euo pipefail

# shellcheck source=scripts/lib-db.sh
source "$(cd "$(dirname "$0")" && pwd)/lib-db.sh"
DB="$(dep_review_db)"

# Same completeness guard as every other report over repo_deps: a version-mismatch report cannot see a mismatch in a repo it skipped.
# shellcheck source=scripts/lib-inventory-guard.sh
source "$(cd "$(dirname "$0")" && pwd)/lib-inventory-guard.sh"
require_complete_inventory "$DB"
ECOSYSTEM="${1:-}"
PACKAGE="${2:-}"

if [ -n "$PACKAGE" ]; then
    sqlite3 -header -column "$DB" <<SQL
SELECT version, repo, CASE is_direct WHEN 1 THEN 'direct' ELSE 'transitive' END AS kind, dep_type
FROM repo_deps
WHERE ecosystem = '${ECOSYSTEM}' AND package = '${PACKAGE}'
ORDER BY version DESC, repo;
SQL
    exit 0
fi

WHERE=""
if [ -n "$ECOSYSTEM" ]; then
    WHERE="WHERE ecosystem = '${ECOSYSTEM}'"
fi

sqlite3 -header -column "$DB" <<SQL
SELECT
    ecosystem,
    package,
    COUNT(DISTINCT version) AS versions,
    COUNT(DISTINCT repo)    AS repos,
    GROUP_CONCAT(DISTINCT version) AS version_list
FROM repo_deps
${WHERE}
GROUP BY ecosystem, package
HAVING versions > 1
ORDER BY versions DESC, repos DESC, package;
SQL
