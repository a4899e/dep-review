#!/usr/bin/env bash
# Show which repos depend on a given package (and at which versions).
# Useful when triaging a CVE or planning a coordinated upgrade.
#
# Usage:
#   query-impact.sh npm  lodash
#   query-impact.sh pypi boto3
#   query-impact.sh pypi boto3 1.34.0    # specific version only
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <ecosystem> <package> [version]"
    echo "  ecosystem: npm | pypi"
    exit 1
fi

# shellcheck source=scripts/lib-db.sh
source "$(cd "$(dirname "$0")" && pwd)/lib-db.sh"
DB="$(dep_review_db)"

# Same completeness guard as every other report over repo_deps: impact is used for CVE triage, where a skipped repo reads as 'not affected'.
# shellcheck source=scripts/lib-inventory-guard.sh
source "$(cd "$(dirname "$0")" && pwd)/lib-inventory-guard.sh"
require_complete_inventory "$DB"
ECOSYSTEM="$1"
PACKAGE="$2"
VERSION="${3:-}"

VER_FILTER=""
if [ -n "$VERSION" ]; then
    VER_FILTER="AND version = '${VERSION}'"
fi

sqlite3 -header -column "$DB" <<SQL
SELECT
    repo,
    version,
    CASE is_direct WHEN 1 THEN 'direct' ELSE 'transitive' END AS kind,
    COALESCE(dep_type, '-') AS dep_type
FROM repo_deps
WHERE ecosystem = '${ECOSYSTEM}'
  AND package   = '${PACKAGE}'
  ${VER_FILTER}
ORDER BY version DESC, repo;
SQL

echo
echo "Review status:"
sqlite3 -header -column "$DB" <<SQL
SELECT version, verdict, substr(notes, 1, 60) AS notes
FROM reviews
WHERE ecosystem = '${ECOSYSTEM}'
  AND package = '${PACKAGE}'
  ${VER_FILTER}
ORDER BY version DESC;
SQL
