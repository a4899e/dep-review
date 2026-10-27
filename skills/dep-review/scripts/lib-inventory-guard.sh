# shellcheck shell=bash
# Shared completeness guard for anything that reports over repo_deps or
# repo_dep_artifacts.
#
# backfill-repo-deps.py deletes and re-inserts per (repo, ecosystem), and it
# deletes only after a successful parse. A skipped pair therefore leaves either
# stale rows from an older revision or no rows at all, and the tables alone
# cannot distinguish either from a clean result -- an absent group simply does
# not appear. Reporting over that mixture produces a plausible number describing
# no single revision.
#
# This lived inline in query-coverage.sh. It is a file because the guard drifting
# between two reports is exactly the failure it exists to prevent: the first
# artifact-gap report shipped without it and would happily have printed a
# worklist from a mixed-revision inventory that query-coverage.sh refuses.
#
# Usage:  source "$(dirname "$0")/lib-inventory-guard.sh"; require_complete_inventory "$DB"

require_complete_inventory() {
    local db="$1"
    local latest status

    # Ordered by run_id, not run_at. run_at has second resolution, so two runs in
    # the same second tie and SQLite then picks by index order -- which is `ref`
    # collation, not run order. That fails OPEN: an earlier complete manifest can
    # win over a later incomplete one that already changed the tables.
    latest=$(sqlite3 "$db" "SELECT run_at || '|' || ref || '|' || status || '|' || completed_pairs || '/' || expected_pairs || '|' || skipped FROM inventory_runs ORDER BY run_id DESC LIMIT 1;")
    if [ -z "$latest" ]; then
        echo "REFUSING: no inventory run recorded. Run backfill-repo-deps.py first." >&2
        exit 1
    fi

    status=$(printf '%s' "$latest" | cut -d'|' -f3)
    if [ "$status" != "complete" ]; then
        echo "REFUSING: the last inventory run was incomplete." >&2
        echo "  run_at : $(printf '%s' "$latest" | cut -d'|' -f1)" >&2
        echo "  ref    : $(printf '%s' "$latest" | cut -d'|' -f2)" >&2
        echo "  done   : $(printf '%s' "$latest" | cut -d'|' -f4) repo/ecosystem pairs" >&2
        echo "  skipped: $(printf '%s' "$latest" | cut -d'|' -f5)" >&2
        echo >&2
        echo "A report over the surviving groups would read as a complete result." >&2
        echo "Make the skipped repos available, or remove them from repos.json, then re-run." >&2
        exit 1
    fi
}
