#!/usr/bin/env bash
# Report reviews that exist only in the working copy.
#
# Only meaningful when the database is tracked in a git repo -- the setup for
# sharing reviews with a team. Exits 2 when it is not.
#
# A review that is not committed is not evidence. A checkout or a lost tree
# destroys it, and the next session's DB query reports the package as
# unreviewed and re-does the work.
#
# Because the database is a binary SQLite file, `git status` tells you only that
# it changed, never what changed. This says what changed.
#
# Compares against HEAD by default, so it answers exactly one question: is the
# working copy committed? That is what a session-completion hook needs. It goes
# green the moment you commit, and stays green on a branch with an open PR --
# a gate that kept failing until merge would just get disabled.
#
# Pass a base ref to ask the other question -- which rows are not yet in that
# ref -- e.g. `check-uncommitted.sh origin/main` before a release.
#
# Exit: 0 clean, 1 rows differ from the base, 2 the check could not be run.
#
# Usage: check-uncommitted.sh [base-ref]   (default: HEAD)

set -euo pipefail

# shellcheck source=scripts/lib-db.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-db.sh"
DB="${DEP_REVIEW_DB:-${REVIEWS_DB:-$(dep_review_home)/reviews.db}}"
BASE_REF="${1:-HEAD}"

[[ -f "$DB" ]] || { echo "no review database at $DB"; exit 2; }
DB="$(cd "$(dirname "$DB")" && pwd)/$(basename "$DB")"
REPO_ROOT="$(git -C "$(dirname "$DB")" rev-parse --show-toplevel 2>/dev/null)" \
    || { echo "$DB is not inside a git repo; nothing to compare against"; exit 2; }
REPO_ROOT="$(cd "$REPO_ROOT" && pwd -P)"
DB_REAL="$(cd "$(dirname "$DB")" && pwd -P)/$(basename "$DB")"
DB_REL="${DB_REAL#"$REPO_ROOT"/}"

cd "$REPO_ROOT"

# A remote-tracking base is only meaningful if it is current. Comparing against
# a stale one is how a branch ends up carrying already-merged commits -- which,
# on a binary file, becomes a conflict that cannot be resolved by choosing a
# side without losing rows. So a failed fetch is a failed check, not a warning:
# certifying "current" off a cached ref is the exact error this guards against.
if git rev-parse --verify --quiet "refs/remotes/${BASE_REF}" >/dev/null; then
    REMOTE="${BASE_REF%%/*}"
    git fetch --quiet "$REMOTE" || {
        echo "could not fetch ${REMOTE}; ${BASE_REF} may be stale and was not trusted" >&2
        exit 2
    }
fi

BASE_DB="$(mktemp -t reviews-base.XXXXXX.db)"
trap 'rm -f "$BASE_DB"' EXIT

if ! git show "${BASE_REF}:${DB_REL}" > "$BASE_DB" 2>/dev/null; then
    echo "could not read ${DB_REL} at ${BASE_REF}"
    exit 2
fi

sqlite3 "$DB" "PRAGMA integrity_check;" | grep -q '^ok$' \
    || { echo "FAIL: integrity_check on the working copy did not return ok"; exit 2; }

# Not `read` -- it is unreliable inside command substitution on macOS.
count() { sqlite3 "$DB" "ATTACH '${BASE_DB}' AS b; $1"; }

KEY="b.ecosystem=r.ecosystem AND b.package=r.package AND b.version=r.version"

ADDED=$(count "SELECT COUNT(*) FROM reviews r
  WHERE NOT EXISTS (SELECT 1 FROM b.reviews b WHERE ${KEY});")
REMOVED=$(count "SELECT COUNT(*) FROM b.reviews b
  WHERE NOT EXISTS (SELECT 1 FROM reviews r WHERE ${KEY});")

# Every non-key column, not just the verdict. reviewed_at and reviewer are the
# audit evidence -- who checked this artifact and when -- so a change to either
# is exactly as material as a flipped verdict, and just as invisible in a
# binary diff.
MODIFIED=$(count "SELECT COUNT(*) FROM reviews r JOIN b.reviews b ON ${KEY}
  WHERE r.sha256      IS NOT b.sha256
     OR r.verdict     IS NOT b.verdict
     OR r.notes       IS NOT b.notes
     OR r.reviewed_at IS NOT b.reviewed_at
     OR r.reviewer    IS NOT b.reviewer;")

if [[ "$BASE_REF" == "HEAD" ]]; then
    NOUN="uncommitted"
    NEXT="Commit ${DB_REL} and open a PR. State the net row count in the title;
do not claim coverage percentages unless repo_deps was refreshed too."
else
    NOUN="not in ${BASE_REF}"
    NEXT="These rows are committed but absent from ${BASE_REF}. Open a PR, or
land the one that carries them."
fi

echo "working copy vs ${BASE_REF}:"
echo "  added:    ${ADDED}"
echo "  removed:  ${REMOVED}"
echo "  modified: ${MODIFIED}"

# review_artifacts carries the same kind of evidence as reviews -- which blob
# was inspected, by whom, when -- and is just as unreadable in a binary diff. A
# check that watched only `reviews` would let an artifact verdict be added,
# flipped, or deleted with the summary still reporting "clean". The table may
# not exist yet in an older base, which is not a discrepancy.
AKEY="b.ecosystem=r.ecosystem AND b.package=r.package AND b.version=r.version AND b.artifact_id=r.artifact_id"
HAS_A=$(sqlite3 "$DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='review_artifacts';")
HAS_A_BASE=$(sqlite3 "$BASE_DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='review_artifacts';")

A_ADDED=0; A_REMOVED=0; A_MODIFIED=0
if [[ "$HAS_A" == "1" && "$HAS_A_BASE" == "1" ]]; then
    A_ADDED=$(count "SELECT COUNT(*) FROM review_artifacts r
      WHERE NOT EXISTS (SELECT 1 FROM b.review_artifacts b WHERE ${AKEY});")
    A_REMOVED=$(count "SELECT COUNT(*) FROM b.review_artifacts b
      WHERE NOT EXISTS (SELECT 1 FROM review_artifacts r WHERE ${AKEY});")
    # EVERY non-key column. artifact_name and artifact_kind included: relabelling
    # a wheel as an sdist rewrites what the row claims was inspected, and is as
    # invisible in a binary diff as a flipped verdict.
    A_MODIFIED=$(count "SELECT COUNT(*) FROM review_artifacts r JOIN b.review_artifacts b ON ${AKEY}
      WHERE r.artifact_name IS NOT b.artifact_name
         OR r.artifact_kind IS NOT b.artifact_kind
         OR r.source_read   IS NOT b.source_read
         OR r.verdict       IS NOT b.verdict
         OR r.notes         IS NOT b.notes
         OR r.reviewed_at   IS NOT b.reviewed_at
         OR r.reviewer      IS NOT b.reviewer;")
elif [[ "$HAS_A" == "1" && "$HAS_A_BASE" == "0" ]]; then
    A_ADDED=$(sqlite3 "$DB" "SELECT COUNT(*) FROM review_artifacts;")
# The inverse: the table is gone from the working copy. Every base row is
# lost evidence, not "no change".
elif [[ "$HAS_A" == "0" && "$HAS_A_BASE" == "1" ]]; then
    A_REMOVED=$(sqlite3 "$BASE_DB" "SELECT COUNT(*) FROM review_artifacts;")
    [[ "$A_REMOVED" == "0" ]] && A_REMOVED=1  # dropping the table is itself a removal
fi

echo "  artifact rows added:    ${A_ADDED}"
echo "  artifact rows removed:  ${A_REMOVED}"
echo "  artifact rows modified: ${A_MODIFIED}"

# repo_dep_artifacts is inventory, not evidence, but it is now half of the
# coverage decision: changing which artifact IDs a dependency admits changes
# whether that dependency is covered, with no review row touched. A silent edit
# here can manufacture coverage just as effectively as a forged verdict.
IKEY="b.repo=r.repo AND b.ecosystem=r.ecosystem AND b.package=r.package AND b.version=r.version AND b.artifact_id=r.artifact_id"
HAS_I=$(sqlite3 "$DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='repo_dep_artifacts';")
HAS_I_BASE=$(sqlite3 "$BASE_DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='repo_dep_artifacts';")

I_ADDED=0; I_REMOVED=0; I_MODIFIED=0
if [[ "$HAS_I" == "1" && "$HAS_I_BASE" == "1" ]]; then
    I_ADDED=$(count "SELECT COUNT(*) FROM repo_dep_artifacts r
      WHERE NOT EXISTS (SELECT 1 FROM b.repo_dep_artifacts b WHERE ${IKEY});")
    I_REMOVED=$(count "SELECT COUNT(*) FROM b.repo_dep_artifacts b
      WHERE NOT EXISTS (SELECT 1 FROM repo_dep_artifacts r WHERE ${IKEY});")
    I_MODIFIED=$(count "SELECT COUNT(*) FROM repo_dep_artifacts r JOIN b.repo_dep_artifacts b ON ${IKEY}
      WHERE r.artifact_name IS NOT b.artifact_name
         OR r.artifact_kind IS NOT b.artifact_kind;")
elif [[ "$HAS_I" == "1" && "$HAS_I_BASE" == "0" ]]; then
    I_ADDED=$(sqlite3 "$DB" "SELECT COUNT(*) FROM repo_dep_artifacts;")
elif [[ "$HAS_I" == "0" && "$HAS_I_BASE" == "1" ]]; then
    I_REMOVED=$(sqlite3 "$BASE_DB" "SELECT COUNT(*) FROM repo_dep_artifacts;")
    [[ "$I_REMOVED" == "0" ]] && I_REMOVED=1
fi

echo "  inventory rows added:    ${I_ADDED}"
echo "  inventory rows removed:  ${I_REMOVED}"
echo "  inventory rows modified: ${I_MODIFIED}"

# fail_resolutions clears a fail veto, and a new fail_events row voids the
# resolution before it, so either can change what is authorised with no review
# row touched. Both are append-only: rows are compared whole, so any difference
# is an addition or a removal. A table, or column set, that differs from the
# base counts every row on both sides.
append_only_diff() {  # table -> "added removed"
    local t="$1" has has_base cols cols_base key
    has=$(sqlite3 "$DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='$t';")
    has_base=$(sqlite3 "$BASE_DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='$t';")
    cols=$(sqlite3 "$DB" "SELECT group_concat(name) FROM (SELECT name FROM pragma_table_info('$t') ORDER BY name);")
    cols_base=$(sqlite3 "$BASE_DB" "SELECT group_concat(name) FROM (SELECT name FROM pragma_table_info('$t') ORDER BY name);")
    if [[ "$has" == "1" && "$has_base" == "1" && "$cols" == "$cols_base" ]]; then
        key=$(sqlite3 "$DB" "SELECT group_concat('b.'||name||' IS r.'||name, ' AND ') FROM pragma_table_info('$t');")
        echo "$(count "SELECT COUNT(*) FROM $t r WHERE NOT EXISTS (SELECT 1 FROM b.$t b WHERE $key);") \
$(count "SELECT COUNT(*) FROM b.$t b WHERE NOT EXISTS (SELECT 1 FROM $t r WHERE $key);")"
        return
    fi
    local added=0 removed=0
    [[ "$has" == "1" ]] && added=$(sqlite3 "$DB" "SELECT COUNT(*) FROM $t;")
    if [[ "$has_base" == "1" ]]; then
        removed=$(sqlite3 "$BASE_DB" "SELECT COUNT(*) FROM $t;")
        [[ "$has" != "1" && "$removed" == "0" ]] && removed=1
    fi
    echo "$added $removed"
}
F_PAIR=$(append_only_diff fail_resolutions); F_ADDED=${F_PAIR% *}; F_REMOVED=${F_PAIR#* }
E_PAIR=$(append_only_diff fail_events); E_ADDED=${E_PAIR% *}; E_REMOVED=${E_PAIR#* }
echo "  failure resolutions added:   ${F_ADDED}"
echo "  failure resolutions removed: ${F_REMOVED}"
echo "  fail events added:           ${E_ADDED}"
echo "  fail events removed:         ${E_REMOVED}"

# repo_deps decides WHICH dependencies are checked and which are exempt.
# source_kind='local' removes a row from both the denominator and the gate, and
# source_ref is the whole of git-pinned identity, so an edit here changes the
# gate's answer without touching a single evidence row. Regenerable from
# lockfiles, but so is repo_dep_artifacts, and consequence -- not provenance --
# is what decides whether a field needs auditing.
DKEY="b.repo=r.repo AND b.ecosystem=r.ecosystem AND b.package=r.package AND b.version=r.version"
HAS_SK=$(sqlite3 "$DB" "SELECT COUNT(*) FROM pragma_table_info('repo_deps') WHERE name='source_kind';")
HAS_SK_BASE=$(sqlite3 "$BASE_DB" "SELECT COUNT(*) FROM pragma_table_info('repo_deps') WHERE name='source_kind';")

# A base predating source_kind cannot be compared on it. Selecting NULL keeps
# the other fields comparable instead of skipping repo_deps altogether, which
# would leave the table unaudited for exactly the commit that introduced it.
if [[ "$HAS_SK_BASE" == "1" ]]; then BASE_SK="b.source_kind"; else BASE_SK="NULL"; fi
if [[ "$HAS_SK" == "1" ]]; then CUR_SK="r.source_kind"; else CUR_SK="NULL"; fi

D_ADDED=$(count "SELECT COUNT(*) FROM repo_deps r
  WHERE NOT EXISTS (SELECT 1 FROM b.repo_deps b WHERE ${DKEY});")
D_REMOVED=$(count "SELECT COUNT(*) FROM b.repo_deps b
  WHERE NOT EXISTS (SELECT 1 FROM repo_deps r WHERE ${DKEY});")
D_MODIFIED=$(count "SELECT COUNT(*) FROM repo_deps r JOIN b.repo_deps b ON ${DKEY}
  WHERE r.is_direct    IS NOT b.is_direct
     OR r.dep_type     IS NOT b.dep_type
     OR r.snapshot_ref IS NOT b.snapshot_ref
     OR r.source_ref   IS NOT b.source_ref
     OR ${CUR_SK}      IS NOT ${BASE_SK};")

# inventory_runs decides whether ANY report is allowed to run: every guarded
# script reads the latest row and refuses unless status='complete'. A row
# inserted or edited here re-enables reporting over a mixed-revision inventory,
# so it is load-bearing even though it looks like a log.
R_ADDED=$(count "SELECT COUNT(*) FROM inventory_runs r
  WHERE NOT EXISTS (SELECT 1 FROM b.inventory_runs b WHERE b.run_id=r.run_id);")
R_REMOVED=$(count "SELECT COUNT(*) FROM b.inventory_runs b
  WHERE NOT EXISTS (SELECT 1 FROM inventory_runs r WHERE r.run_id=b.run_id);")
R_MODIFIED=$(count "SELECT COUNT(*) FROM inventory_runs r JOIN b.inventory_runs b ON b.run_id=r.run_id
  WHERE r.run_at IS NOT b.run_at OR r.ref IS NOT b.ref OR r.status IS NOT b.status
     OR r.expected_pairs IS NOT b.expected_pairs
     OR r.completed_pairs IS NOT b.completed_pairs OR r.skipped IS NOT b.skipped;")

# An ADDED run is not noise. Every guarded report trusts the LATEST row, so
# appending is the primary way the effective guard state changes: append an
# incomplete run and every report starts refusing; append a complete one after a
# committed incomplete run and reporting resumes over inventory tables that never
# moved, which is the mixed-revision guard being walked straight past. Treating
# additions as timestamp noise -- which this script did -- made the audit certify
# exactly that transition as "nothing security-relevant moved".
echo "  inventory runs added:     ${R_ADDED}"
echo "  inventory runs modified:  ${R_MODIFIED} (removed: ${R_REMOVED})"

# Report the effective guard state directly, not only row deltas. This is what
# the reports actually consult, and it is what a reader needs to see flip.
latest_state() {
    sqlite3 "$1" "SELECT COALESCE((SELECT status || ' @ ' || substr(ref,1,8) FROM inventory_runs ORDER BY run_id DESC LIMIT 1), 'none');"
}
GUARD_NOW=$(latest_state "$DB")
GUARD_BASE=$(latest_state "$BASE_DB")
if [[ "$GUARD_NOW" != "$GUARD_BASE" ]]; then
    echo "  effective guard state:    ${GUARD_BASE} -> ${GUARD_NOW}  (CHANGED)"
else
    echo "  effective guard state:    ${GUARD_NOW}"
fi

echo "  dependency rows added:    ${D_ADDED}"
echo "  dependency rows removed:  ${D_REMOVED}"
echo "  dependency rows modified: ${D_MODIFIED}"

if [[ "$ADDED" -eq 0 && "$REMOVED" -eq 0 && "$MODIFIED" -eq 0 \
   && "$A_ADDED" -eq 0 && "$A_REMOVED" -eq 0 && "$A_MODIFIED" -eq 0 \
   && "$I_ADDED" -eq 0 && "$I_REMOVED" -eq 0 && "$I_MODIFIED" -eq 0 \
   && "$F_ADDED" -eq 0 && "$F_REMOVED" -eq 0 \
   && "$E_ADDED" -eq 0 && "$E_REMOVED" -eq 0 \
   && "$D_ADDED" -eq 0 && "$D_REMOVED" -eq 0 && "$D_MODIFIED" -eq 0 \
   && "$R_ADDED" -eq 0 && "$R_REMOVED" -eq 0 && "$R_MODIFIED" -eq 0 \
   && "$GUARD_NOW" == "$GUARD_BASE" ]]; then
    # The audited fields are unchanged, but the file may still differ -- a new
    # inventory_runs row and refreshed snapshot_at timestamps land on every
    # backfill. Say so, because "clean" read as "the file is unchanged" would
    # send someone to `git checkout` a database that legitimately moved.
    if ! cmp -s "$DB" "$BASE_DB"; then
        echo "clean: no audited field changed."
        echo "The file still differs from ${BASE_REF} in non-audited data --"
        echo "normally an inventory_runs row and snapshot_at timestamps from a"
        echo "backfill. Commit it or discard it; nothing security-relevant moved."
        exit 0
    fi
    echo "clean."
    exit 0
fi

if [[ "$ADDED" -gt 0 ]]; then
    echo
    echo "${NOUN} reviews by ecosystem:"
    sqlite3 "$DB" "
    ATTACH '${BASE_DB}' AS b;
    SELECT '  '||r.ecosystem||': '||COUNT(*) FROM reviews r
      WHERE NOT EXISTS (SELECT 1 FROM b.reviews b WHERE ${KEY})
    GROUP BY r.ecosystem;"
fi

# Removed or modified rows are the ones worth stopping over: this database is
# append-mostly, so either usually means a stale base or an overwritten verdict
# rather than intended work.
if [[ "$REMOVED" -gt 0 || "$MODIFIED" -gt 0 ]]; then
    echo
    echo "WARNING: rows were removed or modified, not just added."
    echo "This database is append-mostly. Check the base ref is current and that"
    echo "no existing review was overwritten before committing."
fi

echo
echo "$NEXT"
exit 1
