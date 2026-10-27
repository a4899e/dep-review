# shellcheck shell=bash
# Resolve the review database and make sure its schema exists.
#
# Location, first match wins:
#   $DEP_REVIEW_DB                      explicit file path
#   $REVIEWS_DB                         legacy name, still honoured
#   $DEP_REVIEW_HOME/reviews.db         default home: ${XDG_DATA_HOME:-~/.local/share}/dep-review
#
# The schema is applied with CREATE ... IF NOT EXISTS, so pointing at an
# existing database reuses every review already in it, and pointing at a new
# path creates an empty one.
#
# Usage:  source "$(dirname "$0")/lib-db.sh"; DB=$(dep_review_db)

dep_review_home() {
    printf '%s\n' "${DEP_REVIEW_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/dep-review}"
}

dep_review_db() {
    local db="${DEP_REVIEW_DB:-${REVIEWS_DB:-$(dep_review_home)/reviews.db}}"
    local schema
    schema="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/schema.sql"
    mkdir -p "$(dirname "$db")"
    sqlite3 "$db" < "$schema" || { echo "could not apply schema to $db" >&2; return 2; }
    printf '%s\n' "$db"
}
