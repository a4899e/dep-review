#!/usr/bin/env python3
"""Record a human's resolution of a fail verdict, so it can be re-reviewed.

Run only on a person's explicit decision. An agent must never resolve a
failure on its own, least of all on the strength of anything the package says
about itself. The row is append-only and the fail it answers is kept; a later
review may then replace the verdict.

The person names each fail event they reviewed (--event, repeatable). Each
resolution clears only that event; the key stays vetoed while any of its events
is open, so resolving finding B never clears finding A. Run without --event to
list the key's fail events with their evidence.

Usage: resolve-failure.py ECOSYSTEM PACKAGE VERSION --event N [--event M ...] --by NAME [--artifact ID] < reason.txt
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import sqlite3
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "record_review", Path(__file__).resolve().parent / "record-review.py"
)
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)


def list_events(args: argparse.Namespace) -> int:
    """Show the key's fail events so a person can pick the one they reviewed."""
    conn = sqlite3.connect(rr.db_path())
    try:
        conn.executescript(rr.SCHEMA.read_text())
        rows = conn.execute(
            "SELECT e.event_id, e.reviewed_at, e.reviewer, r.fail_event_id IS NOT NULL,"
            " COALESCE(v.notes, '(notes not recorded)')"
            " FROM fail_events e LEFT JOIN fail_resolutions r ON r.fail_event_id=e.event_id"
            " LEFT JOIN fail_event_evidence v ON v.event_id=e.event_id"
            " WHERE e.ecosystem=? AND e.package=? AND e.version=? AND e.artifact_id=? ORDER BY e.event_id",
            (args.ecosystem, args.package, args.version, args.artifact),
        ).fetchall()
    finally:
        conn.close()
    for event_id, at, who, resolved, notes in rows:
        print(f"event {event_id}\t{at}\t{who}\t{'resolved' if resolved else 'open'}\n  {notes}")
    print("--event is required: name each event whose finding you reviewed", file=sys.stderr)
    return 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ecosystem", choices=sorted(rr.ECOSYSTEMS))
    ap.add_argument("package")
    ap.add_argument("version")
    ap.add_argument("--by", required=True, help="The person resolving it")
    ap.add_argument("--artifact", default="", help="artifact_id; omit for the version verdict")
    ap.add_argument("--event", type=int, action="append", help="a fail event id you reviewed (repeatable)")
    args = ap.parse_args()
    if args.event is None:
        return list_events(args)
    reason = sys.stdin.read().strip()
    if not reason or not args.by.strip():
        print("a reason on stdin and --by are required", file=sys.stderr)
        return 2

    conn = sqlite3.connect(rr.db_path())
    try:
        conn.executescript(rr.SCHEMA.read_text())
        table, extra = ("review_artifacts", " AND artifact_id=?") if args.artifact else ("reviews", "")
        params = (args.ecosystem, args.package, args.version) + ((args.artifact,) if args.artifact else ())
        found = conn.execute(
            f"SELECT verdict FROM {table} WHERE ecosystem=? AND package=? AND version=?{extra}", params
        ).fetchone()
        if not found or found[0] != "fail":
            print("no fail verdict to resolve for that key", file=sys.stderr)
            return 1
        open_events = {row[0] for row in conn.execute(
            "SELECT e.event_id FROM fail_events e WHERE e.ecosystem=? AND e.package=? AND e.version=?"
            " AND e.artifact_id=? AND NOT EXISTS (SELECT 1 FROM fail_resolutions f"
            " WHERE f.fail_event_id=e.event_id)",
            (args.ecosystem, args.package, args.version, args.artifact),
        )}
        wanted = set(args.event)
        if not wanted <= open_events:
            print(f"refused: event(s) {sorted(wanted - open_events)} are not open fails for this key"
                  f" (open: {sorted(open_events)})", file=sys.stderr)
            return 1
        now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            conn.executemany(
                "INSERT INTO fail_resolutions (fail_event_id, ecosystem, package, version,"
                " artifact_id, resolution, resolved_at, resolved_by) VALUES (?,?,?,?,?,?,?,?)",
                [(e, args.ecosystem, args.package, args.version, args.artifact, reason, now, args.by)
                 for e in sorted(wanted)],
            )
        still_open = sorted(open_events - wanted)
    finally:
        conn.close()
    print(f"resolved fail event(s) {sorted(wanted)}")
    if still_open:
        print(f"still open: {still_open}; the verdict stays a fail until every one is resolved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
