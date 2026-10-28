#!/usr/bin/env python3
"""Record a review verdict from JSON, with no shell anywhere between the evidence and the DB.

Review notes quote package content, and package content is attacker-written.
Splicing it into a shell command line -- even inside SQL single quotes inside
shell double quotes -- runs any `$(...)` or backticks it contains on the
reviewer's machine. This takes the record as JSON on stdin (or --file) and
writes it with bound parameters, so the notes are stored byte for byte.

Write the JSON with your file-writing tool, not with echo/printf, then:

    record-review.py --file review.json

Input::

    {
      "ecosystem": "npm" | "pypi",
      "package": "left-pad", "version": "1.3.0",
      "sha256": "<lockfile integrity, or git commit for git sources>",
      "verdict": "pass" | "fail" | "partial",
      "notes": "...",
      "reviewer": "claude",                  # optional; else $DEP_REVIEW_REVIEWER
      "artifacts": [                          # every artifact actually inspected
        {"artifact_id": "sha512-...", "artifact_name": "left-pad-1.3.0.tgz",
         "artifact_kind": "sdist|wheel|tarball|binary", "source_read": true,  # must be true to pass
         "verdict": "pass" | "fail", "notes": "..."}
      ]
    }

The version row and its artifact rows are written in one transaction. The
database refuses to replace, downgrade or delete an unresolved fail; that
refusal is reported and nothing is written.

Exit: 0 written, 1 refused by the database, 2 bad input
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sqlite3
import sys
from pathlib import Path

SCHEMA = Path(__file__).resolve().parent / "schema.sql"
ECOSYSTEMS = {"npm", "pypi"}
VERDICTS = {"pass", "fail", "partial"}
ARTIFACT_VERDICTS = {"pass", "fail"}
KINDS = {"sdist", "wheel", "tarball", "binary"}


def db_path() -> Path:
    explicit = os.environ.get("DEP_REVIEW_DB") or os.environ.get("REVIEWS_DB")
    if explicit:
        return Path(explicit)
    xdg = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(os.environ.get("DEP_REVIEW_HOME") or Path(xdg) / "dep-review") / "reviews.db"


def need(obj: dict, key: str, allowed: set[str] | None = None) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing or empty {key!r}")
    if allowed is not None and value not in allowed:
        raise ValueError(f"{key}={value!r}; expected one of {sorted(allowed)}")
    return value


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", type=Path, help="JSON record (default: stdin)")
    args = ap.parse_args()

    try:
        rec = json.loads(args.file.read_text(encoding="utf-8") if args.file else sys.stdin.read())
        eco = need(rec, "ecosystem", ECOSYSTEMS)
        pkg, ver = need(rec, "package"), need(rec, "version")
        sha, verdict = need(rec, "sha256"), need(rec, "verdict", VERDICTS)
        notes = need(rec, "notes")
        reviewer = rec.get("reviewer") or os.environ.get("DEP_REVIEW_REVIEWER") or ""
        if not reviewer.strip():
            raise ValueError("no reviewer: set 'reviewer' or DEP_REVIEW_REVIEWER")
        arts = rec.get("artifacts") or []
        if not isinstance(arts, list):
            raise ValueError("'artifacts' must be a list")
        art_rows = []
        for a in arts:
            # A JSON boolean, never coerced: "false" or {"read": false} is
            # truthy in Python and would become evidence that bytes were read.
            if not isinstance(a.get("source_read"), bool):
                raise ValueError("artifact 'source_read' must be JSON true or false")
            art_rows.append((
                eco, pkg, ver,
                need(a, "artifact_id"), need(a, "artifact_name"),
                need(a, "artifact_kind", KINDS),
                1 if a["source_read"] else 0,
                need(a, "verdict", ARTIFACT_VERDICTS), need(a, "notes"),
            ))
        if any(r[7] == "pass" and not r[6] for r in art_rows):
            raise ValueError(
                "artifact 'pass' with source_read false: bytes you could not read cannot pass;"
                " leave that artifact out (it stays uncovered) and record the version 'partial'"
            )
        if verdict == "pass" and any(r[7] == "fail" for r in art_rows):
            raise ValueError("verdict 'pass' with a failing artifact; the release fails")
    except (ValueError, json.JSONDecodeError, OSError) as e:
        print(f"bad input: {e}", file=sys.stderr)
        return 2

    now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA.read_text())
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO reviews (ecosystem, package, version, sha256, verdict,"
                " notes, reviewed_at, reviewer) VALUES (?,?,?,?,?,?,?,?)",
                (eco, pkg, ver, sha, verdict, notes, now, reviewer),
            )
            conn.executemany(
                "INSERT OR REPLACE INTO review_artifacts (ecosystem, package, version,"
                " artifact_id, artifact_name, artifact_kind, source_read, verdict, notes,"
                " reviewed_at, reviewer) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [r + (now, reviewer) for r in art_rows],
            )
    except sqlite3.IntegrityError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    print(f"recorded {eco} {pkg} {ver}: {verdict} (+{len(art_rows)} artifact rows) in {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
