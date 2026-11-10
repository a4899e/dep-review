#!/usr/bin/env python3
"""Bring an existing review database's ecosystem lists up to schema.sql.

schema.sql creates tables with CREATE TABLE IF NOT EXISTS, so a database made
before an ecosystem was added (for example 'cargo') keeps its old
CHECK (ecosystem IN (...)) and refuses rows for the new one. SQLite cannot
alter a CHECK constraint, so this rebuilds `reviews` and `review_artifacts`
when their list lacks an ecosystem that schema.sql allows: create the new
table, copy every row, drop the old one, rename, then re-apply schema.sql so
the indexes and guard triggers are back before anything commits.

It is explicit on purpose. A shared, git-tracked database should change shape
only through a step someone runs and commits, never as a side effect of
recording a review.

The rebuild is one transaction: any failure leaves the database as it was.
It refuses when either table carries an index or trigger that schema.sql does
not define, or an index whose definition differs from schema.sql's, because
DROP TABLE would remove it and nothing would put it back as it was. The write
lock is held from the first look at the schema to COMMIT.
Views, and triggers on views, are left in place (see legacy_alter_table below).
fail_events, fail_event_evidence and fail_resolutions are not touched: no
foreign key references the rebuilt tables, and DROP TABLE fires no triggers.

After the commit it runs VACUUM, so the rebuilt tables' freed pages do not
stay in the file. If only the VACUUM fails, the migration has still happened;
running this again finishes the VACUUM.

Usage: migrate-ecosystems.py <path/to/reviews.db>
Exit:  0 migrated (or already current) and vacuumed, 1 refused or failed, 2 bad usage
"""

from __future__ import annotations

import importlib.util
import re
import sqlite3
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "record_review", Path(__file__).resolve().parent / "record-review.py"
)
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)

TABLES = ("reviews", "review_artifacts")
CHECK = re.compile(r"(ecosystem\s+TEXT\s+NOT\s+NULL\s+CHECK\s*\(\s*ecosystem\s+IN\s*\()([^)]*)\)")
HEAD = re.compile(r'^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?("?)(\w+)\1', re.IGNORECASE)
OBJECT = re.compile(r"CREATE\s+(?:UNIQUE\s+)?(?:INDEX|TRIGGER)\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", re.IGNORECASE)


class MigrationError(Exception):
    pass


def ecosystems(sql: str, where: str) -> list[str]:
    found = CHECK.findall(sql)
    if len(found) != 1:
        raise MigrationError(f"{where}: expected one ecosystem CHECK, found {len(found)}")
    return re.findall(r"'([^']*)'", found[0][1])


def schema_create(schema: str, table: str) -> str:
    m = re.search(rf"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+{table}\s*\(.*?\n\);", schema, re.DOTALL)
    if not m:
        raise MigrationError(f"schema.sql has no CREATE TABLE for {table}")
    return m.group(0)


def rebuilt_sql(table: str, sql: str, missing: list[str]) -> str:
    """The table's own CREATE statement, renamed, with the missing ecosystems appended."""
    head = HEAD.match(sql)
    if not head or head.group(2) != table:
        raise MigrationError(f"unexpected CREATE statement for {table}")
    extra = "".join(f",'{e}'" for e in missing)
    new = CHECK.sub(lambda m: f"{m.group(1)}{m.group(2).rstrip()}{extra})", sql, count=1)
    return HEAD.sub(f'CREATE TABLE "{table}__eco_new"', new, count=1)


def norm(sql: str) -> str:
    sql = re.sub(r"\bIF\s+NOT\s+EXISTS\s+", "", sql, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", sql).strip().rstrip(";").strip()


def statements(text: str) -> list[str]:
    """Split SQL text into complete statements (trigger bodies included)."""
    out, buf = [], ""
    for line in text.splitlines(keepends=True):
        buf += line
        if sqlite3.complete_statement(buf):
            if norm(re.sub(r"--[^\n]*", "", buf)):
                out.append(buf)
            buf = ""
    if norm(re.sub(r"--[^\n]*", "", buf)):
        raise MigrationError("schema.sql ends with an incomplete statement")
    return out


def check_attached_objects(conn, schema: str, tables: tuple[str, ...]) -> None:
    """Refuse when DROP TABLE would lose or change something schema.sql would not put back.

    Indexes must match schema.sql's definition exactly; an index with the same name
    but, say, UNIQUE added would otherwise be replaced. Triggers need only a name in
    schema.sql: every schema apply drops and recreates those already.
    """
    defined = {n.lower() for n in OBJECT.findall(schema)}
    indexes = {m.group(1).lower(): norm(m.group(0)) for m in re.finditer(
        r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)[^;]*;", schema, re.IGNORECASE)}
    bad = []
    for kind, name, sql in conn.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE type IN ('index','trigger') AND sql IS NOT NULL"
            f" AND tbl_name IN ({','.join('?' * len(tables))})", tables):
        if name.lower() not in defined:
            bad.append(f"{kind} {name} (not in schema.sql)")
        elif kind == "index" and norm(sql) != indexes.get(name.lower()):
            bad.append(f"index {name} (definition differs from schema.sql)")
    if bad:
        raise MigrationError(
            f"{'; '.join(sorted(bad))} on {', '.join(tables)}: DROP TABLE would lose it."
            " Move it into schema.sql or drop it first")


def vacuum(conn, db: Path, done: str) -> int:
    try:
        conn.execute("VACUUM")
    except sqlite3.Error as e:
        print(f"{done}, and that is committed; VACUUM then failed ({e}). "
              f"Run this again to finish the VACUUM.", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    db = Path(argv[1])
    if not db.is_file():
        print(f"refused: {db} does not exist (a new database gets current lists from schema.sql)",
              file=sys.stderr)
        return 1
    schema = rr.SCHEMA.read_text()
    # Manual transaction control: the write lock is taken before the first look
    # at the schema and held until COMMIT, so no other connection can add or
    # change an object between the checks and the rebuild. (executescript would
    # commit an open transaction first on Python 3.11, so statements run one by one.)
    conn = sqlite3.connect(db, isolation_level=None)
    try:
        # Since SQLite 3.26, RENAME re-checks every view and trigger, and a view
        # over a table dropped a moment ago fails that check. legacy_alter_table
        # skips it; views and triggers name the table, so once the new table has
        # that name they resolve to it. Nothing is dropped and recreated, so no
        # view, no INSTEAD OF trigger and no odd identifier is at risk.
        conn.execute("PRAGMA legacy_alter_table=ON")
        conn.execute("BEGIN IMMEDIATE")
        todo = {}
        for t in TABLES:
            sql = rr.table_sql(conn, t)
            if not sql:
                raise MigrationError(f"{t} table missing; is this a dep-review database?")
            have = ecosystems(sql, f"{t} in {db}")
            missing = [e for e in ecosystems(schema_create(schema, t), f"schema.sql {t}") if e not in have]
            if missing:
                todo[t] = (rebuilt_sql(t, sql, missing), missing)
        if not todo:
            conn.execute("ROLLBACK")
            if conn.execute("PRAGMA freelist_count").fetchone()[0]:
                return vacuum(conn, db, f"{db}: already current")
            print(f"{db}: ecosystem lists already match schema.sql; nothing to do")
            return 0
        check_attached_objects(conn, schema, tuple(todo))
        body = re.sub(r"^\s*BEGIN;\s*$", "", schema, count=1, flags=re.MULTILINE)
        body = re.sub(r"^\s*COMMIT;\s*$", "", body, flags=re.MULTILINE)
        for t, (sql, _) in todo.items():
            conn.execute(sql)
            conn.execute(f'INSERT INTO "{t}__eco_new" SELECT * FROM "{t}"')
            conn.execute(f'DROP TABLE "{t}"')
            conn.execute(f'ALTER TABLE "{t}__eco_new" RENAME TO "{t}"')
        for stmt in statements(body):
            conn.execute(stmt)
        conn.execute("COMMIT")
        conn.execute("PRAGMA legacy_alter_table=OFF")
    except (MigrationError, sqlite3.Error) as e:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        print(f"migration failed, database unchanged: {e}", file=sys.stderr)
        conn.close()
        return 1
    done = f"{db}: " + "; ".join(f"{t} now accepts {', '.join(m)}" for t, (_, m) in todo.items())
    rc = vacuum(conn, db, done)
    conn.close()
    if rc == 0:
        print(done)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
