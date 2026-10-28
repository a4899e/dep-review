BEGIN;
-- dep-review database schema. Applied idempotently by scripts/lib-db.sh.
CREATE TABLE IF NOT EXISTS inventory_runs (
    run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at          TEXT NOT NULL,
    ref             TEXT NOT NULL,
    expected_pairs  INTEGER NOT NULL,
    completed_pairs INTEGER NOT NULL,
    skipped         TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL CHECK (status IN ('complete','incomplete'))
);
CREATE TABLE IF NOT EXISTS repo_dep_artifacts (
    repo          TEXT NOT NULL,
    ecosystem     TEXT NOT NULL CHECK (ecosystem IN ('npm','pypi')),
    package       TEXT NOT NULL,
    version       TEXT NOT NULL,
    artifact_id   TEXT NOT NULL,
    artifact_name TEXT NOT NULL,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('sdist','wheel','tarball','binary')),
    PRIMARY KEY (repo, ecosystem, package, version, artifact_id)
);
CREATE TABLE IF NOT EXISTS repo_deps (
    repo        TEXT NOT NULL,
    ecosystem   TEXT NOT NULL CHECK (ecosystem IN ('npm','pypi')),
    package     TEXT NOT NULL,
    version     TEXT NOT NULL,
    is_direct   INTEGER NOT NULL DEFAULT 0 CHECK (is_direct IN (0,1)),
    dep_type    TEXT,
    snapshot_at TEXT NOT NULL, snapshot_ref TEXT, source_ref TEXT, source_kind TEXT CHECK (source_kind IN ('registry','git','local')),
    PRIMARY KEY (repo, ecosystem, package, version)
);
CREATE TABLE IF NOT EXISTS review_artifacts (
    ecosystem     TEXT NOT NULL CHECK (ecosystem IN ('npm','pypi','maven','golang')),
    package       TEXT NOT NULL,
    version       TEXT NOT NULL,
    artifact_id   TEXT NOT NULL,
    artifact_name TEXT NOT NULL,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('sdist','wheel','tarball','binary')),
    source_read   INTEGER NOT NULL DEFAULT 0 CHECK (source_read IN (0,1)),
    verdict       TEXT NOT NULL CHECK (verdict IN ('pass','fail')),
    notes         TEXT NOT NULL,
    reviewed_at   TEXT NOT NULL,
    reviewer      TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package, version, artifact_id)
);
CREATE TABLE IF NOT EXISTS reviews (
    ecosystem   TEXT NOT NULL CHECK (ecosystem IN ('npm','pypi','maven','golang')),
    package     TEXT NOT NULL,
    version     TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    verdict     TEXT NOT NULL CHECK (verdict IN ('pass', 'fail', 'partial')),
    notes       TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    reviewer    TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package, version)
);
CREATE INDEX IF NOT EXISTS idx_repo_dep_artifacts_pkg ON repo_dep_artifacts(ecosystem, package, version);
CREATE INDEX IF NOT EXISTS idx_repo_dep_artifacts_repo ON repo_dep_artifacts(repo);
CREATE INDEX IF NOT EXISTS idx_repo_deps_pkg ON repo_deps(ecosystem, package, version);
CREATE INDEX IF NOT EXISTS idx_repo_deps_repo ON repo_deps(repo);
CREATE INDEX IF NOT EXISTS idx_review_artifacts_pkg ON review_artifacts(ecosystem, package, version);
CREATE INDEX IF NOT EXISTS idx_reviews_package ON reviews(ecosystem, package);
CREATE INDEX IF NOT EXISTS idx_reviews_verdict ON reviews(verdict);

-- A fail is a finding that needs a human. Nothing may replace, downgrade, or
-- delete it until a fail_resolutions row answers that exact fail. This is
-- enforced here, not in the writer, so a raw sqlite3 INSERT OR REPLACE from any
-- reviewer is held to it too. artifact_id '' is the version-level verdict; any
-- other value is that artifact's verdict.
--
-- Identity is an event id, not a timestamp. Every write of a fail appends a
-- fail_events row (AUTOINCREMENT: ids never repeat), and a resolution names the
-- event it answers. Only a resolution of the LATEST event for a key clears it,
-- so resolving fail A cannot clear a fail B recorded afterwards, even in the
-- same second or from a teammate whose clock disagrees.
--
-- UPGRADES. Everything below is applied to existing databases too, so it must
-- converge from any earlier schema:
--   * Resolutions live in fail_resolutions. An earlier failure_resolutions
--     table (timestamp-bound, from before events existed) is left in place as
--     history and clears nothing: a fail still standing under it needs a fresh,
--     event-bound resolution. That is the safe direction; a timestamp cannot
--     say which finding a person actually looked at.
--   * Guard triggers are dropped and recreated on every apply. CREATE TRIGGER
--     IF NOT EXISTS would keep an older, weaker guard forever.
CREATE TABLE IF NOT EXISTS fail_events (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem   TEXT NOT NULL,
    package     TEXT NOT NULL,
    version     TEXT NOT NULL,
    artifact_id TEXT NOT NULL DEFAULT '',
    reviewed_at TEXT NOT NULL,
    reviewer    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fail_events_key ON fail_events(ecosystem, package, version, artifact_id);

CREATE TABLE IF NOT EXISTS fail_resolutions (
    fail_event_id INTEGER NOT NULL UNIQUE REFERENCES fail_events(event_id),
    ecosystem     TEXT NOT NULL,
    package       TEXT NOT NULL,
    version       TEXT NOT NULL,
    artifact_id   TEXT NOT NULL DEFAULT '',
    resolution    TEXT NOT NULL CHECK (length(trim(resolution)) > 0),
    resolved_at   TEXT NOT NULL,
    resolved_by   TEXT NOT NULL CHECK (length(trim(resolved_by)) > 0)
);

-- Fails written before fail_events existed get one event each, so a human can
-- resolve them. Idempotent: only keys with no event are filled.
INSERT INTO fail_events (ecosystem, package, version, artifact_id, reviewed_at, reviewer)
SELECT r.ecosystem, r.package, r.version, '', r.reviewed_at, r.reviewer FROM reviews r
 WHERE r.verdict='fail' AND NOT EXISTS (SELECT 1 FROM fail_events e
        WHERE e.ecosystem=r.ecosystem AND e.package=r.package AND e.version=r.version AND e.artifact_id='');
INSERT INTO fail_events (ecosystem, package, version, artifact_id, reviewed_at, reviewer)
SELECT r.ecosystem, r.package, r.version, r.artifact_id, r.reviewed_at, r.reviewer FROM review_artifacts r
 WHERE r.verdict='fail' AND NOT EXISTS (SELECT 1 FROM fail_events e
        WHERE e.ecosystem=r.ecosystem AND e.package=r.package AND e.version=r.version AND e.artifact_id=r.artifact_id);

CREATE TRIGGER IF NOT EXISTS fail_events_append_only_update
BEFORE UPDATE ON fail_events
BEGIN SELECT RAISE(ABORT, 'fail_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS fail_events_append_only_delete
BEFORE DELETE ON fail_events
BEGIN SELECT RAISE(ABORT, 'fail_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS fail_resolutions_append_only_update
BEFORE UPDATE ON fail_resolutions
BEGIN SELECT RAISE(ABORT, 'fail_resolutions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS fail_resolutions_append_only_delete
BEFORE DELETE ON fail_resolutions
BEGIN SELECT RAISE(ABORT, 'fail_resolutions is append-only'); END;

DROP TRIGGER IF EXISTS reviews_fail_event_insert;
DROP TRIGGER IF EXISTS reviews_fail_event_update;
DROP TRIGGER IF EXISTS review_artifacts_fail_event_insert;
DROP TRIGGER IF EXISTS review_artifacts_fail_event_update;
DROP TRIGGER IF EXISTS reviews_keep_fail_insert;
DROP TRIGGER IF EXISTS reviews_keep_fail_update;
DROP TRIGGER IF EXISTS reviews_keep_fail_delete;
DROP TRIGGER IF EXISTS review_artifacts_keep_fail_insert;
DROP TRIGGER IF EXISTS review_artifacts_keep_fail_update;
DROP TRIGGER IF EXISTS review_artifacts_keep_fail_delete;

-- Each fail written, including fail -> fail, is a new event needing its own
-- resolution.
CREATE TRIGGER reviews_fail_event_insert
AFTER INSERT ON reviews WHEN NEW.verdict='fail'
BEGIN INSERT INTO fail_events (ecosystem, package, version, artifact_id, reviewed_at, reviewer)
      VALUES (NEW.ecosystem, NEW.package, NEW.version, '', NEW.reviewed_at, NEW.reviewer); END;
CREATE TRIGGER reviews_fail_event_update
AFTER UPDATE ON reviews WHEN NEW.verdict='fail'
BEGIN INSERT INTO fail_events (ecosystem, package, version, artifact_id, reviewed_at, reviewer)
      VALUES (NEW.ecosystem, NEW.package, NEW.version, '', NEW.reviewed_at, NEW.reviewer); END;
CREATE TRIGGER review_artifacts_fail_event_insert
AFTER INSERT ON review_artifacts WHEN NEW.verdict='fail'
BEGIN INSERT INTO fail_events (ecosystem, package, version, artifact_id, reviewed_at, reviewer)
      VALUES (NEW.ecosystem, NEW.package, NEW.version, NEW.artifact_id, NEW.reviewed_at, NEW.reviewer); END;
CREATE TRIGGER review_artifacts_fail_event_update
AFTER UPDATE ON review_artifacts WHEN NEW.verdict='fail'
BEGIN INSERT INTO fail_events (ecosystem, package, version, artifact_id, reviewed_at, reviewer)
      VALUES (NEW.ecosystem, NEW.package, NEW.version, NEW.artifact_id, NEW.reviewed_at, NEW.reviewer); END;

-- BEFORE INSERT also covers INSERT OR REPLACE: it fires while the old row
-- still exists, before the conflict deletes it.
CREATE TRIGGER reviews_keep_fail_insert
BEFORE INSERT ON reviews
WHEN NEW.verdict <> 'fail' AND EXISTS (
    SELECT 1 FROM reviews r
     WHERE r.ecosystem=NEW.ecosystem AND r.package=NEW.package AND r.version=NEW.version
       AND r.verdict='fail'
       AND NOT EXISTS (SELECT 1 FROM fail_resolutions f
                  WHERE f.fail_event_id = (SELECT MAX(e.event_id) FROM fail_events e
                     WHERE e.ecosystem=r.ecosystem AND e.package=r.package
                       AND e.version=r.version AND e.artifact_id='')))
BEGIN SELECT RAISE(ABORT, 'unresolved fail verdict: a human must resolve it with resolve-failure.py first'); END;

CREATE TRIGGER reviews_keep_fail_update
BEFORE UPDATE ON reviews
WHEN OLD.verdict='fail'
 AND (NEW.verdict <> 'fail' OR NEW.ecosystem IS NOT OLD.ecosystem
      OR NEW.package IS NOT OLD.package OR NEW.version IS NOT OLD.version)
 AND NOT EXISTS (SELECT 1 FROM fail_resolutions f
                  WHERE f.fail_event_id = (SELECT MAX(e.event_id) FROM fail_events e
                     WHERE e.ecosystem=OLD.ecosystem AND e.package=OLD.package
                       AND e.version=OLD.version AND e.artifact_id=''))
BEGIN SELECT RAISE(ABORT, 'unresolved fail verdict: a human must resolve it with resolve-failure.py first'); END;

CREATE TRIGGER reviews_keep_fail_delete
BEFORE DELETE ON reviews
WHEN OLD.verdict='fail'
 AND NOT EXISTS (SELECT 1 FROM fail_resolutions f
                  WHERE f.fail_event_id = (SELECT MAX(e.event_id) FROM fail_events e
                     WHERE e.ecosystem=OLD.ecosystem AND e.package=OLD.package
                       AND e.version=OLD.version AND e.artifact_id=''))
BEGIN SELECT RAISE(ABORT, 'unresolved fail verdict: a human must resolve it with resolve-failure.py first'); END;

CREATE TRIGGER review_artifacts_keep_fail_insert
BEFORE INSERT ON review_artifacts
WHEN NEW.verdict <> 'fail' AND EXISTS (
    SELECT 1 FROM review_artifacts r
     WHERE r.ecosystem=NEW.ecosystem AND r.package=NEW.package AND r.version=NEW.version
       AND r.artifact_id=NEW.artifact_id AND r.verdict='fail'
       AND NOT EXISTS (SELECT 1 FROM fail_resolutions f
                  WHERE f.fail_event_id = (SELECT MAX(e.event_id) FROM fail_events e
                     WHERE e.ecosystem=r.ecosystem AND e.package=r.package
                       AND e.version=r.version AND e.artifact_id=r.artifact_id)))
BEGIN SELECT RAISE(ABORT, 'unresolved fail verdict on artifact: a human must resolve it with resolve-failure.py first'); END;

CREATE TRIGGER review_artifacts_keep_fail_update
BEFORE UPDATE ON review_artifacts
WHEN OLD.verdict='fail'
 AND (NEW.verdict <> 'fail' OR NEW.ecosystem IS NOT OLD.ecosystem OR NEW.package IS NOT OLD.package
      OR NEW.version IS NOT OLD.version OR NEW.artifact_id IS NOT OLD.artifact_id)
 AND NOT EXISTS (SELECT 1 FROM fail_resolutions f
                  WHERE f.fail_event_id = (SELECT MAX(e.event_id) FROM fail_events e
                     WHERE e.ecosystem=OLD.ecosystem AND e.package=OLD.package
                       AND e.version=OLD.version AND e.artifact_id=OLD.artifact_id))
BEGIN SELECT RAISE(ABORT, 'unresolved fail verdict on artifact: a human must resolve it with resolve-failure.py first'); END;

CREATE TRIGGER review_artifacts_keep_fail_delete
BEFORE DELETE ON review_artifacts
WHEN OLD.verdict='fail'
 AND NOT EXISTS (SELECT 1 FROM fail_resolutions f
                  WHERE f.fail_event_id = (SELECT MAX(e.event_id) FROM fail_events e
                     WHERE e.ecosystem=OLD.ecosystem AND e.package=OLD.package
                       AND e.version=OLD.version AND e.artifact_id=OLD.artifact_id))
BEGIN SELECT RAISE(ABORT, 'unresolved fail verdict on artifact: a human must resolve it with resolve-failure.py first'); END;
COMMIT;
