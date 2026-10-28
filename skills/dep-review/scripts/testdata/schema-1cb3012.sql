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
-- delete it until a failure_resolutions row newer than the fail says why. This
-- is enforced here, not in the writer, so a raw sqlite3 INSERT OR REPLACE from
-- any reviewer is held to it too. artifact_id '' resolves the version-level
-- verdict; any other value resolves that artifact's verdict.
CREATE TABLE IF NOT EXISTS failure_resolutions (
    ecosystem   TEXT NOT NULL,
    package     TEXT NOT NULL,
    version     TEXT NOT NULL,
    artifact_id TEXT NOT NULL DEFAULT '',
    resolution  TEXT NOT NULL CHECK (length(trim(resolution)) > 0),
    resolved_at TEXT NOT NULL,
    resolved_by TEXT NOT NULL CHECK (length(trim(resolved_by)) > 0)
);
CREATE INDEX IF NOT EXISTS idx_failure_resolutions_key ON failure_resolutions(ecosystem, package, version, artifact_id);

CREATE TRIGGER IF NOT EXISTS failure_resolutions_append_only_update
BEFORE UPDATE ON failure_resolutions
BEGIN SELECT RAISE(ABORT, 'failure_resolutions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS failure_resolutions_append_only_delete
BEFORE DELETE ON failure_resolutions
BEGIN SELECT RAISE(ABORT, 'failure_resolutions is append-only'); END;

-- BEFORE INSERT also covers INSERT OR REPLACE: it fires while the old row
-- still exists, before the conflict deletes it.
CREATE TRIGGER IF NOT EXISTS reviews_keep_fail_insert
BEFORE INSERT ON reviews
WHEN NEW.verdict <> 'fail' AND EXISTS (
    SELECT 1 FROM reviews r
     WHERE r.ecosystem=NEW.ecosystem AND r.package=NEW.package AND r.version=NEW.version
       AND r.verdict='fail'
       AND NOT EXISTS (SELECT 1 FROM failure_resolutions f
                        WHERE f.ecosystem=r.ecosystem AND f.package=r.package
                          AND f.version=r.version AND f.artifact_id=''
                          AND f.resolved_at >= r.reviewed_at))
BEGIN SELECT RAISE(ABORT, 'unresolved fail verdict: a human must add a failure_resolutions row first'); END;

CREATE TRIGGER IF NOT EXISTS reviews_keep_fail_update
BEFORE UPDATE ON reviews
WHEN OLD.verdict='fail'
 AND (NEW.verdict <> 'fail' OR NEW.ecosystem IS NOT OLD.ecosystem
      OR NEW.package IS NOT OLD.package OR NEW.version IS NOT OLD.version)
 AND NOT EXISTS (SELECT 1 FROM failure_resolutions f
                  WHERE f.ecosystem=OLD.ecosystem AND f.package=OLD.package
                    AND f.version=OLD.version AND f.artifact_id=''
                    AND f.resolved_at >= OLD.reviewed_at)
BEGIN SELECT RAISE(ABORT, 'unresolved fail verdict: a human must add a failure_resolutions row first'); END;

CREATE TRIGGER IF NOT EXISTS reviews_keep_fail_delete
BEFORE DELETE ON reviews
WHEN OLD.verdict='fail'
 AND NOT EXISTS (SELECT 1 FROM failure_resolutions f
                  WHERE f.ecosystem=OLD.ecosystem AND f.package=OLD.package
                    AND f.version=OLD.version AND f.artifact_id=''
                    AND f.resolved_at >= OLD.reviewed_at)
BEGIN SELECT RAISE(ABORT, 'unresolved fail verdict: a human must add a failure_resolutions row first'); END;

CREATE TRIGGER IF NOT EXISTS review_artifacts_keep_fail_insert
BEFORE INSERT ON review_artifacts
WHEN NEW.verdict <> 'fail' AND EXISTS (
    SELECT 1 FROM review_artifacts r
     WHERE r.ecosystem=NEW.ecosystem AND r.package=NEW.package AND r.version=NEW.version
       AND r.artifact_id=NEW.artifact_id AND r.verdict='fail'
       AND NOT EXISTS (SELECT 1 FROM failure_resolutions f
                        WHERE f.ecosystem=r.ecosystem AND f.package=r.package
                          AND f.version=r.version AND f.artifact_id=r.artifact_id
                          AND f.resolved_at >= r.reviewed_at))
BEGIN SELECT RAISE(ABORT, 'unresolved fail verdict on artifact: a human must add a failure_resolutions row first'); END;

CREATE TRIGGER IF NOT EXISTS review_artifacts_keep_fail_update
BEFORE UPDATE ON review_artifacts
WHEN OLD.verdict='fail'
 AND (NEW.verdict <> 'fail' OR NEW.ecosystem IS NOT OLD.ecosystem OR NEW.package IS NOT OLD.package
      OR NEW.version IS NOT OLD.version OR NEW.artifact_id IS NOT OLD.artifact_id)
 AND NOT EXISTS (SELECT 1 FROM failure_resolutions f
                  WHERE f.ecosystem=OLD.ecosystem AND f.package=OLD.package
                    AND f.version=OLD.version AND f.artifact_id=OLD.artifact_id
                    AND f.resolved_at >= OLD.reviewed_at)
BEGIN SELECT RAISE(ABORT, 'unresolved fail verdict on artifact: a human must add a failure_resolutions row first'); END;

CREATE TRIGGER IF NOT EXISTS review_artifacts_keep_fail_delete
BEFORE DELETE ON review_artifacts
WHEN OLD.verdict='fail'
 AND NOT EXISTS (SELECT 1 FROM failure_resolutions f
                  WHERE f.ecosystem=OLD.ecosystem AND f.package=OLD.package
                    AND f.version=OLD.version AND f.artifact_id=OLD.artifact_id
                    AND f.resolved_at >= OLD.reviewed_at)
BEGIN SELECT RAISE(ABORT, 'unresolved fail verdict on artifact: a human must add a failure_resolutions row first'); END;
