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
