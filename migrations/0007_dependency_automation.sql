CREATE TABLE IF NOT EXISTS dependency_monitor (
  session_id TEXT NOT NULL, repository TEXT NOT NULL, installation_id INTEGER NOT NULL,
  attempted_at INTEGER NOT NULL, checked_at INTEGER, status TEXT NOT NULL,
  PRIMARY KEY (session_id, repository, installation_id)
);
CREATE TABLE IF NOT EXISTS dependency_automation_policies (
  session_id TEXT NOT NULL, repository TEXT NOT NULL, installation_id INTEGER NOT NULL,
  policy_json TEXT NOT NULL, updated_at INTEGER NOT NULL,
  PRIMARY KEY (session_id, repository, installation_id)
);
CREATE TABLE IF NOT EXISTS dependency_automation_runs (
  id TEXT PRIMARY KEY, session_id TEXT NOT NULL, repository TEXT NOT NULL,
  installation_id INTEGER NOT NULL, trigger TEXT NOT NULL, status TEXT NOT NULL,
  started_at INTEGER NOT NULL, finished_at INTEGER, duration_ms INTEGER,
  revision TEXT, advisory_matches INTEGER, coverage_status TEXT NOT NULL,
  error_code TEXT
);
CREATE INDEX IF NOT EXISTS dependency_automation_runs_repository
  ON dependency_automation_runs(session_id, repository, installation_id, started_at, id);
