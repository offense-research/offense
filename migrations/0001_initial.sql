-- Schema for moving Purple's existing SQLite state to Cloudflare D1.
-- Data is imported separately during cutover; this file contains no credentials.
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, github_id TEXT NOT NULL UNIQUE, login TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
  user_id TEXT NOT NULL, workspace_id TEXT NOT NULL, role TEXT NOT NULL,
  PRIMARY KEY (user_id, workspace_id),
  FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ingest_tokens (
  token_hash TEXT PRIMARY KEY, session_id TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ingest_batches (
  id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, received_at INTEGER NOT NULL,
  message_count INTEGER NOT NULL, accepted_count INTEGER NOT NULL DEFAULT 0,
  duplicate_count INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, received_at INTEGER NOT NULL, payload TEXT NOT NULL,
  queue_message_id TEXT, batch_id INTEGER, analysis_status TEXT NOT NULL DEFAULT 'pending',
  exported_at INTEGER, detected_at INTEGER
);
CREATE TABLE IF NOT EXISTS detection_signals (
  event_id INTEGER NOT NULL, session_id TEXT NOT NULL, source_worker TEXT NOT NULL,
  kind TEXT NOT NULL, received_at INTEGER NOT NULL, request_id TEXT,
  PRIMARY KEY (event_id, kind)
);
CREATE TABLE IF NOT EXISTS investigations (
  id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, rule_id TEXT NOT NULL,
  source_worker TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
  severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, event_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, group_key TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS investigation_events (
  investigation_id INTEGER NOT NULL, event_id INTEGER NOT NULL,
  received_at INTEGER NOT NULL, request_id TEXT, reason TEXT NOT NULL,
  PRIMARY KEY (investigation_id, event_id)
);
CREATE TABLE IF NOT EXISTS worker_repositories (
  session_id TEXT NOT NULL, source_worker TEXT NOT NULL, repository TEXT NOT NULL,
  installation_id INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  PRIMARY KEY (session_id, source_worker)
);
CREATE TABLE IF NOT EXISTS dependency_snapshots (
  session_id TEXT NOT NULL, repository TEXT NOT NULL, installation_id INTEGER NOT NULL,
  revision TEXT NOT NULL, scanned_at INTEGER NOT NULL, data TEXT NOT NULL,
  PRIMARY KEY (session_id, repository, installation_id)
);
CREATE TABLE IF NOT EXISTS agent_runs (
  id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, investigation_id INTEGER NOT NULL UNIQUE,
  repository TEXT NOT NULL, installation_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued', commit_sha TEXT, result TEXT, error TEXT,
  created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER,
  patch TEXT, verification TEXT
);

CREATE INDEX IF NOT EXISTS agent_runs_workspace ON agent_runs(session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS batches_workspace ON ingest_batches(session_id, id DESC);
CREATE INDEX IF NOT EXISTS events_export_pending ON events(id) WHERE exported_at IS NULL;
CREATE INDEX IF NOT EXISTS events_pending ON events(session_id, analysis_status, id);
CREATE UNIQUE INDEX IF NOT EXISTS events_queue_message ON events(session_id, queue_message_id) WHERE queue_message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS investigation_events_recent ON investigation_events(investigation_id, received_at DESC);
CREATE INDEX IF NOT EXISTS investigations_group ON investigations(session_id, source_worker, rule_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS investigations_group_key ON investigations(session_id, source_worker, rule_id, group_key, last_seen DESC);
CREATE INDEX IF NOT EXISTS investigations_workspace ON investigations(session_id, status, last_seen DESC);
CREATE INDEX IF NOT EXISTS signals_retention ON detection_signals(received_at);
CREATE INDEX IF NOT EXISTS signals_window ON detection_signals(session_id, source_worker, kind, received_at);
