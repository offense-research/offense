CREATE TABLE IF NOT EXISTS scan_keys (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS scan_jobs (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, key_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL, fingerprint TEXT NOT NULL, status TEXT NOT NULL,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER,
  input_bytes INTEGER NOT NULL, file_count INTEGER NOT NULL, result TEXT, error TEXT,
  selected_tools TEXT NOT NULL DEFAULT '["opengrep","trivy-vuln","gitleaks"]',
  UNIQUE(workspace_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS scan_jobs_queue ON scan_jobs(status, created_at);
CREATE INDEX IF NOT EXISTS scan_jobs_workspace ON scan_jobs(workspace_id, created_at);
CREATE TABLE IF NOT EXISTS scan_sources (
  scan_id TEXT NOT NULL, path TEXT NOT NULL, content TEXT NOT NULL, PRIMARY KEY(scan_id, path)
);
CREATE TABLE IF NOT EXISTS scan_cleanup (scan_id TEXT PRIMARY KEY);
