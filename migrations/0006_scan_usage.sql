CREATE TABLE IF NOT EXISTS scan_usage_jobs (
  job_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, created_at INTEGER NOT NULL,
  started_at INTEGER, finished_at INTEGER, status TEXT NOT NULL,
  input_bytes INTEGER NOT NULL, file_count INTEGER NOT NULL, tool_count INTEGER NOT NULL,
  queue_ms INTEGER, execution_ms INTEGER, container_ms INTEGER, findings_count INTEGER,
  outbound_connections INTEGER, network_failures INTEGER
);
CREATE INDEX IF NOT EXISTS scan_usage_created ON scan_usage_jobs(created_at, job_id);
CREATE INDEX IF NOT EXISTS scan_usage_workspace ON scan_usage_jobs(workspace_id, created_at, job_id);
CREATE TABLE IF NOT EXISTS scan_usage_tools (
  job_id TEXT NOT NULL, tool_id TEXT NOT NULL, status TEXT NOT NULL, duration_ms INTEGER,
  findings_count INTEGER, critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, unknown INTEGER,
  PRIMARY KEY(job_id, tool_id)
);
CREATE INDEX IF NOT EXISTS scan_usage_tool_id ON scan_usage_tools(tool_id, job_id);
CREATE TABLE IF NOT EXISTS scan_usage_activity (
  day TEXT NOT NULL, workspace_id TEXT NOT NULL, tool_id TEXT NOT NULL, kind TEXT NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY(day, workspace_id, tool_id, kind)
);
CREATE INDEX IF NOT EXISTS scan_usage_activity_day ON scan_usage_activity(day, workspace_id);
CREATE TABLE IF NOT EXISTS scan_usage_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
