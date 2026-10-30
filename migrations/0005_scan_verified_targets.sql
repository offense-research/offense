CREATE TABLE IF NOT EXISTS scan_verified_targets (
  workspace_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  proof TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (workspace_id, origin)
);
