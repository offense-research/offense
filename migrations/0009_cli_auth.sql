CREATE TABLE IF NOT EXISTS cli_auth_devices (
  id TEXT PRIMARY KEY, device_hash TEXT NOT NULL UNIQUE, user_code_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','consumed')),
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  last_poll_at INTEGER, poll_interval INTEGER NOT NULL DEFAULT 5,
  user_id TEXT, workspace_id TEXT, approved_at INTEGER, consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS cli_auth_devices_expiry ON cli_auth_devices(expires_at);
CREATE TABLE IF NOT EXISTS cli_auth_limits (
  bucket_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cli_auth_limits_expiry ON cli_auth_limits(expires_at);
