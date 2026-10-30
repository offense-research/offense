CREATE TABLE IF NOT EXISTS scan_auto_topup_preferences (
  workspace_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0,
  consent_id TEXT, consent_user_id TEXT, consent_version TEXT, consent_at INTEGER,
  account_id TEXT, member_id TEXT, payment_method_id TEXT, error TEXT, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_auto_topup_orders (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL,
  kind TEXT NOT NULL, status TEXT NOT NULL, consent_id TEXT NOT NULL,
  checkout_id TEXT UNIQUE, checkout_url TEXT, account_id TEXT, member_id TEXT,
  payment_method_id TEXT, payment_id TEXT UNIQUE, amount_cents INTEGER NOT NULL,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS scan_auto_topup_orders_workspace ON scan_auto_topup_orders(workspace_id, kind, created_at);
CREATE TABLE IF NOT EXISTS scan_auto_topup_events (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, resource_id TEXT NOT NULL, order_id TEXT,
  created_at INTEGER NOT NULL, processed_at INTEGER, last_attempt_at INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0, outcome TEXT
);
CREATE INDEX IF NOT EXISTS scan_auto_topup_events_pending ON scan_auto_topup_events(processed_at, last_attempt_at, created_at);
CREATE INDEX IF NOT EXISTS scan_auto_topup_events_resource ON scan_auto_topup_events(resource_id, type);
