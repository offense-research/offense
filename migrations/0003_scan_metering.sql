-- Scanner usage is separate from the hosted model balance. Purchase credits
-- may be inserted only after independent payment confirmation.
CREATE TABLE IF NOT EXISTS scan_wallet_entries (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, amount_micros INTEGER NOT NULL,
  kind TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS scan_wallet_workspace ON scan_wallet_entries(workspace_id, created_at);
CREATE TABLE IF NOT EXISTS scan_wallet_blocks (
  workspace_id TEXT PRIMARY KEY, reason TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_meter_jobs (
  job_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, state TEXT NOT NULL,
  quote_json TEXT NOT NULL, reserve_micros INTEGER NOT NULL, charge_micros INTEGER NOT NULL DEFAULT 0,
  reported_tools_json TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS scan_meter_workspace ON scan_meter_jobs(workspace_id, created_at);
CREATE TABLE IF NOT EXISTS scan_wallet_orders (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, status TEXT NOT NULL,
  checkout_id TEXT UNIQUE, checkout_url TEXT, account_id TEXT, payment_id TEXT UNIQUE,
  amount_cents INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS scan_wallet_orders_workspace ON scan_wallet_orders(workspace_id, created_at);
CREATE TABLE IF NOT EXISTS scan_billing_events (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, payment_id TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS scan_billing_events_payment ON scan_billing_events(payment_id);
