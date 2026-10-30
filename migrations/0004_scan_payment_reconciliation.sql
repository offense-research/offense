-- Signed payment events are acknowledged quickly and reconciled by the
-- existing dispatch alarm. An unprocessed event never creates spendable credit.
ALTER TABLE scan_billing_events ADD COLUMN processed_at INTEGER;
ALTER TABLE scan_billing_events ADD COLUMN last_attempt_at INTEGER;
ALTER TABLE scan_billing_events ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_billing_events ADD COLUMN order_id TEXT;
ALTER TABLE scan_billing_events ADD COLUMN outcome TEXT;
CREATE INDEX IF NOT EXISTS scan_billing_events_pending
  ON scan_billing_events(type, processed_at, last_attempt_at, created_at);
