CREATE TABLE IF NOT EXISTS discovery_metric_days (
  day TEXT PRIMARY KEY,
  first_observed_at INTEGER NOT NULL,
  observed_at INTEGER NOT NULL,
  data TEXT NOT NULL
);
