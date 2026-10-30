CREATE TABLE IF NOT EXISTS skill_usage_days (
  day TEXT NOT NULL,
  channel TEXT NOT NULL CHECK(channel IN ('mcp', 'https', 'legacy')),
  operation TEXT NOT NULL CHECK(operation IN ('audit', 'planning')),
  started INTEGER NOT NULL DEFAULT 0 CHECK(started >= 0),
  completed INTEGER NOT NULL DEFAULT 0 CHECK(completed >= 0),
  partial INTEGER NOT NULL DEFAULT 0 CHECK(partial >= 0),
  failed INTEGER NOT NULL DEFAULT 0 CHECK(failed >= 0),
  rejected INTEGER NOT NULL DEFAULT 0 CHECK(rejected >= 0),
  checked_packages INTEGER NOT NULL DEFAULT 0 CHECK(checked_packages >= 0),
  advisory_matches INTEGER NOT NULL DEFAULT 0 CHECK(advisory_matches >= 0),
  critical INTEGER NOT NULL DEFAULT 0 CHECK(critical >= 0),
  high INTEGER NOT NULL DEFAULT 0 CHECK(high >= 0),
  medium INTEGER NOT NULL DEFAULT 0 CHECK(medium >= 0),
  low INTEGER NOT NULL DEFAULT 0 CHECK(low >= 0),
  unknown INTEGER NOT NULL DEFAULT 0 CHECK(unknown >= 0),
  duration_ms INTEGER NOT NULL DEFAULT 0 CHECK(duration_ms >= 0),
  duration_samples INTEGER NOT NULL DEFAULT 0 CHECK(duration_samples >= 0),
  PRIMARY KEY(day, channel, operation)
);
CREATE TABLE IF NOT EXISTS skill_usage_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
