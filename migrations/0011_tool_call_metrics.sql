CREATE TABLE IF NOT EXISTS tool_call_days (
  day TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('tool','request')),
  channel TEXT NOT NULL CHECK(channel IN ('http','mcp')),
  operation TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  started INTEGER NOT NULL DEFAULT 0 CHECK(started >= 0),
  completed INTEGER NOT NULL DEFAULT 0 CHECK(completed >= 0),
  failed INTEGER NOT NULL DEFAULT 0 CHECK(failed >= 0),
  rejected INTEGER NOT NULL DEFAULT 0 CHECK(rejected >= 0),
  CHECK(completed + failed + rejected <= started),
  PRIMARY KEY(day,kind,channel,operation,endpoint)
);
CREATE INDEX IF NOT EXISTS tool_call_days_scope ON tool_call_days(kind,day);
CREATE TABLE IF NOT EXISTS tool_call_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
