import { transactionSync } from './db-transaction.js';

const DAY = 86_400_000;
const CHANNELS = ['mcp', 'https', 'legacy'];
const OPERATIONS = ['audit', 'planning'];
const STATUSES = ['completed', 'partial', 'failed', 'rejected'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];
const COLUMNS = ['started', ...STATUSES, 'checked_packages', 'advisory_matches', ...SEVERITIES, 'duration_ms', 'duration_samples'];
const FIELD_NAMES = { checked_packages: 'checkedPackages', advisory_matches: 'advisoryMatches', duration_ms: 'durationMs', duration_samples: 'durationSamples' };
const unhealthy = new WeakSet();
const MAX_COUNT = 10_000_000;
const schema = `CREATE TABLE IF NOT EXISTS skill_usage_days (
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
CREATE TABLE IF NOT EXISTS skill_usage_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);`;

const own = (value, field) => {
  try {
    const descriptor = value && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, field) : null;
    return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  } catch { return undefined; }
};
const validTime = value => Number.isSafeInteger(value) && value >= 0 && value <= 8_640_000_000_000_000;
const readTime = now => typeof now === 'function' ? now() : now;
const dayName = value => new Date(value).toISOString().slice(0, 10);
const count = value => Number.isSafeInteger(value) && value >= 0 && value <= MAX_COUNT;
const inert = Object.freeze({ finish: () => false });

function facts(input) {
  const status = own(input, 'status');
  if (!STATUSES.includes(status)) return null;
  const packagesValue = own(input, 'checkedPackages'), matchesValue = own(input, 'advisoryMatches');
  const checkedPackages = packagesValue === undefined ? 0 : packagesValue;
  const advisoryMatches = matchesValue === undefined ? 0 : matchesValue;
  if (!count(checkedPackages) || !count(advisoryMatches)) return null;
  const supplied = own(input, 'severity');
  if (supplied !== undefined && (!supplied || typeof supplied !== 'object' || Array.isArray(supplied))) return null;
  const severity = Object.fromEntries(SEVERITIES.map(name => {
    const value = own(supplied, name);
    return [name, supplied === undefined ? name === 'unknown' ? advisoryMatches : 0 : value === undefined ? 0 : value];
  }));
  if (SEVERITIES.some(name => !count(severity[name])) || SEVERITIES.reduce((sum, name) => sum + severity[name], 0) !== advisoryMatches) return null;
  if (['failed', 'rejected'].includes(status) && (checkedPackages || advisoryMatches)) return null;
  return { status, checkedPackages, advisoryMatches, severity };
}

function counters(row, available = true) {
  if (!available) return { started: null, completed: null, partial: null, failed: null, rejected: null, unfinished: null,
    checkedPackages: null, advisoryMatches: null, severity: Object.fromEntries(SEVERITIES.map(name => [name, null])), durationMs: null, durationSamples: null };
  const values = Object.fromEntries(COLUMNS.map(column => [column, row?.[column] ?? 0]));
  if (Object.values(values).some(value => !Number.isSafeInteger(value) || value < 0)) throw new Error('Invalid aggregate counters.');
  const terminal = STATUSES.reduce((sum, status) => sum + values[status], 0);
  if (!Number.isSafeInteger(terminal) || terminal > values.started || values.duration_samples !== terminal ||
      SEVERITIES.reduce((sum, name) => sum + values[name], 0) !== values.advisory_matches) throw new Error('Inconsistent aggregate counters.');
  return { ...Object.fromEntries(COLUMNS.filter(column => !SEVERITIES.includes(column)).map(column => [FIELD_NAMES[column] || column, values[column]])),
    unfinished: values.started - terminal, severity: Object.fromEntries(SEVERITIES.map(name => [name, values[name]])) };
}

const sums = COLUMNS.map(column => `COALESCE(SUM(${column}), 0) AS ${column}`).join(', ');

/** Read-only operator aggregates. This never reads request traces or identities. */
export function skillUsageMetrics(db, { days = 30, now = Date.now } = {}) {
  if (![7, 30, 90].includes(days)) throw Object.assign(new Error('Choose 7, 30 or 90 days.'), { status: 400 });
  const generatedAt = readTime(now);
  if (!validTime(generatedAt)) throw Object.assign(new Error('Invalid metrics time.'), { status: 400 });
  const todayAt = Math.floor(generatedAt / DAY) * DAY, startAt = Math.max(0, todayAt - (days - 1) * DAY);
  const today = dayName(generatedAt), start = dayName(startAt);
  let available = false, trackingStartedAt = null, totals, lifetime, channelRows = [], operationRows = [], dayRows = [];
  try {
    if (unhealthy.has(db)) throw new Error('Usage recording failed.');
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('skill_usage_days', 'skill_usage_meta')").all();
    if (tables.length !== 2) throw new Error('Usage collection unavailable.');
    trackingStartedAt = db.prepare("SELECT value FROM skill_usage_meta WHERE key = 'tracking_started_at'").get()?.value;
    if (!validTime(trackingStartedAt) || trackingStartedAt > generatedAt) throw new Error('Invalid collection start.');
    totals = counters(db.prepare(`SELECT ${sums} FROM skill_usage_days WHERE operation = 'audit' AND day >= ? AND day <= ?`).get(start, today));
    lifetime = counters(db.prepare(`SELECT ${sums} FROM skill_usage_days WHERE operation = 'audit' AND day <= ?`).get(today));
    channelRows = db.prepare(`SELECT channel, ${sums} FROM skill_usage_days WHERE operation = 'audit' AND day >= ? AND day <= ? GROUP BY channel`).all(start, today);
    operationRows = db.prepare(`SELECT operation, ${sums} FROM skill_usage_days WHERE day >= ? AND day <= ? GROUP BY operation`).all(start, today);
    dayRows = db.prepare(`SELECT day, ${sums} FROM skill_usage_days WHERE operation = 'audit' AND day >= ? AND day <= ? GROUP BY day`).all(start, today);
    // Validate every grouped result before returning any numbers.
    for (const row of [...channelRows, ...operationRows, ...dayRows]) counters(row);
    available = true;
  } catch {
    totals = counters(null, false); lifetime = counters(null, false);
  }
  const channels = CHANNELS.map(channel => ({ channel, ...counters(channelRows.find(row => row.channel === channel), available) }));
  const operations = OPERATIONS.map(operation => ({ operation, ...counters(operationRows.find(row => row.operation === operation), available) }));
  const series = Array.from({ length: days }, (_, index) => {
    const at = todayAt - (days - 1 - index) * DAY;
    const date = dayName(Math.max(0, at));
    const tracked = available && at + DAY > trackingStartedAt && at >= 0;
    return { date, tracked, ...counters(dayRows.find(row => row.day === date), tracked) };
  });
  return { schemaVersion: 1, generatedAt, days, timezone: 'UTC',
    coverage: { available, trackingStartedAt: validTime(trackingStartedAt) ? trackingStartedAt : null, historyComplete: false,
      reason: available ? 'Collection starts at trackingStartedAt; older usage is unknown. No trace-history backfill.' : 'Skill usage collection is unavailable; missing observations are unknown.' },
    totals, lifetime, channels, operations, series,
    definitions: {
      audits: 'Public dependency audit attempts only. MCP initialization, tool discovery and planning-only requests are excluded from headline totals.',
      lifetime: 'Recorded audit totals since collection began, not total historical skill usage or installations.',
      advisoryMatches: 'Advisory occurrences returned by completed or partial audits. Repeat audits count again; these are not unique CVEs or confirmed vulnerabilities.',
      planning: 'Planning-only requests are shown separately in operations and never added to audit totals.',
      unfinished: 'Started without a recorded terminal outcome. May include interrupted requests; never assume these are currently running.',
      daily: 'UTC start-day cohorts, including requests that finish after midnight. Days before collection are unknown.',
      privacy: 'Only fixed channel/operation labels, day buckets, outcome counts and numeric measurements are stored. No identities, request IDs, source, dependency names or advisory IDs.'
    } };
}

/** Durable count-only collection, independent of the expiring diagnostic traces. */
export function createSkillUsageStore({ db, now = Date.now } = {}) {
  try {
    const time = readTime(now);
    if (!validTime(time)) throw new Error('Invalid collection time.');
    transactionSync(db, () => {
      db.exec(schema);
      db.prepare("INSERT INTO skill_usage_meta (key, value) VALUES ('tracking_started_at', ?) ON CONFLICT(key) DO NOTHING").run(time);
    });
  } catch { if (db && typeof db === 'object') unhealthy.add(db); }

  function start(input) {
    const channel = own(input, 'channel'), operation = own(input, 'operation');
    if (!CHANNELS.includes(channel) || !OPERATIONS.includes(operation) || unhealthy.has(db)) return inert;
    let startedAt, day;
    try {
      startedAt = readTime(now);
      if (!validTime(startedAt)) return inert;
      day = dayName(startedAt);
      db.prepare(`INSERT INTO skill_usage_days (day, channel, operation, started) VALUES (?, ?, ?, 1)
        ON CONFLICT(day, channel, operation) DO UPDATE SET started = started + 1`).run(day, channel, operation);
    } catch { if (db && typeof db === 'object') unhealthy.add(db); return inert; }
    let finished = false;
    return Object.freeze({ finish(input) {
      if (finished || unhealthy.has(db)) return false;
      const result = facts(input);
      if (!result) return false;
      let finishedAt;
      try { finishedAt = readTime(now); } catch { return false; }
      if (!validTime(finishedAt)) return false;
      // Claim the single terminal write before touching storage: an uncertain
      // write outcome is not retried and cannot accidentally double count.
      finished = true;
      try {
        const written = db.prepare(`UPDATE skill_usage_days SET ${result.status} = ${result.status} + 1,
          checked_packages = checked_packages + ?, advisory_matches = advisory_matches + ?,
          ${SEVERITIES.map(name => `${name} = ${name} + ?`).join(', ')}, duration_ms = duration_ms + ?, duration_samples = duration_samples + 1
          WHERE day = ? AND channel = ? AND operation = ?`)
          .run(result.checkedPackages, result.advisoryMatches, ...SEVERITIES.map(name => result.severity[name]),
            Math.max(0, finishedAt - startedAt), day, channel, operation);
        if (written.changes !== 1) throw new Error('Usage cohort is missing.');
        return true;
      } catch { unhealthy.add(db); return false; }
    } });
  }
  return Object.freeze({ start, read: options => skillUsageMetrics(db, { now, ...options }) });
}
