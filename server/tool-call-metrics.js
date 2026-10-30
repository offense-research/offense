import { transactionSync } from './db-transaction.js';
import { isMetricsOperator } from './discovery-dashboard.js';

const DAY = 86_400_000;
const STATUSES = ['completed', 'failed', 'rejected'];
const KINDS = ['tool', 'request'];
const CHANNELS = ['http', 'mcp'];
const OPERATIONS = ['audit', 'planning', 'hosted_scan', 'capabilities', 'catalog', 'quote', 'result', 'account', 'usage', 'topup', 'target_challenge', 'target_verify', 'artifact_upload', 'mcp_transport'];
const TOOL_OPERATIONS = new Set(['audit', 'planning', 'hosted_scan']);
const requestState = Symbol('offense.toolCallMetrics');
const unhealthy = new WeakSet();
const inert = Object.freeze({ finish: () => false });
const validTime = value => Number.isSafeInteger(value) && value >= 0 && value <= 8_640_000_000_000_000;
const readTime = now => typeof now === 'function' ? now() : now;
const dayName = at => new Date(at).toISOString().slice(0, 10);
const unknown = () => ({ total: null, completed: null, failed: null, rejected: null, unfinished: null });
const fail = message => Object.assign(new Error(message), { status: 400 });

function recordingFailure(db, now) {
  unhealthy.add(db);
  // Preserve a numeric coverage warning when metadata remains writable. A
  // completely unavailable database cannot durably describe its own outage.
  try {
    const at = readTime(now);
    if (validTime(at)) db.prepare("INSERT INTO tool_call_meta(key,value) VALUES ('recording_failed_at',?) ON CONFLICT(key) DO UPDATE SET value = MIN(value,excluded.value)").run(at);
  } catch { /* Collection failure must never fail an application request. */ }
}

const routes = [
  ['POST', '/api/offense/audit', 'audit', true],
  ['POST', '/api/skill/scan', 'audit', true],
  ['POST', '/api/skill/plan', 'planning', true],
  ['GET', '/api/offense/capabilities', 'capabilities'],
  ['GET', '/v1/catalog', 'catalog'],
  ['GET', '/v1/tools', 'catalog'],
  ['GET', '/v1/usage', 'usage'],
  ['POST', '/v1/quotes', 'quote'],
  ['POST', '/v1/scans', 'hosted_scan', true],
  ['GET', '/v1/scans/:id', 'result'],
  ['POST', '/v1/call/:tool', 'hosted_scan', true],
  ['GET', '/v1/account', 'account'],
  ['POST', '/v1/billing/topups', 'topup'],
  ['POST', '/v1/targets/challenge', 'target_challenge'],
  ['POST', '/v1/targets/verify', 'target_verify'],
  ['POST', '/v1/artifacts', 'artifact_upload'],
  ...['GET', 'POST', 'DELETE', 'OPTIONS', 'HEAD', 'PUT', 'PATCH'].map(method => [method, '/mcp', 'mcp_transport'])
];
for (const route of routes.slice()) if (route[0] === 'GET' && route[1] !== '/mcp') routes.push(['HEAD', ...route.slice(1)]);
const routeByEndpoint = new Map(routes.map(([method, path, operation, tool]) => [`${method} ${path}`, { operation, tool: !!tool, channel: path === '/mcp' ? 'mcp' : 'http' }]));
const mcpOperations = new Map([
  ['offense.audit_dependencies', 'audit'], ['offense.security_call', 'hosted_scan']
]);
const mcpEndpoint = operation => operation === 'audit' || operation === 'planning' ? 'offense.audit_dependencies' : operation === 'hosted_scan' ? 'offense.security_call' : null;

export const TOOL_CALL_TABLES = ['tool_call_days', 'tool_call_meta'];
export const TOOL_CALL_SCHEMA = `CREATE TABLE IF NOT EXISTS tool_call_days (
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
CREATE TABLE IF NOT EXISTS tool_call_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);`;

export function toolCallOperation(name) { return mcpOperations.get(name) || null; }

function validLabels({ kind, channel, operation, endpoint }) {
  if (!KINDS.includes(kind) || !CHANNELS.includes(channel) || !OPERATIONS.includes(operation)) return false;
  if (kind === 'tool' && channel === 'mcp') return TOOL_OPERATIONS.has(operation) && endpoint === mcpEndpoint(operation);
  const route = routeByEndpoint.get(endpoint);
  return !!route && route.channel === channel && route.operation === operation && (kind === 'request' || route.tool);
}

function counters(row) {
  const result = { total: row?.started ?? 0, completed: row?.completed ?? 0, failed: row?.failed ?? 0, rejected: row?.rejected ?? 0 };
  if (Object.values(result).some(value => !Number.isSafeInteger(value) || value < 0)) throw Error('Invalid call counters.');
  const terminal = result.completed + result.failed + result.rejected;
  if (!Number.isSafeInteger(terminal) || terminal > result.total) throw Error('Invalid terminal call counters.');
  return { ...result, unfinished: result.total - terminal };
}
const sums = 'COALESCE(SUM(started),0) AS started, COALESCE(SUM(completed),0) AS completed, COALESCE(SUM(failed),0) AS failed, COALESCE(SUM(rejected),0) AS rejected';

function classify(req) {
  if (typeof req.path !== 'string' || typeof req.method !== 'string') return null;
  let path = req.path.toLowerCase().replace(/\/$/, '');
  if (/^\/v1\/scans\/[a-f0-9]{32}$/.test(path)) path = '/v1/scans/:id';
  if (/^\/v1\/call\/[a-z0-9-]{1,80}$/.test(path)) path = '/v1/call/:tool';
  const endpoint = `${req.method.toUpperCase()} ${path}`;
  const route = routeByEndpoint.get(endpoint);
  return route ? { ...route, endpoint } : null;
}

/** Override an HTTP-200 MCP envelope with its actual RPC outcome. No raw data is retained. */
export function markToolCallOutcome(req, status) {
  if (!STATUSES.includes(status)) return false;
  try {
    if (!req?.[requestState]) return false;
    req[requestState].status = status;
    return true;
  } catch { return false; }
}

/** Count-only daily cohorts, independent of identities, jobs and expiring traces. */
export function createToolCallMetrics({ db, now = Date.now } = {}) {
  if (!db || typeof db !== 'object') throw Error('Call metrics require storage.');
  try {
    const at = readTime(now);
    if (!validTime(at)) throw Error('Invalid tracking time.');
    transactionSync(db, () => {
      db.exec(TOOL_CALL_SCHEMA);
      db.prepare("INSERT INTO tool_call_meta(key,value) VALUES ('tracking_started_at',?) ON CONFLICT(key) DO NOTHING").run(at);
    });
  } catch { recordingFailure(db, now); }

  function start(input) {
    let kind, channel, operation, endpoint, day;
    try {
      ({ kind, channel, operation, endpoint } = input || {});
      if (endpoint === undefined && kind === 'tool' && channel === 'mcp') endpoint = mcpEndpoint(operation);
      if (!validLabels({ kind, channel, operation, endpoint }) || unhealthy.has(db)) return inert;
      const at = readTime(now);
      if (!validTime(at)) return inert;
      day = dayName(at);
      db.prepare(`INSERT INTO tool_call_days(day,kind,channel,operation,endpoint,started) VALUES (?,?,?,?,?,1)
        ON CONFLICT(day,kind,channel,operation,endpoint) DO UPDATE SET started = started + 1`).run(day, kind, channel, operation, endpoint);
    } catch { recordingFailure(db, now); return inert; }
    let finished = false;
    return Object.freeze({ finish(input) {
      let status; try { status = input?.status; } catch { return false; }
      if (finished || unhealthy.has(db) || !STATUSES.includes(status)) return false;
      finished = true;
      try {
        const result = db.prepare(`UPDATE tool_call_days SET ${status} = ${status} + 1 WHERE day = ? AND kind = ? AND channel = ? AND operation = ? AND endpoint = ?`)
          .run(day, kind, channel, operation, endpoint);
        if (result.changes !== 1) throw Error('Call cohort is missing.');
        return true;
      } catch { recordingFailure(db, now); return false; }
    } });
  }

  function middleware() {
    return (req, res, next) => {
      let route;
      try { route = classify(req); } catch { /* Metrics never prevent a request. */ }
      if (!route) return next();
      const { channel, operation, endpoint } = route;
      const tickets = [start({ kind: 'request', channel, operation, endpoint })];
      if (route.tool) tickets.push(start({ kind: 'tool', channel, operation, endpoint }));
      req[requestState] = { status: null };
      const finish = closed => {
        const status = req[requestState]?.status || (closed ? 'failed' : res.statusCode >= 500 ? 'failed' : res.statusCode >= 400 ? 'rejected' : 'completed');
        for (const ticket of tickets) ticket.finish({ status });
      };
      res.once('finish', () => finish(false));
      res.once('close', () => finish(!res.writableFinished));
      next();
    };
  }

  function read({ days = 30, scope = 'tools' } = {}) {
    if (![7, 30, 90].includes(days) || !['tools', 'requests'].includes(scope)) throw fail('Choose 7, 30 or 90 days and a tools or requests scope.');
    const generatedAt = readTime(now);
    if (!validTime(generatedAt) || generatedAt < days * DAY) throw fail('Invalid call metrics time.');
    const kind = scope === 'tools' ? 'tool' : 'request';
    const todayAt = Math.floor(generatedAt / DAY) * DAY, startAt = todayAt - (days - 1) * DAY;
    const todayDay = dayName(todayAt), yesterdayDay = dayName(todayAt - DAY), startDay = dayName(startAt);
    let available = false, trackingStartedAt = null, recordingFailedAt = null, totals = unknown(), lifetime = unknown(), today = unknown(), yesterday = unknown(), rows = [], grouped = [];
    try {
      const failed = db.prepare("SELECT value FROM tool_call_meta WHERE key = 'recording_failed_at'").get()?.value;
      if (failed !== undefined && (!validTime(failed) || failed > generatedAt)) throw Error('Invalid recording coverage marker.');
      recordingFailedAt = failed ?? null;
      if (unhealthy.has(db)) throw Error('Call collection failed.');
      trackingStartedAt = db.prepare("SELECT value FROM tool_call_meta WHERE key = 'tracking_started_at'").get()?.value;
      if (!validTime(trackingStartedAt) || trackingStartedAt > generatedAt) throw Error('Call collection start is unavailable.');
      const labels = db.prepare('SELECT DISTINCT kind,channel,operation,endpoint FROM tool_call_days LIMIT 500').all();
      if (labels.length >= 500 || labels.some(row => !validLabels(row))) throw Error('Invalid call labels.');
      const earliest = db.prepare('SELECT MIN(day) AS day FROM tool_call_days').get()?.day;
      if (earliest && earliest < dayName(trackingStartedAt)) throw Error('Call collection history is inconsistent.');
      totals = counters(db.prepare(`SELECT ${sums} FROM tool_call_days WHERE kind = ? AND day >= ? AND day <= ?`).get(kind, startDay, todayDay));
      lifetime = counters(db.prepare(`SELECT ${sums} FROM tool_call_days WHERE kind = ? AND day <= ?`).get(kind, todayDay));
      rows = db.prepare(`SELECT day,${sums} FROM tool_call_days WHERE kind = ? AND day >= ? AND day <= ? GROUP BY day`).all(kind, startDay, todayDay);
      for (const row of rows) counters(row);
      grouped = db.prepare(`SELECT operation,endpoint,channel,${sums} FROM tool_call_days WHERE kind = ? AND day >= ? AND day <= ?
        GROUP BY operation,endpoint,channel ORDER BY started DESC,endpoint,channel`).all(kind, startDay, todayDay);
      for (const row of grouped) counters(row);
      today = counters(rows.find(row => row.day === todayDay));
      yesterday = trackingStartedAt < todayAt ? counters(rows.find(row => row.day === yesterdayDay)) : unknown();
      available = true;
    } catch {
      totals = unknown(); lifetime = unknown(); today = unknown(); yesterday = unknown(); rows = []; grouped = [];
    }
    const daysByName = new Map(rows.map(row => [row.day, row]));
    const comparable = available && recordingFailedAt === null && trackingStartedAt <= todayAt - DAY;
    const absolute = comparable ? today.total - yesterday.total : null;
    const percent = comparable && yesterday.total > 0 ? absolute / yesterday.total * 100 : null;
    const series = Array.from({ length: days }, (_, index) => {
      const at = startAt + index * DAY, date = dayName(at), tracked = available && at + DAY > trackingStartedAt;
      return { date, tracked, ...(tracked ? counters(daysByName.get(date)) : unknown()) };
    });
    return { schemaVersion: 1, audience: 'operator', scope, days, timezone: 'UTC', generatedAt,
      coverage: { available, trackingStartedAt: validTime(trackingStartedAt) ? trackingStartedAt : null, historyComplete: false,
        hasRecordingGap: recordingFailedAt !== null, recordingFailedAt,
        reason: available ? recordingFailedAt !== null ? 'A collection gap may omit calls or outcomes. Totals reflect accepted counter records; historical comparisons are withheld.' : 'Recorded since trackingStartedAt. Earlier endpoint-call history is unknown; no job or trace-history backfill.' : 'Call collection is unavailable. Missing counts are unknown.' },
      lifetime, totals, today, yesterday, change: { absolute, percent, comparable }, series,
      breakdown: grouped.map(({ operation, endpoint, channel, ...row }) => ({ operation, endpoint, channel, ...counters(row) })),
      definitions: {
        tools: 'Security-action attempts: dependency audits, planning and hosted scan submissions across HTTP and MCP. Catalog, quotes, account reads and status polling are excluded.',
        requests: 'Recognized Offense API HTTP requests, including MCP transport messages, catalog, quotes, status polling and binary artifact uploads. Auth, browser console polling, billing webhooks, health checks, static files and unknown-path probes are excluded.',
        retries: 'Each incoming attempt counts once, including repeated idempotent submissions, rejections and failures. A reused job does not erase a tool call.',
        coverage: 'Counts reflect accepted counter records. A persisted recording-failure marker warns of missing calls or outcomes after recovery; completely unavailable storage cannot persist its own coverage warning.',
        completed: 'The request returned successfully; this is not a claim that a queued scan completed or a vulnerability was confirmed.',
        unfinished: 'Started without a recorded terminal outcome; this is not a count of currently running scans.',
        daily: 'UTC start-day cohorts. Today and the tracking-start day may be partial. Yesterday comparisons require a completely observed prior day; no percentage is inferred from zero.',
        privacy: 'Only fixed endpoint, operation, channel and UTC day labels plus numeric outcome counts are persisted. No identities, addresses, keys, request IDs, source or payloads.'
      } };
  }

  return Object.freeze({ start, read, middleware });
}

export function registerToolCallMetrics(app, { store, operatorIds }) {
  app.get('/api/operator/tool-calls', (req, res) => {
    res.set('Cache-Control', 'no-store'); res.set('Vary', 'Cookie');
    if (!req.authUser) return res.status(401).json({ error: 'Sign in to view company calls.' });
    if (!isMetricsOperator(req.authUser, operatorIds)) return res.status(403).json({ error: 'Company metrics require operator access.' });
    if (Object.keys(req.query).some(key => !['days', 'scope'].includes(key)) ||
        req.query.days !== undefined && (typeof req.query.days !== 'string' || !/^(7|30|90)$/.test(req.query.days)) ||
        req.query.scope !== undefined && (typeof req.query.scope !== 'string' || !['tools', 'requests'].includes(req.query.scope)))
      return res.status(400).json({ error: 'Choose only days (7, 30 or 90) and scope (tools or requests).' });
    try { res.json(store.read({ days: req.query.days === undefined ? 30 : Number(req.query.days), scope: req.query.scope || 'tools' })); }
    catch { res.status(503).json({ error: 'Company call metrics are temporarily unavailable.' }); }
  });
}
