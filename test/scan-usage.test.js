import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { createHostedScans, hostedScanTools } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';
import { createScanUsage } from '../server/scan-usage.js';
import { scanController } from '../workers/scan-container.js';

const START = Date.UTC(2026, 9, 26, 12);
const DAY = 86_400_000;
const prices = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url)));
const toolIds = hostedScanTools().tools.map(tool => tool.id);
const source = [{ path: 'src/private-fixture.js', content: 'const privateFixtureMarker = "private-source-fixture";' }];
const observation = ms => ({ observer: 'container_controller', containerDurationMs: ms });
const facts = db => ({ jobs: db.prepare('SELECT * FROM scan_usage_jobs ORDER BY job_id').all(),
  tools: db.prepare('SELECT * FROM scan_usage_tools ORDER BY job_id, tool_id').all(),
  activity: db.prepare('SELECT * FROM scan_usage_activity ORDER BY day, workspace_id, tool_id, kind').all(),
  meta: db.prepare('SELECT * FROM scan_usage_meta ORDER BY key').all() });

function fixture(t, options = {}) {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  let at = START, result = { status: 'running' }, starts = 0, destroys = 0;
  const meter = createScanMetering(db, { enabled: options.enabled ?? true, priceByToolMicros: prices, now: () => at });
  const sandbox = {
    async start(input) { starts++; if (options.start) return options.start(input); return { status: 'running' }; },
    async get() { return result; },
    async destroy(id) { destroys++; if (options.destroy) return options.destroy(id); return { status: 'destroyed', usage: observation(1400) }; }
  };
  const config = { sandbox, metering: meter, now: () => at,
    encrypt: value => Buffer.from(value).toString('base64'), decrypt: value => Buffer.from(value, 'base64').toString() };
  const scans = createHostedScans(db, config), key = scans.issueKey('workspace-a', 'user-a'), principal = scans.authenticate(key.token);
  if (options.credit !== false) meter.recordVerifiedPurchase({ workspaceId: 'workspace-a', paymentId: 'payment-usage-fixture-001', amountMicros: 10_000_000 });
  return { db, meter, scans, key, principal, config, starts: () => starts, destroys: () => destroys,
    advance: ms => { at += ms; }, now: () => at, finish: report => { result = report; },
    create: (idempotency = 'usage-job-0001', tools = ['opengrep']) => scans.create(principal,
      { tools, files: source, maxChargeMicros: tools.reduce((sum, id) => sum + prices[id].baseMicros, 0) }, idempotency) };
}

function legacyJobs(db) {
  db.exec(`CREATE TABLE scan_jobs (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, key_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL, fingerprint TEXT NOT NULL, status TEXT NOT NULL,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER,
    input_bytes INTEGER NOT NULL, file_count INTEGER NOT NULL, result TEXT, error TEXT,
    selected_tools TEXT NOT NULL
  )`);
  return (id, { report = null, status = 'completed', createdAt = START - DAY, tools = ['opengrep'] } = {}) => {
    db.prepare(`INSERT INTO scan_jobs VALUES (?, 'workspace-a', 'user-a', 'key-a', ?, 'private-fingerprint', ?,
      ?, ?, ?, ?, 123, 1, ?, 'private-raw-error', ?)`)
      .run(id, id, status, createdAt, createdAt + 3000, createdAt + 1000, createdAt + 3000,
        report === null ? null : JSON.stringify(report), JSON.stringify(tools));
  };
}

test('job and tool facts follow the real lifecycle once and survive retry, reconstruction, and report expiry', async t => {
  const f = fixture(t), job = f.create();
  assert.equal(facts(f.db).jobs[0].status, 'queued');
  assert.equal(facts(f.db).jobs[0].findings_count, null);
  assert.equal(f.scans.create(f.principal, { files: source, tools: ['opengrep'], maxChargeMicros: 25000 }, 'usage-job-0001').id, job.id);
  f.advance(200); await f.scans.dispatch();
  assert.equal(f.starts(), 1);
  assert.equal(facts(f.db).jobs[0].status, 'running');
  f.advance(900);
  f.finish({ status: 'completed', tools: [{ name: 'opengrep', status: 'complete', durationMs: 600 }],
    findings: [{ tool: 'opengrep', severity: 'HIGH' }], execution: observation(1100) });
  await f.scans.dispatch();
  const first = facts(f.db);
  assert.equal(first.jobs.length, 1); assert.equal(first.tools.length, 1);
  assert.equal(first.jobs[0].queue_ms, 200); assert.equal(first.jobs[0].execution_ms, 900);
  assert.equal(first.jobs[0].container_ms, 1400); assert.equal(first.tools[0].duration_ms, 600);
  assert.equal(first.tools[0].status, 'complete'); assert.equal(first.jobs[0].findings_count, 1);
  assert.equal(f.meter.status('workspace-a').balanceMicros, 9_975_000);
  const rebuilt = createHostedScans(f.db, f.config);
  assert.equal(rebuilt.create(f.principal, { files: source, tools: ['opengrep'], maxChargeMicros: 25000 }, 'usage-job-0001').id, job.id);
  assert.deepEqual(facts(f.db), first);
  f.advance(31 * DAY); await rebuilt.dispatch();
  assert.equal(f.db.prepare('SELECT result FROM scan_jobs WHERE id=?').get(job.id).result, null);
  assert.deepEqual(facts(f.db), first);
  assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_entries WHERE kind='usage'").get().n, 1);
});

test('usage facts persist only numeric summaries and fixed tool labels, not private report or source fields', async t => {
  const f = fixture(t), job = f.create('privacy-usage-0001', ['opengrep', 'gitleaks']);
  await f.scans.dispatch();
  const secret = 'PRIVATE_CREDENTIAL_MARKER_123';
  f.finish({ status: 'completed', private: secret,
    tools: [{ name: 'opengrep', status: 'complete', durationMs: 0, error: secret }, { name: 'gitleaks', status: 'complete', durationMs: 800 },
      { name: secret, status: 'complete', durationMs: 7 }],
    findings: [
      { tool: 'opengrep', severity: 'CRITICAL', file: `private/${secret}.js`, source: secret },
      { tool: 'opengrep', severity: 'high', evidence: secret },
      { tool: 'opengrep', severity: secret, raw: secret },
      { tool: 'gitleaks', severity: 'MEDIUM', secret, url: `https://${secret}.example.com` }
    ],
    coverage: { outboundConnections: 12, networkFailures: 1, target: `https://${secret}.example.com`, raw: secret },
    execution: { observer: 'container_controller', containerDurationMs: 900, token: secret } });
  await f.scans.dispatch();
  const captured = facts(f.db), serialized = JSON.stringify(captured);
  for (const marker of [secret, source[0].content, source[0].path, f.key.token, 'private-fingerprint']) assert.ok(!serialized.includes(marker));
  assert.deepEqual(captured.tools.map(row => row.tool_id), ['gitleaks', 'opengrep']);
  const code = captured.tools.find(row => row.tool_id === 'opengrep');
  assert.deepEqual([code.critical, code.high, code.medium, code.low, code.unknown], [1, 1, 0, 0, 1]);
  assert.equal(code.duration_ms, 0);
  assert.equal(captured.jobs[0].outbound_connections, 12);
  assert.equal(captured.jobs[0].network_failures, 1);
  assert.equal(captured.jobs[0].job_id, job.id);
});

test('bounded historical backfill preserves unknown metrics and distinguishes measured zero findings', t => {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const put = legacyJobs(db);
  put('expired-report', { createdAt: START - 60 * DAY });
  put('known-clean', { report: { tools: [{ name: 'opengrep', status: 'complete', durationMs: 0 }], findings: [] } });
  put('known-finding', { report: { tools: [{ name: 'opengrep', status: 'complete', durationMs: 300 }],
    findings: [{ tool: 'opengrep', severity: 'LOW' }] } });
  const usage = createScanUsage(db, { toolIds, now: () => START });
  assert.equal(usage.backfill(1), 1); assert.equal(facts(db).jobs.length, 1);
  assert.equal(usage.backfill(100), 2); assert.equal(usage.backfill(100), 0);
  const rows = new Map(facts(db).jobs.map(row => [row.job_id, row]));
  assert.equal(rows.get('expired-report').findings_count, null);
  assert.equal(rows.get('expired-report').container_ms, null);
  assert.equal(rows.get('expired-report').outbound_connections, null);
  assert.equal(rows.get('expired-report').queue_ms, 1000);
  assert.equal(rows.get('expired-report').execution_ms, 2000);
  assert.equal(rows.get('known-clean').findings_count, 0);
  assert.equal(rows.get('known-finding').findings_count, 1);
  const expiredTool = db.prepare('SELECT * FROM scan_usage_tools WHERE job_id=?').get('expired-report');
  assert.equal(expiredTool.duration_ms, null); assert.equal(expiredTool.status, 'missing');
  assert.equal(expiredTool.high, null);
  assert.equal(db.prepare("SELECT value FROM scan_usage_meta WHERE key='tracking_started_at'").get().value, START);
  createScanUsage(db, { toolIds, now: () => START + DAY });
  assert.equal(db.prepare("SELECT value FROM scan_usage_meta WHERE key='tracking_started_at'").get().value, START);
  for (const invalid of [0, -1, 101, 1.5]) assert.throws(() => usage.backfill(invalid), /backfill limit/);
});

test('actual quote and rejection activity is counted without treating catalogue display as a quote or job', t => {
  const f = fixture(t, { credit: false });
  f.scans.tools('workspace-a'); f.scans.tools('workspace-a');
  assert.deepEqual(facts(f.db).activity, []);
  f.scans.quote({ tools: ['opengrep'], inputBytes: 20, fileCount: 1 }, 'workspace-a');
  f.scans.quote({ tools: ['opengrep'], inputBytes: 20, fileCount: 1 }, 'workspace-a');
  assert.throws(() => f.scans.quote({ tools: ['PRIVATE_LABEL'], inputBytes: 20, fileCount: 1 }, 'workspace-a'));
  assert.throws(() => f.create('underfunded-usage-001'), error => error.status === 402);
  const activity = new Map(facts(f.db).activity.map(row => [row.kind, row]));
  assert.equal(activity.get('quote_issued').count, 2);
  assert.equal(activity.get('quote_denied').count, 1);
  assert.equal(activity.get('quote_denied').tool_id, 'unknown');
  assert.equal(activity.get('submission_denied').count, 1);
  assert.equal(facts(f.db).jobs.length, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_meter_jobs').get().n, 0);
  assert.equal(f.meter.status('workspace-a').reservedMicros, 0);
  assert.equal(f.meter.status('workspace-a').balanceMicros, 0);
  assert.ok(!JSON.stringify(facts(f.db)).includes('PRIVATE_LABEL'));
});

test('unconfigured scanner submission records one denial and creates no retained job or phantom debit', t => {
  const f = fixture(t);
  const scans = createHostedScans(f.db, { metering: f.meter, now: f.now });
  assert.throws(() => scans.create(f.principal, { files: source, tools: ['opengrep'], maxChargeMicros: 50000 }, 'not-configured-0001'),
    error => error.status === 503);
  assert.equal(f.db.prepare("SELECT count FROM scan_usage_activity WHERE kind='submission_denied'").get().count, 1);
  assert.equal(facts(f.db).jobs.length, 0);
  assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_entries WHERE kind='usage'").get().n, 0);
});

test('start failures, expired queue jobs and cleanup retries retain operational usage without charging credit', async t => {
  let cleanupAttempts = 0;
  const f = fixture(t, { start: async () => { throw new Error('private-upstream-failure'); }, destroy: async () => {
    if (++cleanupAttempts === 1) throw new Error('temporary cleanup failure');
    return { status: 'destroyed', usage: observation(600) };
  } });
  const failed = f.create('failed-start-usage01'); await f.scans.dispatch();
  assert.equal(facts(f.db).jobs[0].status, 'failed');
  assert.equal(facts(f.db).jobs[0].container_ms, null);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_cleanup').get().n, 1);
  await f.scans.dispatch();
  assert.equal(facts(f.db).jobs[0].container_ms, 600);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_cleanup').get().n, 0);
  const expired = f.create('expired-usage-0001'); f.advance(31 * 60_000); await f.scans.dispatch();
  const rows = new Map(facts(f.db).jobs.map(row => [row.job_id, row]));
  assert.equal(rows.get(expired.id).status, 'failed'); assert.equal(rows.get(expired.id).started_at, null);
  assert.equal(rows.get(expired.id).queue_ms, null);
  assert.equal(f.scans.get(failed.id, 'workspace-a').metering.chargeMicros, 0);
  assert.equal(f.scans.get(expired.id, 'workspace-a').metering.chargeMicros, 0);
  assert.equal(f.meter.status('workspace-a').balanceMicros, 10_000_000);
  assert.equal(f.meter.status('workspace-a').reservedMicros, 0);
});

test('Worker timing comes from the controller and repeated cleanup excludes later idle time', async t => {
  let at = START, destroyed = 0;
  t.mock.method(Date, 'now', () => at);
  const saved = new Map();
  const ctx = { storage: { kv: { get: key => saved.get(key), put: (key, value) => saved.set(key, value) },
    setAlarm: async () => {}, deleteAlarm: async () => {} },
  container: { running: false, images: { scan: 'fixture-image' }, start() { this.running = true; },
    setInactivityTimeout: async () => {},
    async exec(argv) { return { output: async () => ({ exitCode: 0, stdout: new TextEncoder().encode(JSON.stringify({
      status: 'completed', tools: [{ name: 'opengrep', status: 'complete' }], findings: [],
      execution: { observer: 'container_controller', containerDurationMs: 999999999, private: 'PRIVATE_EXECUTABLE_VALUE' }
    })) }) }; },
    async destroy() { destroyed++; at += 100; this.running = false; } } };
  const controller = scanController(ctx);
  await controller.start({ files: source, tools: ['opengrep'] }); at += 500;
  const report = await controller.get();
  assert.deepEqual(report.execution, observation(500));
  assert.ok(!JSON.stringify(report.execution).includes('PRIVATE_EXECUTABLE_VALUE'));
  const first = await controller.destroy();
  assert.deepEqual(first.usage, observation(600));
  at += DAY;
  assert.deepEqual(await controller.destroy(), first);
  assert.equal(destroyed, 1);
});

test('an already stopped VM cannot fabricate a lifecycle duration from a later cleanup request', async t => {
  let at = START; t.mock.method(Date, 'now', () => at);
  const saved = new Map(), ctx = { storage: { kv: { get: key => saved.get(key), put: (key, value) => saved.set(key, value) },
    setAlarm: async () => {}, deleteAlarm: async () => {} }, container: { images: { scan: 'fixture-image' }, running: false,
      start() { this.running = true; }, setInactivityTimeout: async () => {}, exec: async () => ({}), destroy: async () => {} } };
  const controller = scanController(ctx); await controller.start({ files: source, tools: ['opengrep'] });
  ctx.container.running = false; at += 10 * 60_000;
  const cleanup = await controller.destroy(); assert.equal(cleanup.usage, undefined);
});

test('the additive usage migration and producer bootstrap preserve existing wallet rows', t => {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const put = legacyJobs(db); put('legacy-complete', { report: { findings: [], tools: [{ name: 'opengrep', status: 'complete' }] } });
  const meter = createScanMetering(db);
  meter.recordVerifiedPurchase({ workspaceId: 'workspace-a', paymentId: 'legacy-payment-0001', amountMicros: 5_000_000 });
  const before = db.prepare('SELECT * FROM scan_wallet_entries').all();
  db.exec(readFileSync(new URL('../migrations/0006_scan_usage.sql', import.meta.url), 'utf8'));
  const scans = createHostedScans(db, { metering: meter, now: () => START });
  assert.equal(facts(db).jobs.length, 1); assert.equal(facts(db).jobs[0].findings_count, 0);
  assert.deepEqual(db.prepare('SELECT * FROM scan_wallet_entries').all(), before);
  const summary = scans.usage('workspace-a'); assert.ok(summary.analytics);
  assert.deepEqual(db.prepare('SELECT * FROM scan_wallet_entries').all(), before);
});

test('historical usage backfill keeps progressing in bounded batches when no sandbox is configured', async t => {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const put = legacyJobs(db);
  for (let index = 0; index < 250; index++) put(`restored-${String(index).padStart(3, '0')}`, {
    createdAt: START - 40 * DAY,
    report: { findings: [], tools: [{ name: 'opengrep', status: 'complete', durationMs: 50 }] }
  });
  const meter = createScanMetering(db);
  const scans = createHostedScans(db, { metering: meter, now: () => START });
  const retainedReports = () => db.prepare('SELECT COUNT(*) AS n FROM scan_jobs WHERE result IS NOT NULL').get().n;
  assert.equal(facts(db).jobs.length, 100);
  assert.equal(retainedReports(), 250);
  await scans.dispatch();
  assert.equal(facts(db).jobs.length, 200);
  assert.equal(retainedReports(), 50, 'uncaptured reports remain available for the next bounded batch');
  await scans.dispatch();
  assert.equal(facts(db).jobs.length, 250);
  assert.equal(retainedReports(), 0);
  assert.ok(facts(db).jobs.every(row => row.findings_count === 0));
  assert.ok(facts(db).tools.every(row => row.duration_ms === 50));
  await scans.dispatch();
  assert.equal(facts(db).jobs.length, 250);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_wallet_entries').get().n, 0);
});

test('expired report backfill recovers retained tool observations without inventing findings or severity counts', t => {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const put = legacyJobs(db), jobId = 'a'.repeat(32);
  put(jobId, { tools: ['opengrep', 'gitleaks'], createdAt: START - 40 * DAY });
  const meter = createScanMetering(db);
  const quote = meter.quote({ tools: ['opengrep', 'gitleaks'], inputBytes: 123, fileCount: 1 });
  meter.reserve({ jobId, workspaceId: 'workspace-a', quote });
  meter.settle({ jobId, status: 'completed', tools: [
    { name: 'opengrep', status: 'complete', durationMs: 700, source: 'PRIVATE_RETAINED_VALUE' },
    { name: 'gitleaks', status: 'complete', durationMs: 0 },
    { name: 'PRIVATE_UNSELECTED_LABEL', status: 'complete', durationMs: 9 }
  ] });
  const before = db.prepare('SELECT * FROM scan_meter_jobs').all();
  const usage = createScanUsage(db, { toolIds, now: () => START });
  assert.equal(usage.backfill(), 1);
  const result = facts(db), rows = new Map(result.tools.map(row => [row.tool_id, row]));
  assert.deepEqual([...rows.keys()], ['gitleaks', 'opengrep']);
  assert.equal(rows.get('opengrep').status, 'complete'); assert.equal(rows.get('opengrep').duration_ms, 700);
  assert.equal(rows.get('gitleaks').status, 'complete'); assert.equal(rows.get('gitleaks').duration_ms, 0);
  for (const row of result.tools) {
    for (const field of ['findings_count', 'critical', 'high', 'medium', 'low', 'unknown']) assert.equal(row[field], null);
  }
  for (const field of ['findings_count', 'container_ms', 'outbound_connections', 'network_failures']) assert.equal(result.jobs[0][field], null);
  assert.ok(!JSON.stringify(result).includes('PRIVATE_'));
  assert.deepEqual(db.prepare('SELECT * FROM scan_meter_jobs').all(), before);
  usage.capture(jobId);
  assert.deepEqual(facts(db), result);
});
