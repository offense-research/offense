import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import express from 'express';
import { createOffenseTraceStore, beginOffenseRequest, OFFENSE_TRACE_LIMITS } from '../server/offense-traces.js';
import { createDependencyIntelligence } from '../server/dependency-intelligence.js';
import { registerOffenseApi } from '../server/offense-api.js';
import { registerSkillApi } from '../server/skill-api.js';

const canary = 'PRIVATE_CUSTOMER_PATIENT_HARRIET_2077_secret';
const clientId = 'a691b731-d937-44ac-a461-7955c21fa630';
const privatePackage = '@private-customer/security-canary';
const files = [{ path: 'customer-private/package-lock.json', content: { lockfileVersion: 3, name: canary, packages: {
  '': { name: canary, dependencies: { [privatePackage]: '^1.0.0' }, scripts: { preinstall: canary } },
  ['node_modules/' + privatePackage]: { version: '1.0.0', resolved: `https://user:${canary}@private-registry.example/pkg` }
} } }];
const check = async packages => ({ status: 'complete', checkedPackages: packages.length, findings: packages.map(pkg => ({ id: 'GHSA-private-canary',
  package: pkg.name, version: pkg.version, severity: 'HIGH', summary: canary, fixedVersions: ['1.0.1'], advisory: { details: canary } })) });
const plan = async (snapshot, name, currentVersion) => ({ name, currentVersion, targetVersion: '1.0.1', steps: [{ text: canary }],
  considered: [{ version: '1.0.1', advisories: 0 }], parentOptions: [], impact: { paths: [[canary, name]], parents: [] } });

function database(t) {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close()); return db;
}
async function fixture(t, options = {}) {
  const db = database(t), app = express();
  const usedDb = options.dbFactory ? options.dbFactory(db) : db;
  const intelligence = createDependencyIntelligence({ db: usedDb, check, plan, ...options });
  registerSkillApi(app, { intelligence }); registerOffenseApi(app, { intelligence, publicUrl: 'http://127.0.0.1' });
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  return { db, intelligence, url: `http://127.0.0.1:${server.address().port}` };
}
const post = (url, body, path = '/api/offense/audit', moreHeaders = {}) => fetch(url + path, { method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Offense-Request-Id': clientId, 'X-Client-Trace-Id': clientId,
    Authorization: `Bearer ${canary}`, 'User-Agent': canary, ...moreHeaders }, body: typeof body === 'string' ? body : JSON.stringify(body) });
const allRows = db => db.prepare('SELECT request_id, created_at, expires_at, bytes, event FROM offense_trace_events').all();
function assertNoPrivateData(value) {
  const serialized = JSON.stringify(value);
  for (const forbidden of [canary, privatePackage, 'private-registry.example', 'customer-private', clientId, '127.0.0.1',
    createHash('sha256').update(canary).digest('hex'), createHash('sha256').update('127.0.0.1').digest('hex')]) {
    assert.ok(!serialized.includes(forbidden), `Unexpected private field in trace: ${forbidden}`);
  }
  for (const forbiddenKey of ['payload', 'headers', 'ip', 'userAgent', 'fingerprint', 'metadataFingerprint', 'prompt', 'stack', 'message', 'repository']) {
    assert.ok(!serialized.includes(`"${forbiddenKey}"`), `Unexpected field ${forbiddenKey}`);
  }
}

test('only allowlisted constructor-owned events reach SQLite; unknown fields, getters and identity hashes never do', t => {
  const db = database(t), observedBindings = [];
  const observedDb = { exec: sql => db.exec(sql), prepare(sql) {
    const statement = db.prepare(sql);
    return { get: (...args) => statement.get(...args), all: (...args) => statement.all(...args), run(...args) {
      if (sql.startsWith('INSERT INTO offense_trace_events')) observedBindings.push(args);
      return statement.run(...args);
    } };
  } };
  const store = createOffenseTraceStore({ db: observedDb }), trace = store.start('https');
  let getterCalls = 0;
  const fields = { requestId: clientId, runId: clientId, eventId: clientId, errorCode: canary, message: canary, stack: canary,
    payload: { body: canary }, headers: { Authorization: canary }, fingerprint: createHash('sha256').update(canary).digest('hex'),
    counts: { packages: 4, matches: 1, [canary]: 27, secret: canary }, durationMs: 193 };
  Object.defineProperty(fields, 'privateGetter', { get() { getterCalls++; throw Error(canary); } });
  Object.defineProperty(fields, 'evidenceSource', { get() { getterCalls++; throw Error(canary); } });
  trace.record('advisory_scan', 'completed', fields);
  const rows = allRows(db); assert.equal(rows.length, 1); assert.equal(observedBindings.length, 1);
  assertNoPrivateData(rows); assertNoPrivateData(observedBindings); assert.equal(getterCalls, 0);
  const event = store.read()[0]; assert.equal(event.requestId, trace.requestId); assert.equal(event.origin, 'server');
  assert.equal(event.errorCode, 'unknown'); assert.equal(event.evidenceSource, 'observed');
  assert.deepEqual({ ...event.counts }, { packages: 4, matches: 1 }); assert.equal(event.durationMs, 200);
  assert.equal(event.timestampMs % 60_000, 0);
});

test('server request traces have hard event, row and serialized-byte bounds', t => {
  const db = database(t), store = createOffenseTraceStore({ db, limits: { rows: 4, bytes: 1200, eventsPerRequest: 3 } });
  for (let request = 0; request < 15; request++) {
    const trace = store.start('mcp');
    for (let event = 0; event < 50; event++) trace.record('upgrade_planning', 'started', { counts: { plans: 1 } });
    trace.record('response', 'completed');
  }
  const rows = allRows(db); assert.ok(rows.length <= 4); assert.ok(rows.reduce((sum, row) => sum + row.bytes, 0) <= 1200);
  const grouped = new Map(); for (const row of rows) grouped.set(row.request_id, (grouped.get(row.request_id) || 0) + 1);
  assert.ok([...grouped.values()].every(count => count <= 3));
  assert.ok(rows.every(row => row.bytes <= OFFENSE_TRACE_LIMITS.eventBytes));
  assert.ok(store.read().some(event => event.stage === 'response'), 'terminal outcome has reserved capacity');
  const tinyDb = database(t), tiny = createOffenseTraceStore({ db: tinyDb, limits: { eventBytes: 64 } });
  tiny.start().record('request', 'started'); assert.equal(allRows(tinyDb).length, 0);
});

test('expiry is hidden and physically pruned on reads, writes and explicit maintenance', t => {
  const db = database(t); let now = Date.now(); const store = createOffenseTraceStore({ db, now: () => now });
  store.start().record('request', 'started'); assert.equal(allRows(db).length, 1);
  now += OFFENSE_TRACE_LIMITS.retentionMs + 60_000;
  assert.deepEqual(store.read(), []); assert.equal(allRows(db).length, 0, 'read prunes expired rows before returning');
  now = Date.now(); store.start().record('request', 'started'); assert.equal(allRows(db).length, 1);
  const result = store.prune(now + OFFENSE_TRACE_LIMITS.retentionMs + 60_000);
  assert.equal(result.status, 'ok'); assert.equal(result.removed, 1); assert.equal(allRows(db).length, 0);
  store.start().record('request', 'started'); now += OFFENSE_TRACE_LIMITS.retentionMs + 60_000;
  store.start().record('request', 'started'); assert.equal(allRows(db).length, 0, 'writes do not retain expired observations');
});

test('stored-reader rejects corrupted fields and incoming UUIDs never select trace ownership', t => {
  const db = database(t), store = createOffenseTraceStore({ db });
  const headers = new Map(), callbacks = new Map();
  const req = { headers: { 'x-offense-request-id': clientId }, body: { traceId: clientId, private: canary } };
  const res = { set(key, value) { headers.set(key, value); }, once(event, callback) { callbacks.set(event, callback); }, statusCode: 200 };
  const trace = beginOffenseRequest(req, res, { store });
  assert.notEqual(trace.requestId, clientId); assert.equal(headers.get('X-Offense-Request-Id'), trace.requestId);
  callbacks.get('finish')(); callbacks.get('close')();
  assert.equal(store.read({ requestId: trace.requestId }).filter(event => event.stage === 'response').length, 1);
  assert.deepEqual(store.read({ requestId: canary }), []); assertNoPrivateData(allRows(db));
  const original = allRows(db)[0], corrupted = JSON.parse(original.event); corrupted.private = canary;
  db.prepare('UPDATE offense_trace_events SET event = ?').run(JSON.stringify(corrupted));
  assert.deepEqual(store.read(), [], 'readback revalidates the allowlist rather than exporting arbitrary stored JSON');
});

test('REST scan, partial plan and rejected input preserve responses while recording safe stages and outcomes', async t => {
  const { url, db, intelligence } = await fixture(t, { plan: async () => { throw Object.assign(Error(canary), { code: canary }); } });
  const response = await post(url, { files }); assert.equal(response.status, 200);
  const report = await response.json(); assert.equal(report.status, 'partial'); assert.equal(report.findings.length, 1);
  const requestId = response.headers.get('x-offense-request-id'); assert.notEqual(requestId, clientId);
  const events = intelligence.traces.read({ requestId });
  assert.ok(events.some(event => event.stage === 'validation' && event.outcome === 'completed'));
  assert.ok(events.some(event => event.stage === 'advisory_scan' && event.counts.advisoryMatches === 1));
  assert.ok(events.some(event => event.stage === 'upgrade_planning' && event.outcome === 'failed'));
  assert.ok(events.some(event => event.stage === 'response' && event.outcome === 'partial'));
  const rejected = await post(url, { files, traceId: clientId }); assert.equal(rejected.status, 400); await rejected.json();
  assert.ok(intelligence.traces.read({ requestId: rejected.headers.get('x-offense-request-id') }).some(event => event.outcome === 'rejected'));
  const malformed = await post(url, '{broken ' + canary); assert.equal(malformed.status, 400); await malformed.json();
  const badOrigin = await post(url, { files }, '/api/offense/audit', { Origin: 'https://' + canary + '.example' }); assert.equal(badOrigin.status, 403); await badOrigin.json();
  assert.ok(intelligence.traces.read({ requestId: badOrigin.headers.get('x-offense-request-id') }).some(event => event.errorCode === 'invalid_origin'));
  assert.equal((await fetch(url + '/api/offense/traces')).status, 404, 'there is no public trace reader');
  assertNoPrivateData(allRows(db));
});

test('MCP initialization/tool errors and legacy Purple requests share safe request tracing', async t => {
  const { url, db, intelligence } = await fixture(t, { check: async () => { throw Object.assign(Error(canary), { code: 'provider_unavailable' }); } });
  const mcpHeaders = { Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25' };
  const initialized = await post(url, { jsonrpc: '2.0', id: canary, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: canary, version: canary } } }, '/mcp', mcpHeaders);
  assert.equal(initialized.status, 200); const initialization = await initialized.json(); assert.equal(initialization.id, canary);
  const called = await post(url, { jsonrpc: '2.0', id: canary, method: 'tools/call', params: { name: 'offense.audit_dependencies', arguments: { files, planLimit: 0 } } }, '/mcp', mcpHeaders);
  const body = await called.json(); assert.equal(called.status, 200); assert.equal(body.result.isError, true);
  const events = intelligence.traces.read({ requestId: called.headers.get('x-offense-request-id') });
  assert.ok(events.every(event => event.transport === 'mcp'));
  assert.ok(events.some(event => event.stage === 'advisory_scan' && event.errorCode === 'provider_failure'));
  assert.ok(events.some(event => event.stage === 'response' && event.outcome === 'failed'));
  const legacy = await post(url, { files }, '/api/skill/scan'); assert.equal(legacy.status, 502); await legacy.json();
  assert.ok(intelligence.traces.read({ requestId: legacy.headers.get('x-offense-request-id') }).some(event => event.stage === 'advisory_scan'));
  const rejected = await post(url, { jsonrpc: '2.0', id: canary, method: 'ping' }, '/mcp', { ...mcpHeaders, Origin: 'https://' + canary + '.example' });
  assert.equal(rejected.status, 403); await rejected.json();
  assertNoPrivateData(allRows(db));
});

test('quota and busy rejections create fixed outcome buckets without persisting request identity', async t => {
  const { url, db, intelligence } = await fixture(t);
  intelligence.admit = () => ({ status: 429, retryAfter: 60, error: canary });
  const limited = await post(url, { files }); assert.equal(limited.status, 429); await limited.json();
  assert.ok(intelligence.traces.read({ requestId: limited.headers.get('x-offense-request-id') }).some(event => event.errorCode === 'quota_exceeded'));
  intelligence.admit = () => ({ status: 503, retryAfter: 10, error: canary });
  const busy = await post(url, { files }); assert.equal(busy.status, 503); await busy.json();
  assert.ok(intelligence.traces.read({ requestId: busy.headers.get('x-offense-request-id') }).some(event => event.errorCode === 'busy'));
  assertNoPrivateData(allRows(db));
});

test('trace storage failures and explicit opt-out never change the successful advisory response', async t => {
  const { url, intelligence } = await fixture(t, { dbFactory(db) { return {
    exec(sql) { if (/offense_trace/.test(sql)) throw Error(canary); return db.exec(sql); },
    prepare(sql) { if (/offense_trace/.test(sql)) throw Error(canary); return db.prepare(sql); }
  }; } });
  const response = await post(url, { files, planLimit: 0 }); assert.equal(response.status, 200);
  const report = await response.json(); assert.equal(report.summary.advisoryMatches, 1); assert.equal(report.summary.confirmedVulnerabilities, 0);
  assert.match(response.headers.get('x-offense-request-id'), /^[a-f0-9-]{36}$/);
  assert.deepEqual(intelligence.traces.read(), []); assert.equal(intelligence.pruneTraces().status, 'unavailable');
  const db = database(t), disabled = createDependencyIntelligence({ db, check, plan, traceEnabled: false });
  assert.equal(disabled.traces, null); assert.equal(disabled.pruneTraces().status, 'disabled');
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE name = 'offense_trace_events'").get().count, 0);
  assert.equal((await disabled.audit({ files, planLimit: 0 })).summary.advisoryMatches, 1);
});

test('disabling new trace collection still prunes previously stored records after their retention window', t => {
  const db = database(t); let now = Date.now();
  const enabled = createDependencyIntelligence({ db, check, plan, now: () => now });
  enabled.traces.start().record('request', 'started'); assert.equal(allRows(db).length, 1);
  const disabled = createDependencyIntelligence({ db, check, plan, now: () => now, traceEnabled: false });
  assert.equal(disabled.traces, null); assert.equal(allRows(db).length, 1, 'unexpired old records remain within their original visibility window');
  now += OFFENSE_TRACE_LIMITS.retentionMs + 60_000;
  const result = disabled.pruneTraces();
  assert.equal(result.status, 'ok'); assert.equal(result.removed, 1); assert.equal(allRows(db).length, 0);
});

test('parent lookup failures and candidate-search bounds retain accurate fixed trace buckets without action text', async t => {
  for (const [action, expectedBlocker, expectedTrace] of [
    [`Could not inspect parent releases: npm registry returned HTTP 503 ${canary}`, 'provider_failure', 'provider_failure'],
    [`No clean compatible parent release found among the first 10 candidates. ${canary}`, 'candidate_limit', 'analysis_incomplete']
  ]) {
    const { url, db, intelligence } = await fixture(t, { plan: async (...args) => ({ ...await plan(...args),
      impact: { paths: [], parents: [{ name: 'private-parent-canary', version: '1.0.0', compatible: false }] },
      parentOptions: [{ parent: 'private-parent-canary', currentVersion: '1.0.0', version: null, action }] }) });
    const response = await post(url, { files }); assert.equal(response.status, 200);
    const report = await response.json(); assert.equal(report.remediation.blockers[0].code, expectedBlocker);
    const events = intelligence.traces.read({ requestId: response.headers.get('x-offense-request-id') });
    const planning = events.find(event => event.stage === 'upgrade_planning' && event.outcome === 'partial');
    assert.ok(planning); assert.equal(planning.errorCode, expectedTrace);
    assert.ok(!events.some(event => event.errorCode === 'dependency_constraints'), 'an unavailable lookup or bounded search is not a proven compatibility conflict');
    assertNoPrivateData(allRows(db)); assert.ok(!JSON.stringify(allRows(db)).includes('private-parent-canary'));
  }
});
