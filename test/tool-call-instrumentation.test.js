import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import express from 'express';
import { registerOffenseMcp, OFFENSE_MCP_TOOL } from '../server/offense-mcp.js';
import { registerOffenseApi } from '../server/offense-api.js';
import { registerSkillApi } from '../server/skill-api.js';
import { registerOffensePlatform } from '../server/offense-platform.js';
import { registerScanApi } from '../server/hosted-scans.js';
import { createToolCallMetrics } from '../server/tool-call-metrics.js';
import { AUDIT_SCHEMA_VERSION } from '../shared/offense-schema.js';

const PRIVATE = 'PRIVATE-CALL-METRICS-identity-key-source';
const input = { files: [{ path: 'package-lock.json', content: { lockfileVersion: 3, packages: {
  'node_modules/example': { version: '1.0.0' }
} } }], planLimit: 0 };
const report = () => ({ schemaVersion: AUDIT_SCHEMA_VERSION, capability: 'audit_dependencies', status: 'complete',
  findings: [], coverage: { complete: true }, remediation: { plans: [], blockers: [] },
  summary: { advisoryMatches: 0 }, providers: [{ id: 'fixture' }] });
const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream',
  'MCP-Protocol-Version': '2025-11-25', authorization: `Bearer ${PRIVATE}`, 'user-agent': PRIVATE };
const rpc = (method, params, id = PRIVATE) => ({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) });
const call = (name = OFFENSE_MCP_TOOL, args = input) => rpc('tools/call', { name, arguments: structuredClone(args) });
const init = rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: PRIVATE, version: '1' } });

async function fixture(t, { audit = async () => report(), admit = () => null, gateway, legacy = false, hosted = false } = {}) {
  const db = new DatabaseSync(':memory:'), app = express();
  const metrics = createToolCallMetrics({ db });
  app.use(metrics.middleware());
  if (legacy) {
    const intelligence = { audit, legacy: audit, admit, traces: null, usage: null };
    registerSkillApi(app, { intelligence });
    registerOffenseApi(app, { intelligence, publicUrl: 'http://127.0.0.1', gateway, callMetrics: metrics });
  } else registerOffenseMcp(app, { publicUrl: 'http://127.0.0.1', audit, admit, gateway, callMetrics: metrics });
  if (hosted) {
    const jobs = new Map();
    const scans = {
      authenticate: token => token === PRIVATE ? { user_id: 'private-user', workspace_id: 'private-workspace' } : null,
      create(principal, value, key) { if (!jobs.has(key)) jobs.set(key, { id: 'a'.repeat(32), status: 'queued' }); return jobs.get(key); },
      get: id => id === 'a'.repeat(32) ? { id, status: 'completed' } : null,
      tools: () => ({ tools: [] }), quote: () => ({ maximumMicros: 50000 }), usage: () => ({ jobs: [] })
    };
    const toolGateway = { authenticate: token => scans.authenticate(token), errorDetails: () => ({}),
      execute: async (name, args, token) => {
        const principal = scans.authenticate(token);
        if (!principal) throw Object.assign(new Error('Sign in.'), { status: 401 });
        return scans.create(principal, args.input, args.idempotencyKey);
      } };
    registerOffensePlatform(app, { scans, gateway: toolGateway, billing: {}, baseUrl: 'http://127.0.0.1' });
    registerScanApi(app, { scans });
    app.locals.jobs = jobs;
  }
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); });
  const url = `http://127.0.0.1:${server.address().port}`;
  const post = (message, extra = {}) => fetch(url + '/mcp', { method: 'POST', headers: { ...headers, ...extra }, body: JSON.stringify(message) });
  return { app, db, url, metrics, post, read: scope => metrics.read({ days: 7, scope: scope || 'tools' }) };
}

test('MCP transport requests count once while initialization, discovery and notifications never create tool calls', async t => {
  const f = await fixture(t);
  for (const message of [init, rpc('tools/list'), rpc('ping'), { jsonrpc: '2.0', method: 'notifications/initialized' }]) {
    const response = await f.post(message); assert.ok([200, 202].includes(response.status)); await response.text();
  }
  assert.equal(f.read().lifetime.total, 0);
  assert.equal(f.read('requests').lifetime.total, 4);
  for (const args of [input, input, { ...input, planning: { metadataFingerprint: 'a'.repeat(64), pendingTargetIds: ['b'.repeat(64)] } }]) {
    const response = await f.post(call(OFFENSE_MCP_TOOL, args)); assert.equal(response.status, 200);
    assert.equal((await response.json()).result.isError, false);
  }
  const tools = f.read();
  assert.equal(tools.lifetime.total, 3);
  assert.equal(tools.totals.completed, 3);
  assert.equal(tools.breakdown.find(row => row.operation === 'audit').total, 2);
  assert.equal(tools.breakdown.find(row => row.operation === 'planning').total, 1);
  assert.equal(f.read('requests').lifetime.total, 7, 'RPC tool calls do not add a second HTTP request.');
});

test('MCP rejects and provider failures remain outcomes even when JSON-RPC responds HTTP 200', async t => {
  let denied = null, fail = false;
  const f = await fixture(t, { admit: () => denied,
    audit: async () => { if (fail) throw Error(PRIVATE); return report(); } });
  for (const params of [{ name: OFFENSE_MCP_TOOL, arguments: [] }, { name: OFFENSE_MCP_TOOL, arguments: {} },
    { name: OFFENSE_MCP_TOOL, arguments: input, task: { ttl: 1000 } }]) {
    const response = await f.post(rpc('tools/call', params)); assert.equal(response.status, 200);
    const value = await response.json(); assert.ok(value.error || value.result?.isError);
  }
  denied = { status: 429, retryAfter: 1, error: 'Quota reached' };
  assert.equal((await f.post(call())).status, 429);
  denied = null; fail = true;
  const failed = await f.post(call()); assert.equal(failed.status, 200); assert.equal((await failed.json()).result.isError, true);
  assert.equal(f.read().lifetime.total, 5);
  assert.equal(f.read().totals.rejected, 4);
  assert.equal(f.read().totals.failed, 1);
  assert.equal(f.read().totals.unfinished, 0);
  assert.equal(f.read('requests').totals.rejected, 4);
  assert.equal(f.read('requests').totals.failed, 1);
});

test('unknown MCP tool names remain a fixed transport rejection without arbitrary operation dimensions', async t => {
  const f = await fixture(t);
  const response = await f.post(call(PRIVATE)); assert.equal(response.status, 200); assert.ok((await response.json()).error);
  assert.equal(f.read().lifetime.total, 0);
  const requests = f.read('requests'); assert.equal(requests.lifetime.total, 1); assert.equal(requests.totals.rejected, 1);
  assert.ok(!JSON.stringify(requests).includes(PRIVATE));
});

test('paid MCP retries count invocations rather than deduplicated jobs and support tools do not inflate tool totals', async t => {
  const jobs = new Map();
  const gateway = { authenticate: token => token === PRIVATE ? {} : null, errorDetails: () => ({}),
    execute: async (name, args, token) => {
      if (token !== PRIVATE) throw Object.assign(new Error('Authentication required.'), { status: 401 });
      if (name !== 'offense.security_call') return { tools: [] };
      if (!jobs.has(args.idempotencyKey)) jobs.set(args.idempotencyKey, { id: 'a'.repeat(32), status: 'queued' });
      return jobs.get(args.idempotencyKey);
    } };
  const f = await fixture(t, { gateway });
  const args = { tool: 'opengrep', input: { files: [] }, maxChargeMicros: 50000, idempotencyKey: 'repeat-fixture-key' };
  for (let index = 0; index < 2; index++) {
    const response = await f.post(call('offense.security_call', args)); assert.equal(response.status, 200);
    assert.equal((await response.json()).result.isError, false);
  }
  assert.equal(jobs.size, 1); assert.equal(f.read().lifetime.total, 2);
  const invalid = await f.post(call('offense.security_call', {})); assert.equal((await invalid.json()).result.isError, true);
  const unauthorized = await f.post(call('offense.security_call', args), { authorization: 'Bearer invalid' });
  assert.equal((await unauthorized.json()).result.isError, true);
  for (const [name, input] of [['offense.security_tools', {}], ['offense.security_quote', { tool: 'opengrep', inputBytes: 1, fileCount: 1 }],
    ['offense.security_result', { id: 'a'.repeat(32) }], ['offense.account', {}]]) {
    assert.equal((await (await f.post(call(name, input))).json()).result.isError, false);
  }
  assert.equal(f.read().lifetime.total, 4); assert.equal(f.read().totals.rejected, 2);
  assert.equal(f.read('requests').lifetime.total, 8);
});

test('REST, legacy and hosted request middleware count malformed and repeated submissions before execution', async t => {
  const f = await fixture(t, { legacy: true, hosted: true });
  const post = (path, body, extra = {}) => fetch(f.url + path, { method: 'POST', headers: { ...headers, ...extra }, body });
  for (const path of ['/api/offense/audit', '/api/skill/scan', '/api/skill/plan']) {
    assert.equal((await post(path, JSON.stringify(input))).status, 200);
  }
  assert.equal((await post('/api/offense/audit', '{invalid')).status, 400);
  for (let index = 0; index < 2; index++) assert.equal((await post('/v1/call/opengrep', JSON.stringify({ files: [], maxChargeMicros: 50000 }), { 'idempotency-key': 'same-http-job' })).status, 202);
  assert.equal(f.app.locals.jobs.size, 1);
  assert.equal((await post('/v1/scans', JSON.stringify({ files: [] }), { authorization: 'Bearer invalid' })).status, 401);
  const before = f.read().lifetime.total;
  for (const path of ['/v1/catalog', '/v1/tools', '/v1/scans/' + 'a'.repeat(32)]) {
    const response = await fetch(f.url + path, { headers }); await response.text(); assert.equal(response.status, 200);
  }
  assert.equal(before, 7); assert.equal(f.read().lifetime.total, before);
  assert.equal(f.read('requests').lifetime.total, 10);
  assert.equal(f.read().totals.rejected, 2);
});

test('unavailable optional MCP recording never prevents a successful capability response', async t => {
  const app = express();
  registerOffenseMcp(app, { publicUrl: 'http://127.0.0.1', audit: async () => report(), callMetrics: { start() { throw Error(PRIVATE); } } });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const response = await fetch(`http://127.0.0.1:${server.address().port}/mcp`, { method: 'POST', headers, body: JSON.stringify(call()) });
  assert.equal(response.status, 200); assert.equal((await response.json()).result.isError, false);
});
