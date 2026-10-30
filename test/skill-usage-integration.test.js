import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import express from 'express';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createDependencyIntelligence } from '../server/dependency-intelligence.js';
import { registerSkillApi } from '../server/skill-api.js';
import { registerOffenseApi } from '../server/offense-api.js';
import { registerOffenseMcp, OFFENSE_MCP_TOOL } from '../server/offense-mcp.js';
import { createSkillUsageStore, skillUsageMetrics } from '../server/skill-usage.js';
import { createWorkerApp } from '../workers/app-api.js';
import { createAccounts } from '../server/accounts.js';

const PRIVATE = 'PRIVATE-SKILL-USAGE-CUSTOMER-secret';
const files = [{ path: 'package-lock.json', content: { lockfileVersion: 3, name: PRIVATE, packages: {
  '': { name: PRIVATE, dependencies: { semver: '^7.5.1', lodash: '^4.17.20' }, scripts: { postinstall: PRIVATE } },
  'node_modules/semver': { version: '7.5.1', resolved: `https://user:${PRIVATE}@private.example/semver.tgz` },
  'node_modules/lodash': { version: '4.17.20' }
} } }];
const findings = [
  { id: 'GHSA-usage-one', package: 'semver', version: '7.5.1', severity: 'HIGH', summary: PRIVATE,
    cves: ['CVE-2022-25883'], fixedVersions: ['7.5.2'], advisory: { details: PRIVATE } },
  { id: 'GHSA-usage-two', package: 'lodash', version: '4.17.20', severity: 'CRITICAL', summary: PRIVATE,
    fixedVersions: ['4.17.21'], advisory: { details: PRIVATE } }
];
const check = async packages => ({ status: 'complete', checkedPackages: packages.length, skippedPackages: 0,
  checkedAt: Date.now(), findings: findings.filter(f => packages.some(p => p.name === f.package && p.version === f.version)) });
const plan = async (snapshot, name, version) => ({ name, currentVersion: version,
  targetVersion: name === 'semver' ? '7.5.2' : '4.17.21', releases: [version], steps: [], parentOptions: [],
  considered: [{ version: name === 'semver' ? '7.5.2' : '4.17.21', advisories: 0 }],
  impact: { paths: [['application', name]], parents: [] } });

async function fixture(t, options = {}) {
  const db = new DatabaseSync(':memory:'), app = express();
  const intelligence = createDependencyIntelligence({ db, check, plan, ...options });
  registerSkillApi(app, { intelligence });
  registerOffenseApi(app, { intelligence, publicUrl: 'http://127.0.0.1' });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); });
  return { db, intelligence, url: `http://127.0.0.1:${server.address().port}`, read: () => skillUsageMetrics(db) };
}
const post = (url, body = { files, planLimit: 0 }, path = '/api/offense/audit') => fetch(url + path, {
  method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${PRIVATE}`,
    'x-offense-request-id': PRIVATE, 'user-agent': PRIVATE }, body: JSON.stringify(body)
});
async function mcpClient(t, url) {
  const client = new Client({ name: PRIVATE, version: '1' });
  await client.connect(new StreamableHTTPClientTransport(new URL(url + '/mcp')));
  t.after(() => client.close());
  return client;
}
const channel = (metrics, name) => metrics.channels.find(row => row.channel === name);
const operation = (metrics, name) => metrics.operations.find(row => row.operation === name);

test('REST, MCP and legacy scans share durable anonymous counts while MCP discovery is not a scan', async t => {
  const f = await fixture(t);
  const client = await mcpClient(t, f.url);
  await client.ping(); await client.listTools();
  assert.equal((await fetch(f.url + '/api/offense/capabilities')).status, 200);
  assert.equal(f.read().totals.started, 0);
  assert.equal(f.read().totals.advisoryMatches, 0);

  assert.equal((await post(f.url)).status, 200);
  assert.equal((await client.callTool({ name: OFFENSE_MCP_TOOL, arguments: { files, planLimit: 0 } })).isError, false);
  assert.equal((await post(f.url, { files }, '/api/skill/scan')).status, 200);
  const result = f.read();
  assert.equal(result.totals.started, 3);
  assert.equal(result.totals.completed, 3);
  assert.equal(result.totals.advisoryMatches, 6);
  assert.equal(result.totals.checkedPackages, 6);
  assert.equal(result.totals.severity.critical, 3);
  assert.equal(result.totals.severity.high, 3);
  for (const name of ['https', 'mcp', 'legacy']) {
    assert.equal(channel(result, name).started, 1);
    assert.equal(channel(result, name).completed, 1);
    assert.equal(channel(result, name).advisoryMatches, 2);
  }
});

test('planning continuations and legacy targeted plans do not inflate full-audit headlines', async t => {
  const f = await fixture(t);
  const initial = await (await post(f.url, { files, planLimit: 1 })).json();
  assert.equal(initial.status, 'partial');
  assert.ok(initial.remediation.planning.next);
  const before = f.read();
  assert.equal(before.totals.started, 1);
  assert.equal(before.totals.advisoryMatches, 2);
  const continuation = await post(f.url, { files, planLimit: 1, planning: initial.remediation.planning.next });
  assert.equal(continuation.status, 200);
  assert.equal((await continuation.json()).coverage.planningOnly, true);
  assert.equal((await post(f.url, { files, name: 'semver', version: '7.5.1' }, '/api/skill/plan')).status, 200);
  const result = f.read();
  assert.equal(result.totals.started, before.totals.started);
  assert.equal(result.totals.advisoryMatches, before.totals.advisoryMatches);
  assert.equal(result.totals.checkedPackages, before.totals.checkedPackages);
  assert.equal(operation(result, 'planning').started, 2);
});

test('strict input rejections and provider failures remain separate from completed advisory checks', async t => {
  let calls = 0;
  const f = await fixture(t, { check: async () => { calls++; throw Error(`Provider unavailable ${PRIVATE}`); } });
  assert.equal((await post(f.url, { files, apiKey: PRIVATE })).status, 400);
  assert.equal(calls, 0);
  let result = f.read();
  assert.equal(result.totals.started, 1); assert.equal(result.totals.rejected, 1);
  assert.equal(result.totals.completed, 0); assert.equal(result.totals.advisoryMatches, 0);
  assert.equal((await post(f.url)).status, 502);
  result = f.read();
  assert.equal(result.totals.started, 2); assert.equal(result.totals.failed, 1);
  assert.equal(result.totals.rejected, 1); assert.equal(result.totals.completed, 0);
  assert.equal(result.totals.advisoryMatches, 0); assert.equal(result.totals.checkedPackages, 0);
  assert.equal(result.totals.unfinished, 0);
});

test('partial reports retain observed matches and repeated audits count repeated observations', async t => {
  const f = await fixture(t, { plan: async () => { throw Error('Fixture planning unavailable'); } });
  for (let index = 0; index < 2; index++) {
    const response = await post(f.url, { files, planLimit: 2 });
    assert.equal(response.status, 200); assert.equal((await response.json()).status, 'partial');
  }
  const result = f.read();
  assert.equal(result.totals.started, 2); assert.equal(result.totals.partial, 2);
  assert.equal(result.totals.completed, 0); assert.equal(result.totals.failed, 0);
  assert.equal(result.totals.advisoryMatches, 4);
  assert.equal(result.totals.severity.critical, 2); assert.equal(result.totals.severity.high, 2);
  assert.equal(result.lifetime.advisoryMatches, 4);
});

test('aggregates still count when diagnostic traces are disabled and persist no caller or finding identifiers', async t => {
  const f = await fixture(t, { traceEnabled: false });
  assert.equal((await post(f.url)).status, 200);
  assert.equal(f.read().totals.completed, 1);
  const rows = [...f.db.prepare('SELECT * FROM skill_usage_days').all(), ...f.db.prepare('SELECT * FROM skill_usage_meta').all()];
  const serialized = JSON.stringify(rows);
  for (const forbidden of [PRIVATE, 'semver', 'lodash', 'private.example', 'GHSA-usage', 'CVE-2022-25883',
    'package-lock.json', '127.0.0.1', 'metadataFingerprint', 'user-agent', 'authorization']) {
    assert.ok(!serialized.includes(forbidden), `Usage aggregates retained private or identifying data: ${forbidden}`);
  }
  assert.equal(f.db.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name IN ('workspaces', 'users', 'vulnerability_discoveries')").get().count, 0,
    'Anonymous audits never create account records or a confirmed-vulnerability ledger.');
});

test('MCP rejects schema-invalid output as failed without adding matches', async t => {
  const db = new DatabaseSync(':memory:'), app = express();
  const usage = createSkillUsageStore({ db });
  registerOffenseMcp(app, { publicUrl: 'http://127.0.0.1', usage, audit: async () => ({}) });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); });
  const client = await mcpClient(t, `http://127.0.0.1:${server.address().port}`);
  const response = await client.callTool({ name: OFFENSE_MCP_TOOL, arguments: { files, planLimit: 0 } });
  assert.equal(response.isError, true);
  const metrics = skillUsageMetrics(db);
  assert.equal(metrics.totals.started, 1); assert.equal(metrics.totals.failed, 1);
  assert.equal(metrics.totals.completed, 0); assert.equal(metrics.totals.advisoryMatches, 0);
});

test('browser skill metrics require numeric operator access, and internal metrics retain separate bearer authorization', async t => {
  const db = new DatabaseSync(':memory:');
  const { app } = createWorkerApp({ db, env: { OPERATIONS_GITHUB_IDS: '1234,2468', OPERATIONS_METRICS_KEY: 'metrics-fixture-key' }, schedule() {} });
  const accounts = createAccounts(db);
  for (const [cookie, id] of [['a', 1234], ['b', 5678]]) {
    const user = accounts.upsertUser(id, 'identical-login');
    const workspaceId = `private-workspace-${cookie}`;
    accounts.createWorkspace(user.id, workspaceId, { company: PRIVATE, openrouter: { secret: PRIVATE } });
    db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(cookie.repeat(64), JSON.stringify({ userId: user.id, workspaceId }), Date.now());
  }
  const newOperator = accounts.upsertUser(2468, 'new-operator-without-workspace');
  db.prepare('INSERT INTO sessions VALUES(?,?,?)').run('c'.repeat(64), JSON.stringify({ userId: newOperator.id }), Date.now());
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM memberships WHERE user_id = ?').get(newOperator.id).count, 0);
  const beforeDiscoveries = db.prepare('SELECT COUNT(*) AS count FROM vulnerability_discoveries').get().count;
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = `${base}/api/operator/skill-usage`;
  assert.equal((await fetch(browser)).status, 401);
  assert.equal((await fetch(browser, { headers: { authorization: 'Bearer metrics-fixture-key' } })).status, 401);
  assert.equal((await fetch(browser, { headers: { cookie: `purple_session=${'b'.repeat(64)}` } })).status, 403);
  const headers = { cookie: `purple_session=${'a'.repeat(64)}` };
  const response = await fetch(browser + '?days=7', { headers });
  assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
  const result = await response.json();
  assert.equal(result.days, 7); assert.equal(result.series.length, 7);
  assert.equal(result.coverage.available, true); assert.equal(result.totals.started, 0);
  const newlySignedIn = await fetch(browser, { headers: { cookie: `purple_session=${'c'.repeat(64)}` } });
  assert.equal(newlySignedIn.status, 200, 'An allowlisted operator needs no pre-existing workspace membership to read company skill metrics.');
  assert.equal((await newlySignedIn.json()).totals.started, 0);
  for (const query of ['?days=8', '?workspaceId=another', '?days=7&days=30'])
    assert.equal((await fetch(browser + query, { headers })).status, 400);
  assert.equal((await fetch(base + '/api/internal/metrics', { headers })).status, 401);
  const internal = await fetch(base + '/api/internal/metrics', { headers: { authorization: 'Bearer metrics-fixture-key' } });
  assert.equal(internal.status, 200);
  const metrics = await internal.json();
  assert.equal(metrics.skillUsage.totals.started, 0);
  assert.equal(metrics.totals.confirmed.total, 0);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM vulnerability_discoveries').get().count, beforeDiscoveries);
  for (const value of [PRIVATE, 'private-workspace', 'metrics-fixture-key', 'identical-login'])
    assert.ok(!JSON.stringify(result).includes(value), 'Browser skill metrics expose aggregates only.');
});
