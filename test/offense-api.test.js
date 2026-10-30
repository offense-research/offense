import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import express from 'express';
import { request as httpRequest } from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createDependencyIntelligence } from '../server/dependency-intelligence.js';
import { registerSkillApi } from '../server/skill-api.js';
import { registerOffenseApi } from '../server/offense-api.js';
import { createWorkerApp } from '../workers/app-api.js';
import { OFFENSE_SERVICE_VERSION } from '../shared/offense-schema.js';

const files = [{ path: 'package-lock.json', content: { lockfileVersion: 3, name: 'PRIVATE-REPO', packages: {
  '': { name: 'PRIVATE-REPO', dependencies: { semver: '^7.5.1', lodash: '^4.17.20' }, scripts: { postinstall: 'DO-NOT-RUN' } },
  'node_modules/semver': { version: '7.5.1', resolved: 'https://user:SECRET@private.example/package.tgz' },
  'node_modules/lodash': { version: '4.17.20' }
} } }];
const findings = [{ id: 'GHSA-one', package: 'semver', version: '7.5.1', severity: 'HIGH', fixedVersions: ['7.5.2'], summary: 'Untrusted summary', cves: ['CVE-2022-25883'], advisory: { affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '7.5.2' }] }] }] } },
  { id: 'GHSA-two', package: 'lodash', version: '4.17.20', severity: 'CRITICAL', fixedVersions: ['4.17.21'], summary: 'Another match' }];
const check = async packages => ({ status: 'complete', checkedPackages: packages.length, skippedPackages: 0, checkedAt: Date.now(), findings: findings.filter(f => packages.some(p => p.name === f.package && p.version === f.version)) });
const plan = async (snapshot, name, version) => ({ name, currentVersion: version, targetVersion: name === 'semver' ? '7.5.2' : '4.17.21',
  releases: [version], steps: [], parentOptions: [], considered: [{ version: 'checked', advisories: 0 }], impact: { paths: [['application', name]], parents: [] } });
async function fixture(t, options = {}) {
  const db = new DatabaseSync(':memory:'), app = express();
  const intelligence = createDependencyIntelligence({ db, check, plan, ...options });
  registerSkillApi(app, { intelligence }); registerOffenseApi(app, { intelligence, publicUrl: 'http://127.0.0.1' });
  app.use((req, res) => res.sendStatus(401));
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); });
  return { db, intelligence, url: `http://127.0.0.1:${server.address().port}` };
}
const post = (url, body = { files }, path = '/api/offense/audit', headers = {}) => fetch(url + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
const statusWithHost = (url, path) => new Promise((resolve, reject) => {
  const req = httpRequest(url + path, { method: 'POST', headers: { Host: 'ingest.example.test', 'content-type': 'application/json' } }, response => { response.resume(); resolve(response.statusCode); });
  req.on('error', reject); req.end('{}');
});

test('one audit returns standardized evidence and coordinated paths without account state or source execution', async t => {
  const { url, db } = await fixture(t);
  const response = await post(url); assert.equal(response.status, 200); assert.equal(response.headers.get('set-cookie'), null);
  const result = await response.json();
  assert.equal(result.schemaVersion, 'offense.audit.v1'); assert.equal(result.capability, 'audit_dependencies'); assert.equal(result.status, 'complete');
  assert.equal(result.summary.advisoryMatches, 2); assert.equal(result.summary.critical, 1); assert.equal(result.summary.confirmedVulnerabilities, 0); assert.equal(result.summary.checkedUpgradePaths, 2);
  assert.equal(result.remediation.plans[0].package, 'lodash', 'critical package is planned first');
  for (const finding of result.findings) { assert.equal(finding.verification.confirmed, false); assert.equal(finding.relevance.status, 'needs_review'); assert.match(finding.source.url, /^https:\/\/osv.dev\/vulnerability\//); assert.equal(finding.remediation.status, 'path_checked'); }
  assert.equal(result.findings[0].advisoryListedFixedVersions[0], '7.5.2');
  assert.match(result.metadataFingerprint, /^[a-f0-9]{64}$/);
  assert.ok(result.remediation.agentPrompt.includes(`"evidenceIdentity": "${result.metadataFingerprint}"`));
  assert.match(result.remediation.agentPrompt, /No Git commit or source files were supplied/);
  const serialized = JSON.stringify(result); for (const secret of ['SECRET', 'private.example', 'PRIVATE-REPO', 'DO-NOT-RUN']) assert.ok(!serialized.includes(secret));
  assert.ok(!db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().some(row => /sessions|workspaces|discoveries/.test(row.name)));
  const capability = await (await fetch(url + '/api/offense/capabilities')).json(); assert.equal(capability.capabilities[0].mcpTool, 'offense.audit_dependencies');
  assert.equal(capability.integrations.sdk, '/downloads/offense-sdk.tgz');
  assert.equal(capability.integrations.cli, '/downloads/offense-automation.mjs');
  assert.equal(capability.integrations.automation.defaults.schedule, 'daily');
  assert.ok(capability.integrations.automation.events.includes('pre_deploy'));
  assert.match(capability.integrations.automation.lifecycle, /must invoke/);
  assert.equal((await fetch(url + '/protected')).status, 401);
});

test('planning errors, constrained targets and planning limits retain every advisory with explicit partial status', async t => {
  const { url } = await fixture(t, { plan: async (snapshot, name, version) => {
    if (name === 'semver') throw Error('No maintained parent release');
    return { ...await plan(snapshot, name, version), constraintWarnings: ['Peer conflict'], impact: { paths: [], parents: [], truncated: true } };
  } });
  const result = await (await post(url)).json(); assert.equal(result.status, 'partial'); assert.equal(result.findings.length, 2);
  assert.equal(result.summary.checkedUpgradePaths, 0); assert.equal(result.remediation.blockers.length, 2);
  assert.equal(result.findings.find(f => f.package.name === 'semver').remediation.status, 'blocked');
  assert.equal(result.findings.find(f => f.package.name === 'lodash').remediation.status, 'needs_review');
  for (const finding of findings) assert.ok(result.remediation.agentPrompt.includes(finding.id));
  const limited = await (await post(url, { files, planLimit: 1 })).json(); assert.equal(limited.findings.length, 2);
  assert.ok(limited.remediation.blockers.some(b => b.code === 'plan_limit')); assert.equal(limited.findings.find(f => f.package.name === 'semver').remediation.status, 'not_planned');
  const scanOnly = await (await post(url, { files, planLimit: 0 })).json(); assert.equal(scanOnly.remediation.status, 'not_requested'); assert.equal(scanOnly.remediation.plans.length, 0);
});

test('npm and pnpm use the same capability, with all omitted coverage visible', async t => {
  const { url } = await fixture(t);
  const pnpm = await (await post(url, { files: [{ path: 'pnpm-lock.yaml', content: "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      semver: {specifier: '^7.5.1', version: 7.5.1}\npackages:\n  semver@7.5.1: {}\nsnapshots:\n  semver@7.5.1: {}\n" }], planLimit: 0 })).json();
  assert.deepEqual(pnpm.coverage.packageManagers, ['pnpm']); assert.equal(pnpm.findings[0].package.name, 'semver');
  const broken = structuredClone(files); broken[0].content.packages['node_modules/local'] = { version: 'git+https://private.test' };
  const result = await (await post(url, { files: broken, planLimit: 0 })).json(); assert.equal(result.status, 'partial'); assert.equal(result.coverage.status, 'partial'); assert.ok(result.coverage.warnings.length);
});

test('separately checked upgrades that disagree on one installed parent remain blocked as a combined plan', async t => {
  const { url } = await fixture(t, { plan: async (snapshot, name, version) => ({ ...await plan(snapshot, name, version),
    impact: { paths: [], parents: [{ name: 'shared-parent', version: '1.0.0', compatible: false }] },
    parentOptions: [{ parent: 'shared-parent', currentVersion: '1.0.0', version: name === 'semver' ? '2.0.0' : '3.0.0', upstream: [] }] }) });
  const result = await (await post(url)).json();
  assert.equal(result.status, 'partial'); assert.equal(result.remediation.status, 'partial'); assert.equal(result.summary.checkedUpgradePaths, 0);
  assert.ok(result.remediation.plans.every(p => p.status === 'needs_review' && !p.routes.some(route => route.recommended)));
  assert.equal(result.remediation.blockers.filter(b => b.code === 'coordinated_target_conflict').length, 2);
  assert.match(result.remediation.agentPrompt, /Coordinated targets disagree/);
  assert.equal(result.findings.length, 2);
});

test('invalid inputs and provider failure never produce a clean report', async t => {
  let checks = 0; const { url } = await fixture(t, { check: async () => { checks++; throw Error('OSV unavailable'); } });
  for (const body of [{ files, apiKey: 'do-not-send' }, { files, planLimit: -1 }, { files, planLimit: 11 }, { files, planLimit: 1.5 }, { files: [{ path: 'package.json', content: {} }] }, { files: [{ ...files[0], path: '../package-lock.json' }] }]) assert.equal((await post(url, body)).status, 400);
  assert.equal(checks, 0);
  assert.equal((await post(url, { files }, '/api/offense/audit', { Origin: 'https://attacker.test' })).status, 403);
  const failed = await post(url); assert.equal(failed.status, 502); const body = await failed.json(); assert.equal(body.error.code, 'analysis_incomplete'); assert.equal(body.findings, undefined);
  assert.equal((await post(url, { files: [], padding: 'x'.repeat(2_100_000) })).status, 413);
});

test('REST, legacy skill and MCP share durable quotas and exactly two execution slots', async t => {
  let release, started = 0; const gate = new Promise(resolve => { release = resolve; });
  const { url } = await fixture(t, { check: async packages => { started++; await gate; return check(packages); } });
  const client = new Client({ name: 'fixture', version: '1' }); await client.connect(new StreamableHTTPClientTransport(new URL(url + '/mcp'))); t.after(() => client.close());
  const a = post(url, { files, planLimit: 0 });
  const b = client.callTool({ name: 'offense.audit_dependencies', arguments: { files, planLimit: 0 } });
  while (started < 2) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal((await post(url, { files }, '/api/skill/scan')).status, 503);
  release(); assert.equal((await a).status, 200); assert.equal((await b).isError, false);
  for (let n = 0; n < 37; n++) await post(url, {});
  assert.equal((await post(url, { files }, '/api/skill/scan')).status, 429);
  await assert.rejects(() => client.callTool({ name: 'offense.audit_dependencies', arguments: { files } }), /quota|429/i);
});

test('the entire audit shares a bounded provider budget and uses the Worker-compatible no-redirect boundary', async t => {
  let outbound = 0;
  const { url } = await fixture(t, { fetchImpl: async (url, options) => { assert.equal(options.redirect, 'manual'); outbound++; return Response.json({}); }, check: async (packages, fetchImpl) => {
    await assert.rejects(() => fetchImpl('https://attacker.test/steal'), /provider URL/);
    for (let n = 0; n < 90; n++) await fetchImpl('https://api.osv.dev/v1/query');
    return check(packages);
  }, plan: async (snapshot, name, version, { fetchImpl }) => { await fetchImpl('https://registry.npmjs.org/semver'); return plan(snapshot, name, version); } });
  const report = await (await post(url)).json(); assert.equal(outbound, 90); assert.equal(report.status, 'partial'); assert.equal(report.findings.length, 2);
  assert.ok(report.remediation.blockers.every(item => item.reason.includes('budget')));
});

test('manual provider redirects are rejected rather than followed', async t => {
  let outbound = 0;
  const { url } = await fixture(t, { fetchImpl: async (url, options) => { outbound++; assert.equal(options.redirect, 'manual'); return new Response(null, { status: 302, headers: { location: 'https://attacker.test/' } }); },
    check: async (packages, fetchImpl) => { await fetchImpl('https://api.osv.dev/v1/querybatch'); return check(packages); } });
  const response = await post(url); assert.equal(response.status, 502); assert.equal(outbound, 1);
  assert.match((await response.json()).error.message, /redirects are not accepted/);
});

test('Worker app registers public Offense before authentication and rejects the ingestion host', async t => {
  const db = new DatabaseSync(':memory:');
  const { app } = createWorkerApp({ db, env: { PUBLIC_URL: 'https://app.example.test', PURPLE_INGEST_URL: 'https://ingest.example.test' }, schedule() {} });
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); });
  const url = `http://127.0.0.1:${server.address().port}`;
  const response = await post(url, {}); assert.equal(response.status, 400); assert.equal(response.headers.get('set-cookie'), null);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM sessions').get().count, 0);
  assert.equal(await statusWithHost(url, '/api/offense/audit'), 404);
  assert.equal(await statusWithHost(url, '/mcp'), 404);
});

test('capability discovery advertises resumable planning and server-created request diagnostics', async t => {
  const { url } = await fixture(t);
  const a = await fetch(url + '/api/offense/capabilities', { headers: { 'X-Offense-Request-Id': 'untrusted-caller-value' } });
  const b = await fetch(url + '/api/offense/capabilities');
  const requestId = a.headers.get('x-offense-request-id');
  assert.match(requestId, /^[a-f0-9-]{36}$/); assert.notEqual(requestId, 'untrusted-caller-value');
  assert.notEqual(requestId, b.headers.get('x-offense-request-id'));
  assert.equal(a.headers.get('x-offense-version'), OFFENSE_SERVICE_VERSION);
  const discovery = await a.json();
  assert.equal(discovery.service.title, 'Offense Security'); assert.equal(discovery.service.version, OFFENSE_SERVICE_VERSION);
  assert.equal(discovery.capabilities[0].planning.continuationRechecksOnlySelectedTargets, true);
  assert.ok(discovery.capabilities[0].inputSchema.properties.planning);
  const initial = await (await post(url, { files, planLimit: 1 })).json();
  const response = await post(url, { files, planLimit: 1, planning: initial.remediation.planning.next });
  assert.equal(response.status, 200); assert.equal((await response.json()).coverage.planningOnly, true);
});
