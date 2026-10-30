import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, mkdir, writeFile, readFile, symlink, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import { request } from 'node:http';
import { registerSkillApi } from '../server/skill-api.js';
import { sanitizeLockfiles } from '../public/skills/purple/scripts/metadata.mjs';
import { collectMetadata, analyze } from '../public/skills/purple/scripts/purple.mjs';
import { dependencyImpact } from '../server/dependency-graph.js';
import { createWorkerApp } from '../workers/app-api.js';

const files = [{ path: 'package-lock.json', content: JSON.stringify({ name: 'private-repository', lockfileVersion: 3, packages: {
  '': { name: 'private-repository', scripts: { postinstall: 'secret-script' }, dependencies: { semver: '^7.5.1' } },
  'node_modules/semver': { version: '7.5.1', resolved: 'https://user:password@private-registry.test/pkg', integrity: 'secret-integrity' }
} }) }];
const finding = { package: 'semver', version: '7.5.1', id: 'GHSA-example', cves: [], severity: 'HIGH', summary: 'Example advisory', fixedVersions: ['7.5.2'] };
const checked = async packages => ({ status: 'complete', checkedPackages: packages.length, findings: [finding], checkedAt: Date.now() });
const planned = async () => ({ name: 'semver', currentVersion: '7.5.1', targetVersion: '7.5.2', considered: [{ version: '7.5.2', advisories: 0 }],
  impact: { paths: [['application', 'semver']], parents: [] }, parentOptions: [], releases: ['7.5.1', '7.5.2'], steps: [] });
async function fixture(t, options = {}, db = new DatabaseSync(':memory:')) {
  const app = express(); registerSkillApi(app, { db, check: checked, plan: planned, ...options });
  app.get('/protected', (req, res) => res.sendStatus(401));
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  return { db, url: `http://127.0.0.1:${server.address().port}` };
}
const post = (url, route, body = { files }, headers = {}) => fetch(`${url}/api/skill/${route}`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body)
});

test('metadata allowlist strips scripts, repository identity, credential URLs and non-registry constraints', () => {
  const lock = JSON.parse(files[0].content);
  lock.packages[''].dependencies.local = 'git+https://user:secret@host/repo';
  const result = sanitizeLockfiles([{ ...files[0], content: lock }]);
  const wire = JSON.stringify(result.files);
  for (const sensitive of ['private-repository', 'secret-script', 'password', 'private-registry', 'integrity', 'user:secret']) assert.ok(!wire.includes(sensitive));
  assert.equal(JSON.parse(result.files[0].content).packages['node_modules/semver'].version, '7.5.1');
  assert.equal(result.warnings.length, 1);
  assert.throws(() => sanitizeLockfiles([{ ...files[0], content: { lockfileVersion: 1, dependencies: {} } }]), /v2 or v3/);
  assert.throws(() => sanitizeLockfiles([{ ...files[0], path: '../package-lock.json' }]), /relative/);
  assert.throws(() => sanitizeLockfiles([files[0], files[0]]), /unique/);
});

test('public scan and plan work without cookies or provider credentials and use the existing handoff', async t => {
  const { url, db } = await fixture(t);
  const response = await post(url, 'scan');
  assert.equal(response.status, 200); assert.equal(response.headers.get('set-cookie'), null);
  const scan = await response.json(); assert.equal(scan.protocolVersion, 1);
  assert.equal(scan.vulnerabilityCheck.findings[0].id, finding.id);
  assert.equal(scan.packages[0].name, 'semver');
  const result = await post(url, 'plan', { files, name: 'semver', version: '7.5.1' });
  assert.equal(result.status, 200);
  const handoff = await result.json(); assert.equal(handoff.plan.targetVersion, '7.5.2');
  assert.match(handoff.report, /GHSA-example/); assert.match(handoff.prompt, /Do not claim the vulnerability is fixed/);
  assert.equal((await fetch(`${url}/protected`)).status, 401);
  assert.deepEqual(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map(row => row.name),
    ['skill_rate_limits', 'offense_trace_events', 'sqlite_sequence', 'skill_usage_days', 'skill_usage_meta'], 'anonymous analysis retains only quotas, bounded diagnostics and count-only usage aggregates, never account state');
});

test('real app exposes only the skill API before login and still rejects it on the ingestion host', async t => {
  const db = new DatabaseSync(':memory:');
  const { app } = createWorkerApp({ db, env: { PUBLIC_URL: 'https://app.example.test', PURPLE_INGEST_URL: 'https://ingest.example.test' }, schedule() {} });
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); });
  const url = `http://127.0.0.1:${server.address().port}`;
  const invalid = await post(url, 'scan', {});
  assert.equal(invalid.status, 400); assert.equal(invalid.headers.get('set-cookie'), null);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM sessions').get().count, 0);
  assert.equal((await fetch(`${url}/api/agent/repositories`)).status, 401);
  const ingestStatus = await new Promise((resolve, reject) => {
    const req = request(`${url}/api/skill/scan`, { method: 'POST', headers: { Host: 'ingest.example.test' } }, response => {
      response.resume(); resolve(response.statusCode);
    });
    req.on('error', reject); req.end();
  });
  assert.equal(ingestStatus, 404);
});

test('API rejects wrong origins, unsupported metadata and absent packages, and never reports upstream failure as clean', async t => {
  let checks = 0;
  const { url } = await fixture(t, { check: async () => { checks++; throw new Error('OSV offline'); } });
  assert.equal((await post(url, 'scan', { files }, { Origin: 'https://attacker.test' })).status, 403);
  assert.equal((await post(url, 'scan', {})).status, 400);
  assert.equal((await post(url, 'plan', { files, name: 'absent', version: '1.0.0' })).status, 400);
  assert.equal((await post(url, 'something')).status, 404); assert.equal(checks, 0);
  const response = await post(url, 'scan'); assert.equal(response.status, 502);
  const body = await response.json(); assert.match(body.error, /OSV offline/); assert.equal(body.vulnerabilityCheck, undefined);
  assert.equal((await post(url, 'scan', { files: [], padding: 'x'.repeat(2_100_000) })).status, 413);
});

test('durable quotas persist across app recreation and reset at the next window', async t => {
  let timestamp = 3600000;
  const first = await fixture(t, { now: () => timestamp });
  for (let n = 0; n < 40; n++) assert.equal((await post(first.url, 'scan', {})).status, 400);
  const next = await fixture(t, { now: () => timestamp }, first.db);
  assert.equal((await post(next.url, 'scan', {})).status, 429);
  timestamp += 60000;
  assert.equal((await post(next.url, 'scan', {})).status, 400);
  assert.ok(first.db.prepare('SELECT COUNT(*) AS count FROM skill_rate_limits').get().count <= 3);
});

test('concurrency is bounded and slots are released after failed checks', async t => {
  let release, started = 0;
  const gate = new Promise(resolve => { release = resolve; });
  const { url } = await fixture(t, { check: async () => { started++; await gate; throw new Error('failed'); } });
  const a = post(url, 'scan'), b = post(url, 'scan');
  while (started < 2) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal((await post(url, 'scan')).status, 503);
  release(); assert.equal((await a).status, 502); assert.equal((await b).status, 502);
  assert.equal((await post(url, 'scan')).status, 502); assert.equal(started, 3);
});

test('client scans nested projects, skips symlinks and unsupported managers, and preserves partial upgrade reports', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-skill-test-')); t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'app')); await mkdir(path.join(root, 'node_modules'));
  await writeFile(path.join(root, 'app/package-lock.json'), files[0].content);
  await writeFile(path.join(root, 'app/package.json'), '{"scripts":{"postinstall":"DO-NOT-RUN"}}');
  await writeFile(path.join(root, 'node_modules/package-lock.json'), 'invalid JSON must never be read');
  await writeFile(path.join(root, 'yarn.lock'), 'unsupported');
  await symlink(path.join(root, 'app'), path.join(root, 'linked'));
  const metadata = await collectMetadata(root); assert.equal(metadata.files.length, 1);
  assert.ok(metadata.warnings.some(w => w.includes('symlink'))); assert.ok(metadata.warnings.some(w => w.includes('unsupported')));
  let requests = 0;
  const result = await analyze(root, { output: path.join(root, 'report'), log() {}, fetchImpl: async (url, options) => {
    requests++; assert.equal(new URL(url).hostname, 'app.purpleteam.sh');
    assert.ok(!options.body.includes('password')); assert.ok(!options.body.includes('DO-NOT-RUN'));
    if (String(url).endsWith('/plan')) return Response.json({ error: 'No checked fix available' }, { status: 502 });
    return Response.json({ protocolVersion: 1, packages: [], vulnerabilityCheck: await checked([{}]), warnings: [] });
  } });
  assert.equal(requests, 2); assert.equal(result.advisoryMatches, 1); assert.equal(result.upgradePlans, 0); assert.equal(result.blockers, 1);
  const report = await readFile(result.report, 'utf8'); assert.match(report, /No checked fix available/);
  const saved = JSON.parse(await readFile(result.json)); assert.equal(saved.verification, 'advisory_matches_only');
  assert.equal(await readFile(path.join(root, 'app/package.json'), 'utf8'), '{"scripts":{"postinstall":"DO-NOT-RUN"}}');
  const preview = await analyze(root, { preview: true, fetchImpl: () => assert.fail('Preview must not send metadata') });
  assert.equal(preview.files.length, 1);
});

test('dense dependency paths cannot grow an unbounded traversal queue', () => {
  const nodes = Array.from({ length: 120 }, (_, i) => ({ id: `${i}`, name: `p${i}`, version: '1.0.0', path: `node_modules/p${i}`, file: 'package-lock.json',
    requires: Array.from({ length: i }, (_, j) => ({ name: `p${j}`, range: '^1.0.0', to: `${j}` })) }));
  const impact = dependencyImpact({ nodes }, 'p0', '1.0.0', '1.0.1');
  assert.equal(impact.truncated, true); assert.ok(impact.paths.length <= 20);
});
