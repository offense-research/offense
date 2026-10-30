import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { generateKeyPairSync } from 'node:crypto';
import { once } from 'node:events';
import { createWorkerApp } from '../workers/app-api.js';
import { createAccounts } from '../server/accounts.js';
import { buildRemediationPrompt } from '../src/remediation-prompts.js';

test('GitHub-only org onboarding persists repositories, scans CVEs and produces upgrade prompts with tenant isolation', async () => {
  const db = new DatabaseSync(':memory:'), originalFetch = globalThis.fetch;
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const env = { PUBLIC_URL: 'https://purple.test', GITHUB_APP_ID: '1',
    GITHUB_APP_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
  let server, accessible = true;
  const lock = { name: 'test-app', lockfileVersion: 3, packages: {
    '': { name: 'test-app', version: '1.0.0', dependencies: { semver: '^7.5.1' } },
    'node_modules/semver': { version: '7.5.1' }
  } };
  try {
    globalThis.fetch = async (url, options) => {
      const address = String(url);
      if (address.startsWith('http://127.0.0.1:')) return originalFetch(url, options);
      if (address.endsWith('/app/installations/123/access_tokens')) return Response.json({ token: 'fixture-token' });
      if (address.includes('/installation/repositories?')) return Response.json({ repositories: accessible ? [{ full_name: 'customer-org/app', private: true }] : [] });
      if (address === 'https://api.github.com/repos/customer-org/app') return Response.json({ default_branch: 'main' });
      if (address.endsWith('/commits/main')) return Response.json({ sha: 'a'.repeat(40), commit: { tree: { sha: 'b'.repeat(40) } } });
      if (address.includes('/git/trees/')) return Response.json({ tree: [{ type: 'blob', path: 'package-lock.json', sha: 'c'.repeat(40) }] });
      if (address.includes('/git/blobs/')) return Response.json({ encoding: 'base64', content: Buffer.from(JSON.stringify(lock)).toString('base64') });
      if (address.endsWith('/querybatch')) return Response.json({ results: JSON.parse(options.body).queries.map(item => ({ vulns: item.version === '7.5.1' ? [{ id: 'GHSA-test' }] : [] })) });
      if (address.endsWith('/vulns/GHSA-test')) return Response.json({ id: 'GHSA-test', aliases: ['CVE-2023-42282'], summary: 'Test advisory', database_specific: { severity: 'HIGH' },
        affected: [{ package: { ecosystem: 'npm', name: 'semver' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '7.5.2' }] }] }] });
      if (address === 'https://registry.npmjs.org/semver') return Response.json({ versions: { '7.5.1': {}, '7.5.2': {} } });
      throw new Error(`Unexpected provider call: ${address}`);
    };
    const { app } = createWorkerApp({ db, env, schedule: () => {} });
    const accounts = createAccounts(db), owner = accounts.upsertUser(1234, 'org-member'), other = accounts.upsertUser(5678, 'other-customer');
    accounts.createWorkspace(owner.id, 'org-workspace', { company: 'Customer', github: { installationId: 123, account: 'customer-org' } });
    accounts.createWorkspace(other.id, 'other-workspace', { company: 'Other', github: { installationId: 456, account: 'other-org' } });
    for (const [id, user, workspaceId] of [['a'.repeat(64), owner, 'org-workspace'], ['b'.repeat(64), other, 'other-workspace'], ['c'.repeat(64), owner, 'org-workspace']]) {
      db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run(id, JSON.stringify({ userId: user.id, workspaceId }), Date.now());
    }
    server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
    const base = `http://127.0.0.1:${server.address().port}`;
    const call = async (route, method = 'GET', body, session = 'a') => {
      const response = await originalFetch(`${base}/api/${route}`, { method, headers: { cookie: `purple_session=${session.repeat(64)}`, 'content-type': 'application/json' },
        ...(body ? { body: JSON.stringify(body) } : {}) });
      return { status: response.status, data: await response.json() };
    };
    const item = { repository: 'customer-org/app', installationId: 123 };
    const state = (await call('state')).data;
    assert.equal(state.cloudflare, null); assert.equal(state.openrouter, null); assert.ok(state.github);
    assert.equal((await call('dependencies/scan', 'POST', item)).status, 403);
    assert.equal((await call('dependencies/rehearsal', 'POST', item)).status, 403);
    assert.equal((await call('dependencies/repositories', 'POST', { ...item, installationId: 456 })).status, 403);
    assert.equal((await call('dependencies/repositories', 'POST', { ...item, repository: 'customer-org/secret' })).status, 403);
    assert.equal((await call('dependencies/repositories', 'POST', item)).status, 200);
    const scanned = await call('dependencies/scan', 'POST', item);
    assert.equal(scanned.status, 200); assert.equal(scanned.data.snapshot.vulnerabilityCheck.status, 'complete');
    assert.equal(scanned.data.snapshot.vulnerabilityCheck.findings[0].cves[0], 'CVE-2023-42282');
    assert.equal((await call('dependencies/check', 'POST', item)).status, 200);
    const planned = await call('dependencies/upgrade-plan', 'POST', { ...item, name: 'semver', version: '7.5.1' });
    assert.equal(planned.status, 200); assert.equal(planned.data.plan.targetVersion, '7.5.2');
    const prompt = buildRemediationPrompt({ repository: item.repository, snapshot: scanned.data.snapshot,
      findings: scanned.data.snapshot.vulnerabilityCheck.findings, plans: [planned.data.plan] });
    assert.match(prompt, /customer-org\/app/); assert.match(prompt, /7\.5\.2/); assert.match(prompt, /CVE-2023-42282/);
    const synced = await call('dependencies/sync', 'POST', item);
    assert.equal(synced.status, 200); assert.equal(synced.data.snapshot.upgradePlans[0].targetVersion, '7.5.2');
    assert.equal((await call('dependencies/sync', 'POST', item, 'b')).status, 403);
    const secondDevice = (await call('dependencies', 'GET', null, 'c')).data;
    assert.equal(secondDevice.repositories[0].repository, item.repository); assert.equal(secondDevice.snapshots.length, 1);
    assert.deepEqual(secondDevice.mappings, []);
    assert.deepEqual((await call('dependencies', 'GET', null, 'b')).data.snapshots, []);
    assert.equal((await call('dependencies/repositories', 'POST', item, 'b')).status, 403);
    assert.equal((await call('dependencies/rehearsal', 'POST', item, 'b')).status, 403);
    assert.equal((await call('dependencies/upgrade-plan', 'POST', { ...item, name: 'semver', version: '7.5.1' }, 'b')).status, 403);
    accessible = false;
    for (const action of ['scan', 'sync', 'check', 'upgrade-plan', 'rehearsal']) assert.equal((await call(`dependencies/${action}`, 'POST', item)).status, 403);
    assert.equal((await call('dependencies/repositories', 'DELETE', item)).status, 200);
    assert.deepEqual((await call('dependencies', 'GET', null, 'c')).data.repositories, []);
    assert.equal((await call('vulnerabilities')).data.metrics.total, 0);
  } finally {
    globalThis.fetch = originalFetch;
    if (server) await new Promise(resolve => server.close(resolve));
    db.close();
  }
});
