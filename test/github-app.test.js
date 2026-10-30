import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createGitHubApp } from '../server/github-app.js';

test('GitHub App visibility distinguishes a private app from a public app', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'purple-github-app-'));
  try {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const keyPath = join(dir, 'app.pem');
    writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
    for (const [status, isPublic] of [[404, false], [200, true]]) {
      const calls = [];
      const app = createGitHubApp({ appId: 123, privateKeyPath: keyPath, fetchImpl: async (url, options) => {
        calls.push({ url, options });
        if (url.endsWith('/app')) return { ok: true, json: async () => ({ slug: 'purple-team-dev', owner: { login: 'owner', type: 'User' } }) };
        return { status };
      } });
      assert.deepEqual(await app.appInfo(), { slug: 'purple-team-dev', owner: 'owner', ownerType: 'User', isPublic });
      assert.equal(calls.length, 2);
      assert.match(calls[0].options.headers.Authorization, /^Bearer /);
      assert.equal(calls[1].options.headers.Authorization, undefined);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('Worker discovery authenticates per installation, skips empty repos and reads nested configs', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const app = createGitHubApp({ appId: 123, privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    fetchImpl: async (url, options) => {
      const reply = body => ({ ok: true, json: async () => body });
      if (url.endsWith('/access_tokens')) return reply({ token: 'installation-secret' });
      assert.equal(options.headers.Authorization, 'Bearer installation-secret');
      if (url.includes('/installation/repositories')) return reply({ repositories: [
        { full_name: 'org/empty' }, { full_name: 'org/monorepo' }
      ] });
      if (url.includes('/org/empty/')) return { ok: false, status: 409 };
      if (url.includes('/git/trees/')) return reply({ tree: [
        { type: 'blob', path: 'apps/api/wrangler.jsonc', sha: 'config', size: 100 },
        { type: 'blob', path: 'node_modules/example/wrangler.toml', sha: 'ignored', size: 100 }
      ] });
      assert.ok(url.endsWith('/git/blobs/config'));
      return reply({ encoding: 'base64', content: Buffer.from('{"name":"api","env":{"production":{"name":"api-production"}}}').toString('base64') });
    } });
  const repos = await app.workerRepositories(42);
  assert.deepEqual(repos.map(repo => ({ name: repo.fullName, id: repo.installationId, workers: repo.workers })),
    [{ name: 'org/monorepo', id: 42, workers: ['api', 'api-production'] }]);
});

test('dependency evidence records a checkout commit rather than a Git tree identifier', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const commit = 'a'.repeat(40), tree = 'b'.repeat(40);
  const app = createGitHubApp({ appId: 123, privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }), fetchImpl: async url => {
    let data;
    if (url.endsWith('/access_tokens')) data = { token: 'fixture-token' };
    else if (url.endsWith('/repos/org/repo')) data = { default_branch: 'main' };
    else if (url.endsWith('/commits/main')) data = { sha: commit, commit: { tree: { sha: tree } } };
    else {
      assert.ok(url.endsWith(`/git/trees/${tree}?recursive=1`));
      data = { sha: tree, tree: [] };
    }
    return { ok: true, json: async () => data };
  } });
  assert.equal((await app.dependencyFiles(42, 'org/repo')).revision, commit);
});

test('GitHub dependency discovery reads pnpm lockfiles at the pinned tree', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const commit = 'c'.repeat(40), tree = 'd'.repeat(40), lock = 'e'.repeat(40);
  const app = createGitHubApp({ appId: 123, privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }), fetchImpl: async url => {
    let data;
    if (url.endsWith('/access_tokens')) data = { token: 'fixture-token' };
    else if (url.endsWith('/repos/org/repo')) data = { default_branch: 'main' };
    else if (url.endsWith('/commits/main')) data = { sha: commit, commit: { tree: { sha: tree } } };
    else if (url.endsWith(`/git/trees/${tree}?recursive=1`)) data = { tree: [{ type: 'blob', path: 'pnpm-lock.yaml', sha: lock, size: 40 }] };
    else { assert.ok(url.endsWith(`/git/blobs/${lock}`)); data = { encoding: 'base64', content: Buffer.from("lockfileVersion: '9.0'\npackages: {}\nsnapshots: {}\n").toString('base64') }; }
    return { ok: true, json: async () => data };
  } });
  const result = await app.dependencyFiles(42, 'org/repo');
  assert.equal(result.revision, commit); assert.equal(result.files[0].path, 'pnpm-lock.yaml');
  assert.match(result.files[0].content, /lockfileVersion/);
});

test('repository inventory has metadata-only access and dependency reads restrict tokens to one repository', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const requests = [], commit = 'a'.repeat(40), tree = 'b'.repeat(40);
  const app = createGitHubApp({ appId: 123, privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    fetchImpl: async (url, options) => {
      if (url.endsWith('/access_tokens')) {
        const body = JSON.parse(options.body); requests.push(body);
        return Response.json({ token: body.repositories ? 'single-repository-token' : 'metadata-only-token' });
      }
      if (url.includes('/installation/repositories')) {
        assert.equal(options.headers.Authorization, 'Bearer metadata-only-token');
        return Response.json({ repositories: [{ full_name: 'org/selected', private: true }] });
      }
      assert.equal(options.headers.Authorization, 'Bearer single-repository-token');
      if (url.endsWith('/repos/org/selected')) return Response.json({ default_branch: 'main' });
      if (url.endsWith('/commits/main')) return Response.json({ sha: commit, commit: { tree: { sha: tree } } });
      return Response.json({ tree: [] });
    } });
  await app.repositories(42);
  await app.dependencyRevision(42, 'org/selected');
  await app.dependencyFiles(42, 'org/selected');
  assert.deepEqual(requests, [
    { permissions: { metadata: 'read' } },
    { permissions: { contents: 'read' }, repositories: ['selected'] },
    { permissions: { contents: 'read' }, repositories: ['selected'] }
  ]);
});

test('code credentials reject invalid repository scope and never retry with broader access after denial', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 }); let calls = 0;
  const app = createGitHubApp({ appId: 123, privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    fetchImpl: async (_url, options) => {
      calls++;
      assert.deepEqual(JSON.parse(options.body), { permissions: { contents: 'read' }, repositories: ['denied'] });
      return new Response('{}', { status: 422 });
    } });
  for (const invalid of ['', null, 'org', 'org/repo/extra', '../repo', 'org/..', 'org/repo?other=true']) {
    await assert.rejects(app.installationToken(42, invalid), /valid owner\/repository/);
  }
  assert.equal(calls, 0);
  await assert.rejects(app.installationToken(42, 'org/denied'), error => error.status === 422);
  assert.equal(calls, 1, 'a denied single-repo token must never fall back to an installation-wide token');
});
