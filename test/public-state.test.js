import test from 'node:test';
import assert from 'node:assert/strict';
import { publicState } from '../shared/public-state.js';

const options = { defaultCompany: 'Default', config: { githubAppSlug: 'purple' } };
const project = (session, user, workspaceId, runtime = options) => publicState(session, user, workspaceId, runtime);

test('anonymous projection preserves field order, nulls, defaults and config reference', () => {
  const result = project({});
  assert.deepEqual(result, {
    user: null, workspaceId: null, legacyWorkspace: false, company: '', cloudflare: null,
    collector: null, github: null, connectedGithubInstallations: [], openrouter: null,
    complete: false, config: options.config
  });
  assert.deepEqual(Object.keys(result), ['user', 'workspaceId', 'legacyWorkspace', 'company', 'cloudflare',
    'collector', 'github', 'connectedGithubInstallations', 'openrouter', 'complete', 'config']);
  assert.equal(result.config, options.config);
});

test('default company, legacy connections and signed-in users retain classification', () => {
  assert.equal(project({ company: 'Default' }).legacyWorkspace, false);
  assert.equal(project({ company: 'Customer' }).legacyWorkspace, true);
  assert.equal(project({ githubInstallations: [{ installationId: 1, account: 'org' }] }).legacyWorkspace, false);
  for (const provider of ['cloudflare', 'github', 'openrouter', 'collectorInstall']) {
    assert.equal(project({ company: 'Default', [provider]: {} }).legacyWorkspace, true);
  }
  assert.equal(project({ company: 'Customer' }, { login: 'user' }).legacyWorkspace, false);
});

test('connected projection allowlists fields without leaking credentials or copying runtime config', () => {
  const session = {
    company: 'Customer', secret: 'session-secret', githubAuthorization: { secret: 'oauth-secret' },
    cloudflare: { name: 'Account', accounts: [{ id: 'cf' }], accessToken: 'cf-secret' },
    collectorInstall: { accountId: 'cf', sources: ['api'], status: 'installed', attached: false, secret: 'collector-secret' },
    github: { account: 'org', installationId: '2', secret: 'github-secret' },
    openrouter: { label: 'Key', last4: '1234', secret: 'or-secret' }
  };
  const before = structuredClone(session);
  const result = project(session, { login: 'user', githubId: 7, secret: 'user-secret' }, 'workspace');
  assert.deepEqual(result, {
    user: { login: 'user', githubId: 7 }, workspaceId: 'workspace', legacyWorkspace: false, company: 'Customer',
    cloudflare: { name: 'Account', accounts: [{ id: 'cf' }] },
    collector: { accountId: 'cf', sources: ['api'], status: 'installed', attached: false },
    github: { account: 'org', installationId: '2' }, connectedGithubInstallations: [{ installationId: 2, account: 'org' }],
    openrouter: { label: 'Key', last4: '1234' }, complete: true, config: options.config
  });
  assert.doesNotMatch(JSON.stringify(result), /secret/);
  assert.equal(result.cloudflare.accounts, session.cloudflare.accounts);
  assert.equal(result.collector.sources, session.collectorInstall.sources);
  assert.deepEqual(session, before);
  for (const key of ['company', 'cloudflare', 'github', 'openrouter', 'collectorInstall']) {
    const incomplete = { ...session }; delete incomplete[key];
    assert.equal(project(incomplete).complete, false);
  }
  assert.equal(project({ ...session, collectorInstall: { status: 'pending' } }).complete, false);
});

test('missing provider fields retain undefined properties and JSON omission', () => {
  const result = project({ cloudflare: {}, collectorInstall: {}, github: {}, openrouter: {} }, {});
  assert.deepEqual(result.user, { login: undefined, githubId: undefined });
  assert.deepEqual(result.cloudflare, { name: 'Cloudflare account', accounts: [] });
  assert.deepEqual(result.collector, { accountId: undefined, sources: undefined, status: undefined, attached: undefined });
  assert.deepEqual(result.github, { account: undefined, installationId: undefined });
  assert.deepEqual(result.openrouter, { label: 'Verified key', last4: undefined });
  const json = JSON.parse(JSON.stringify(result));
  assert.deepEqual(json.user, {});
  assert.deepEqual(json.collector, {});
  assert.deepEqual(json.github, {});
  assert.deepEqual(json.openrouter, { label: 'Verified key' });
  assert.deepEqual(project({ collectorInstall: { attached: null }, openrouter: { last4: null } }).openrouter,
    { label: 'Verified key', last4: null });
  assert.equal(project({ collectorInstall: { attached: null } }).collector.attached, null);
});

test('installations normalize IDs, deduplicate primary first and preserve remaining order', () => {
  const result = project({
    github: { installationId: '3', account: 'primary' },
    githubInstallations: [null, { installationId: 3, account: 'duplicate' },
      { installationId: '2', account: 'second', secret: 'hidden' }, { installationId: 0, account: 'invalid' },
      { installationId: 5, account: 5 }, { installationId: 4, account: 'third' }, { installationId: '2', account: 'duplicate' }]
  });
  assert.deepEqual(result.connectedGithubInstallations, [
    { installationId: 3, account: 'primary' }, { installationId: 2, account: 'second' }, { installationId: 4, account: 'third' }
  ]);
  assert.deepEqual(project({ githubInstallations: {} }).connectedGithubInstallations, []);
});

test('each invocation uses its own default company and original config object', () => {
  const node = { defaultCompany: 'Node', config: { runtime: 'node' } };
  const worker = { defaultCompany: 'Worker', config: { runtime: 'worker' } };
  for (const runtime of [node, worker, node]) {
    const result = project({ company: 'Node' }, undefined, undefined, runtime);
    assert.equal(result.config, runtime.config);
    assert.equal(result.legacyWorkspace, runtime === worker);
  }
});
