import test from 'node:test';
import assert from 'node:assert/strict';
import { connectInstallation, purpleInstallations, resolveInstallationConnections, workspaceInstallations } from '../server/github-installations.js';

test('only valid installations of the Purple App are connectable', () => {
  const data = { installations: [
    { id: 12, app_slug: 'purple-app', account: { login: 'my-org' } },
    { id: 13, app_slug: 'another-app', account: { login: 'my-org' } },
    { id: 14, app_slug: 'purple-app', account: null },
    { id: 15, app_slug: 'purple-app', account: { login: 'my-user' } }
  ] };
  assert.deepEqual(purpleInstallations(data, 'purple-app'), [
    { installationId: 12, account: 'my-org' },
    { installationId: 15, account: 'my-user' }
  ]);
});

test('a workspace can retain multiple GitHub App installations', () => {
  const session = { github: { installationId: 12, account: 'my-user' } };
  connectInstallation(session, { installationId: 34, account: 'my-org' });
  connectInstallation(session, { installationId: 34, account: 'my-org' });
  assert.deepEqual(workspaceInstallations(session), [
    { installationId: 12, account: 'my-user' },
    { installationId: 34, account: 'my-org' }
  ]);
  assert.equal(session.github.installationId, 12);
});

test('connecting an additional organization picks the new installation instead of the existing personal one', () => {
  const personal = { installationId: 12, account: 'my-user' };
  const organization = { installationId: 34, account: 'my-org' };
  const workspace = { github: personal };
  const result = resolveInstallationConnections(workspace, [personal, organization]);
  assert.deepEqual(result, { connections: [organization], choices: [] });
  result.connections.forEach(item => connectInstallation(workspace, item));
  assert.deepEqual(workspaceInstallations(workspace), [personal, organization]);
  assert.deepEqual(resolveInstallationConnections(workspace, [personal, organization]), { connections: [], choices: [] });
});

test('access refresh connects only user-verified installations and explicit selections cannot bypass that list', () => {
  const personal = { installationId: 12, account: 'my-user' };
  const orgA = { installationId: 34, account: 'org-a' };
  const orgB = { installationId: 56, account: 'org-b' };
  const workspace = { github: personal };
  assert.deepEqual(resolveInstallationConnections(workspace, [personal, orgA, orgB]), { connections: [], choices: [orgA, orgB] });
  assert.deepEqual(resolveInstallationConnections(workspace, [personal, orgA], { sync: true }), { connections: [personal, orgA], choices: [] });
  assert.deepEqual(resolveInstallationConnections(workspace, [personal, orgA], { installationId: 34 }), { connections: [orgA], choices: [] });
  assert.throws(() => resolveInstallationConnections(workspace, [personal, orgA], { installationId: 56, sync: true }), /not available/);
});
