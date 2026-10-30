import test from 'node:test';
import assert from 'node:assert/strict';
import { registerDependencyRoutes } from '../server/dependency-routes.js';

test('missing lockfiles produce actionable API responses without starting paid or free simulations', async () => {
  const handlers = new Map(), coverage = { status: 'manifest_only', complete: false, missingLockfiles: [{ manifest: 'package.json' }] };
  const blocked = () => Object.assign(new Error('Generate and commit the lockfile, then rescan.'), { status: 400, code: 'lockfile_required', coverage });
  let dispatches = 0;
  const app = Object.fromEntries(['get', 'post', 'delete'].map(method => [method, (path, handler) => handlers.set(`${method}:${path}`, handler)]));
  const mapper = { upgradePlan: async () => { throw blocked(); }, snapshots: () => [] };
  registerDependencyRoutes(app, { github: { repositories: async () => [{ fullName: 'org/project' }] }, mapper,
    runner: { mappings: () => [] }, rehearsals: { start: () => { throw blocked(); } }, dispatchRehearsals: () => { dispatches++; } });
  const request = { body: { repository: 'org/project', installationId: 1, name: 'example', version: '1.0.0' }, sessionId: 'workspace',
    session: { github: { installationId: 1, account: 'org' }, dependencyRepositories: { project: { installationId: 1, repository: 'org/project' } } } };
  for (const action of ['upgrade-plan', 'rehearsal']) {
    let status, result;
    const response = { status(value) { status = value; return this; }, json(value) { result = value; return this; } };
    await handlers.get(`post:/api/dependencies/${action}`)(request, response);
    assert.equal(status, 400); assert.equal(result.code, 'lockfile_required'); assert.deepEqual(result.coverage, coverage);
    assert.match(result.error, /lockfile/);
  }
  assert.equal(dispatches, 0); assert.equal(mapper.repositoryLocks.size, 0);
});
