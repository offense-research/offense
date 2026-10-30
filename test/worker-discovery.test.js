import test from 'node:test';
import assert from 'node:assert/strict';
import { configuredWorkers, uniqueWorkerLinks } from '../server/worker-discovery.js';

test('Worker discovery reads JSONC and TOML environment names without guessing', () => {
  assert.deepEqual(configuredWorkers('wrangler.jsonc', '{// comment\n"name":"api", "env":{"production":{"name":"api-production"}},}'), ['api', 'api-production']);
  assert.deepEqual(configuredWorkers('wrangler.toml', 'name = "api"\n[env.production]\nname = "api-production"'), ['api', 'api-production']);
  assert.deepEqual(configuredWorkers('wrangler.json', '{invalid'), []);
  assert.deepEqual(configuredWorkers('wrangler.toml', 'name="${SECRET}"'), []);
});

test('automatic links require a unique exact config match and preserve manual mappings', () => {
  const repos = [{ fullName: 'org/a', installationId: 1, workers: ['api', 'duplicate', 'manual'] },
    { fullName: 'org/b', installationId: 2, workers: ['duplicate'] }];
  assert.deepEqual(uniqueWorkerLinks(['api', 'api-undefined', 'duplicate', 'manual'], repos,
    [{ sourceWorker: 'manual' }]), [{ sourceWorker: 'api', repository: 'org/a', installationId: 1 }]);
});
