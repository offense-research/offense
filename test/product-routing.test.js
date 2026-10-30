import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveProductRoute } from '../src/product-routing.js';

test('fresh app visits open agent setup and account links select their management section', () => {
  for (const path of ['/', '/app', '/app/', '/login']) assert.deepEqual(resolveProductRoute(path), { surface: 'console', section: 'start' });
  assert.deepEqual(resolveProductRoute('/account/'), { surface: 'console', section: 'keys' });
  for (const path of ['/activity', '/activity/', '/usage']) assert.deepEqual(resolveProductRoute(path), { surface: 'console', section: 'activity' });
  assert.deepEqual(resolveProductRoute('/billing', '', '?scannerPayment=returned'), { surface: 'console', section: 'billing' });
  assert.equal(resolveProductRoute('/app', '', '?connected=github').surface, 'console');
});

test('explicit V1 routes and saved workflow bookmarks preserve access to existing projects', () => {
  assert.equal(resolveProductRoute('/legacy', '#billing').surface, 'legacy');
  for (const section of ['dependencies', 'connections', 'collector', 'investigations', 'events', 'worker-repositories'])
    assert.equal(resolveProductRoute('/app', '#' + section).surface, 'legacy');
  assert.equal(resolveProductRoute('/billing', '', '?payment=returned').surface, 'legacy');
  assert.equal(resolveProductRoute('/account', '#dependencies').surface, 'console');
});

test('device consent, metrics and skill setup retain dedicated entrypoints', () => {
  assert.deepEqual(resolveProductRoute('/device/', '#code=ABCD-EFGH'), { surface: 'device' });
  assert.deepEqual(resolveProductRoute('/metrics'), { surface: 'metrics' });
  assert.deepEqual(resolveProductRoute('/skill/'), { surface: 'skill' });
});
