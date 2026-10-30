import test from 'node:test';
import assert from 'node:assert/strict';
import { fixPathSummary, repositoryMonitorStatus } from '../src/fix-workflow.js';

test('repo readiness counts package/version paths once and keeps unresolved targets out of checked paths', () => {
  const findings = [{ package: 'example', version: '1', fixedVersions: ['2'] }, { package: 'example', version: '1' },
    { package: 'blocked', version: '1' }, { package: 'pending', version: '1' }, { package: 'failed', version: '1' }];
  const plans = [{ name: 'example', currentVersion: '1', targetVersion: '2', impact: { parents: [] } },
    { name: 'blocked', currentVersion: '1', targetVersion: '2', constraintWarnings: ['Peer conflict'], impact: { parents: [] } }];
  const result = fixPathSummary(findings, plans, [{ name: 'failed', version: '1', error: 'No registry result' }]);
  assert.deepEqual(result, { total: 4, checked: 1, blocked: 2, pending: 1, text: '1 path checked · 2 need review · 1 not prepared' });
  assert.equal(fixPathSummary([{ package: 'example', version: '1', resolved: false }], plans).checked, 0);
});

test('monitor failures cannot render as healthy or be hidden by an in-progress browser request', () => {
  assert.deepEqual(repositoryMonitorStatus({ status: 'access_required' }, { updating: true }), { state: 'access_required', label: 'Access needed' });
  assert.equal(repositoryMonitorStatus({ status: 'retrying' }).state, 'retrying');
  assert.equal(repositoryMonitorStatus({ status: 'watching' }).state, 'watching');
  assert.equal(repositoryMonitorStatus({ status: 'watching' }, { updating: true }).state, 'checking');
  assert.equal(repositoryMonitorStatus(null).state, 'pending');
  assert.equal(repositoryMonitorStatus(null, { backgroundEnabled: false }).label, 'Manual checks');
});

test('saved automation pauses and integration-only modes do not appear as active background monitoring', () => {
  assert.equal(repositoryMonitorStatus({ status: 'watching', policy: { enabled: false } }).state, 'paused');
  assert.equal(repositoryMonitorStatus({ status: 'manual' }).state, 'manual');
  assert.equal(repositoryMonitorStatus({ status: 'watching', policy: { enabled: true, onChange: false, schedule: 'off' } }).state, 'manual');
  assert.equal(repositoryMonitorStatus({ status: 'watching' }, { backgroundEnabled: false }).label, 'Manual checks');
});
