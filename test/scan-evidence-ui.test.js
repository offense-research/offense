import { passingUpgradeEvidence } from './fixtures/upgrade-evidence.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeDependencySnapshot } from '../src/rehearsal-evidence.js';
import { promptEvidenceVersion } from '../src/prompt-evidence.js';
import { buildOneShotPrompt } from '../src/remediation-prompts.js';
import { extractPromptEvidence } from '../scripts/validate-live-rehearsal.mjs';
import { routeEvidence } from '../src/upgrade-routes.js';

function fixture(status = 'completed') {
  const snapshot = { repository: 'owner/repo', installationId: 123, revision: 'a'.repeat(40), evidenceIdentity: '1'.repeat(64), scannedAt: 1,
    files: ['package-lock.json'], vulnerabilityCheck: { status: 'complete', checkedAt: 2, findings: [] } };
  const change = { name: 'leaf', currentVersion: '1.0.0', targetVersion: '1.1.0' };
  snapshot.rehearsal = { id: 'saved-job', repository: snapshot.repository, installationId: snapshot.installationId, revision: snapshot.revision,
    evidenceIdentity: snapshot.evidenceIdentity, scannedAt: 1, advisoryCheckedAt: 2, status, createdAt: Date.now() - 1000, updatedAt: 3, stale: false,
    result: passingUpgradeEvidence({ revision:snapshot.revision,changes:[change] }).result };
  return { snapshot, route: { id: 'published', changes: [change] } };
}

test('same-content automatic refresh preserves running/completed rehearsal evidence and prompt cache identity', () => {
  for (const status of ['running', 'completed']) {
    const { snapshot, route } = fixture(status);
    const next = { ...snapshot, rehearsal: undefined, scannedAt: 10, lastSyncedAt: 30, vulnerabilityCheck: { ...snapshot.vulnerabilityCheck, checkedAt: 20 } };
    const merged = mergeDependencySnapshot(snapshot, next);
    assert.equal(merged.rehearsal.id, snapshot.rehearsal.id); assert.equal(merged.rehearsal.stale, false);
    assert.equal(promptEvidenceVersion(merged), promptEvidenceVersion(snapshot));
    const copied = extractPromptEvidence(buildOneShotPrompt({ repository: snapshot.repository, snapshot: merged, findings: [] }));
    assert.equal(copied.evidenceIdentity, snapshot.evidenceIdentity); assert.equal(copied.installationId, snapshot.installationId);
    assert.equal(copied.upgradeRehearsal.usable, status === 'completed');
    assert.equal(copied.upgradeRehearsal.scannedAt, 1, 'the original job observations remain truthful');
    if (status === 'completed') assert.equal(routeEvidence(route, merged.rehearsal, merged), 'Scenario checks passed');
  }
});

test('commit, dependency/lock evidence, advisory evidence, repository and installation changes invalidate cached use', () => {
  for (const change of [value => { value.revision = 'b'.repeat(40); },
    value => { value.evidenceIdentity = '2'.repeat(64); }, value => { value.evidenceIdentity = '3'.repeat(64); },
    value => { value.repository = 'owner/other'; }, value => { value.installationId = 456; }]) {
    const { snapshot } = fixture(), next = structuredClone(snapshot); delete next.rehearsal; change(next);
    const merged = mergeDependencySnapshot(snapshot, next);
    assert.ok(!merged.rehearsal || merged.rehearsal.stale);
    assert.notEqual(promptEvidenceVersion(merged), promptEvidenceVersion(snapshot));
    const evidence = extractPromptEvidence(buildOneShotPrompt({ repository: next.repository, snapshot: merged, findings: [] }));
    assert.equal(evidence.upgradeRehearsal.usable, false);
  }
});

test('legacy evidence requires the original observation timestamps and cannot inherit an unrelated identity', () => {
  const { snapshot } = fixture(); delete snapshot.evidenceIdentity; delete snapshot.rehearsal.evidenceIdentity;
  const next = { ...snapshot, rehearsal: undefined, scannedAt: 10, vulnerabilityCheck: { ...snapshot.vulnerabilityCheck, checkedAt: 20 } };
  const merged = mergeDependencySnapshot(snapshot, next);
  assert.equal(merged.rehearsal.stale, true); assert.notEqual(promptEvidenceVersion(merged), promptEvidenceVersion(snapshot));
  next.evidenceIdentity = '1'.repeat(64);
  assert.equal(mergeDependencySnapshot(snapshot, next).rehearsal.stale, true);
});

test('fresh observation clocks cannot revive an expired saved candidate', () => {
  const { snapshot, route } = fixture(); snapshot.rehearsal.createdAt = Date.now() - 25 * 3600000;
  const next = { ...snapshot, rehearsal: undefined, scannedAt: Date.now(), vulnerabilityCheck: { ...snapshot.vulnerabilityCheck, checkedAt: Date.now() } };
  const merged = mergeDependencySnapshot(snapshot, next);
  assert.equal(merged.rehearsal.stale, true);
  assert.equal(routeEvidence(route, merged.rehearsal, merged), 'Not simulated for this scan');
  const copied = extractPromptEvidence(buildOneShotPrompt({ repository: snapshot.repository, snapshot: merged, findings: [] }));
  assert.equal(copied.upgradeRehearsal.usable, false);
});
