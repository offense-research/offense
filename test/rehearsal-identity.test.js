import test from 'node:test';
import assert from 'node:assert/strict';
import { bindScanEvidence, scanEvidenceIdentity } from '../server/rehearsal-identity.js';

const original = {
  repository: 'org/repo', installationId: 1, revision: 'a'.repeat(40), scannedAt: 10, lastSyncedAt: 11,
  files: ['package-lock.json'], packages: [{ name: 'example', version: '1.0.0', resolved: true, files: ['package-lock.json'] }],
  graph: { nodes: [{ id: 'root', name: 'app', version: '', requires: [{ name: 'example', range: '^1.0.0', to: 'leaf' }] },
    { id: 'leaf', name: 'example', version: '1.0.0', requires: [] }], warnings: [] },
  coverage: { status: 'resolved', complete: true, missingLockfiles: [], assessmentCheckedAt: 12 }, warnings: [],
  vulnerabilityCheck: { source: 'OSV', status: 'complete', checkedAt: 13, findings: [
    { id: 'GHSA-first', package: 'example', version: '1.0.0', severity: 'HIGH', fixedVersions: ['1.1.0', '2.0.0'],
      advisory: { modified: '2026-10-24', details: 'Affected behavior.', affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '1.1.0' }] }] }] } },
    { id: 'GHSA-second', package: 'example', version: '1.0.0', severity: 'MODERATE', fixedVersions: ['1.2.0'] }
  ] }
};

test('SHA256 scan identity ignores only observation clocks, set ordering and unrelated cached job/plan state', () => {
  const refreshed = structuredClone(original);
  refreshed.scannedAt++; refreshed.lastSyncedAt++; refreshed.coverage.assessmentCheckedAt++; refreshed.vulnerabilityCheck.checkedAt++;
  refreshed.graph.nodes.reverse(); refreshed.vulnerabilityCheck.findings.reverse(); refreshed.vulnerabilityCheck.findings[1].fixedVersions.reverse();
  refreshed.upgradePlans = [{ plannedAt: Date.now() }]; refreshed.rehearsal = { status: 'running' };
  const identity = scanEvidenceIdentity(original);
  assert.match(identity, /^[a-f0-9]{64}$/); assert.equal(scanEvidenceIdentity(refreshed), identity);
  assert.equal(bindScanEvidence({ ...refreshed, evidenceIdentity: 'untrusted-stale-key' }).evidenceIdentity, identity);
});

test('commit, dependency, coverage and advisory changes remain distinct, including ordered OSV range events', () => {
  for (const change of [
    value => { value.revision = 'b'.repeat(40); },
    value => { value.packages[0].version = '1.0.1'; },
    value => { value.graph.nodes[0].requires[0].range = '^2.0.0'; },
    value => { value.coverage.complete = false; },
    value => { value.vulnerabilityCheck.findings.push({ id: 'GHSA-new', package: 'example', version: '1.0.0' }); },
    value => { value.vulnerabilityCheck.findings.pop(); },
    value => { value.vulnerabilityCheck.findings[0].severity = 'CRITICAL'; },
    value => { value.vulnerabilityCheck.findings[0].fixedVersions = ['1.1.1']; },
    value => { value.vulnerabilityCheck.findings[0].advisory.modified = '2026-10-25'; },
    value => { value.vulnerabilityCheck.findings[0].advisory.details = 'Changed affected behavior.'; },
    value => { value.vulnerabilityCheck.findings[0].advisory.affected[0].ranges[0].events.reverse(); },
    value => { value.vulnerabilityCheck.status = 'failed'; }
  ]) {
    const changed = structuredClone(original); change(changed);
    assert.notEqual(scanEvidenceIdentity(changed), scanEvidenceIdentity(original));
  }
});

test('derived impact copy cannot change scan identity while provider weakness evidence still does', () => {
  const explained = structuredClone(original);
  explained.vulnerabilityCheck.findings[0].impact = { schemaVersion: 1, headline: 'A plain-English consequence' };
  const identity = scanEvidenceIdentity(original);
  assert.equal(scanEvidenceIdentity(explained), identity);
  explained.vulnerabilityCheck.findings[0].impact.headline = 'A revised explanation';
  assert.equal(scanEvidenceIdentity(explained), identity);
  assert.equal(explained.vulnerabilityCheck.findings[0].impact.headline, 'A revised explanation', 'Identity derivation must not mutate a saved finding.');
  explained.vulnerabilityCheck.findings[0].advisory.cwes = ['CWE-94', 'CWE-78'];
  const withWeaknesses = scanEvidenceIdentity(explained);
  assert.notEqual(withWeaknesses, identity);
  explained.vulnerabilityCheck.findings[0].advisory.cwes.reverse();
  assert.equal(scanEvidenceIdentity(explained), withWeaknesses);
});
