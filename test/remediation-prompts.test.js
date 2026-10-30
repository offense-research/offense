import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRemediationPrompt, buildOneShotPrompt } from '../src/remediation-prompts.js';
import { mergeDependencySnapshot } from '../src/rehearsal-evidence.js';
const finding = { id: 'GHSA-example', package: 'example', version: '1.0.0', fixedVersions: ['1.2.0'], cves: ['CVE-2026-example'], severity: 'HIGH', summary: 'Example flaw' };
const snapshot = { revision: 'abc123', scannedAt: 1, files: ['api/package-lock.json'], vulnerabilityCheck: { checkedAt: 2 } };

test('background synchronization preserves incomplete diagnostics without promoting them and invalidates changed scans', () => {
  const next = { ...snapshot, repository: 'org/api', installationId: 1 };
  const rehearsal = { id: 'saved', status: 'completed', repository: 'org/api', installationId: 1,
    revision: snapshot.revision, scannedAt: snapshot.scannedAt, advisoryCheckedAt: 2, result: { scenarios: [] } };
  const merged = mergeDependencySnapshot({ ...next, rehearsal }, next);
  assert.equal(merged.rehearsal.id, 'saved'); assert.equal(merged.rehearsal.stale, false);
  const prompt = buildOneShotPrompt({ repository: 'org/api', snapshot: merged, findings: [] });
  assert.match(prompt, /"id": "saved"/); assert.match(prompt, /"usable": false/); assert.match(prompt, /"evidenceAvailable": true/);
  assert.equal(mergeDependencySnapshot(merged, { ...next, revision: 'new' }).rehearsal.stale, true);
  assert.equal(mergeDependencySnapshot(merged, { ...next, repository: 'org/other' }).rehearsal, null);
});

test('individual prompt includes checked update path, parent migrations and verification work', () => {
  const prompt = buildRemediationPrompt({ repository: 'org/api', snapshot, findings: [finding], plans: [{
    name: 'example', currentVersion: '1.0.0', targetVersion: '1.2.0', releases: ['1.0.0', '1.1.0', '1.2.0'],
    steps: [{ from: '1.0.0', to: '1.1.0', changes: ['peer update'] }],
    impact: { paths: [['app', 'parent', 'example']], parents: [{ name: 'parent', compatible: false }] },
    parentOptions: [{ parent: 'parent', version: '2.0.0' }], considered: []
  }] });
  assert.match(prompt, /"targetVersion": "1.2.0"/);
  assert.match(prompt, /"parentUpgrades"/);
  assert.match(prompt, /CVE-2026-example/);
  assert.match(prompt, /api\/package-lock.json/);
  assert.match(prompt, /fails before remediation and passes afterward/);
  assert.match(prompt, /not instructions to install every release/);
});

test('repository one-shot includes every advisory without including other repositories', () => {
  const inputs = [{ repository: 'org/api', snapshot, findings: [finding, { ...finding, id: 'GHSA-unfixed', fixedVersions: [] }] },
    { repository: 'org/worker', snapshot: { ...snapshot, revision: 'def456' }, findings: [{ ...finding, id: 'GHSA-second' }] }];
  const prompt = buildOneShotPrompt(inputs[0]);
  for (const value of ['org/api', 'abc123', 'GHSA-example', 'GHSA-unfixed']) assert.ok(prompt.includes(value));
  for (const value of ['org/worker', 'def456', 'GHSA-second']) assert.ok(!prompt.includes(value));
  assert.match(prompt, /Work only in this repository/);
  assert.match(prompt, /"status": "not yet planned"/);
  assert.match(prompt, /advisory-specific candidates, not a checked upgrade path/);
  assert.match(prompt, /If no fixed release exists/);
  assert.match(prompt, /Never drop an item silently/);
});

test('automatic repository preparation deduplicates package work and includes blocked advisories', async () => {
  const { prepareRepositoryPrompt } = await import('../src/remediation-prompts.js');
  const calls = [], progress = [];
  const result = await prepareRepositoryPrompt({ repository: 'org/api', snapshot,
    findings: [finding, { ...finding, id: 'GHSA-overlap' }, { ...finding, package: 'unfixed', id: 'GHSA-blocked' }],
    onProgress: value => progress.push(value),
    loadPlan: async value => {
      calls.push(value.package);
      if (value.package === 'unfixed') throw new Error('No published fix');
      return { name: value.package, currentVersion: value.version, targetVersion: '1.2.0', releases: ['1.0.0', '1.2.0'],
        impact: { paths: [['app', value.package]], parents: [] }, steps: [], parentOptions: [], considered: [] };
    }
  });
  assert.deepEqual(calls, ['example', 'unfixed']);
  for (const id of ['GHSA-example', 'GHSA-overlap', 'GHSA-blocked']) assert.ok(result.prompt.includes(id));
  assert.match(result.prompt, /"targetVersion": "1.2.0"/);
  assert.match(result.prompt, /"status": "blocked"/);
  assert.match(result.prompt, /No published fix/);
  assert.doesNotMatch(result.prompt, /not yet planned/);
  assert.equal(result.plans.length, 1);
  assert.equal(result.planErrors.length, 1);
  assert.deepEqual(progress.at(-1), { completed: 2, total: 2 });
});

test('mitigation evidence is distinct from a planned package upgrade in the agent prompt', () => {
  const prompt = buildRemediationPrompt({ repository: 'org/api', snapshot, findings: [finding], plans: [{
    name: finding.package, currentVersion: finding.version, targetVersion: null,
    impact: { paths: [['app', 'example']] }, mitigation: { steps: ['Review a depth guard'], status: 'proposed; not applied' }
  }] });
  assert.match(prompt, /"kind": "mitigation"/);
  assert.match(prompt, /requires application and verification/);
  assert.doesNotMatch(prompt, /"targetVersion"/);
});
