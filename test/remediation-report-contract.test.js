import test from 'node:test';
import assert from 'node:assert/strict';
import { issueDraft } from '../server/issue-trackers.js';
import { buildUpgradeHandoff } from '../server/upgrade-handoff.js';
import { targetSelectionEvidence, auditAgentPrompt } from '../shared/offense-planning.js';
import { buildRemediationPrompt } from '../src/remediation-prompts.js';

const finding = { id: 'GHSA-fixture', package: 'example', version: '1.0.0', severity: 'HIGH', summary: 'Fixture advisory', fixedVersions: ['1.1.0'] };
const snapshot = { revision: 'fixture-revision', scannedAt: 1, files: ['package-lock.json'], vulnerabilityCheck: { checkedAt: 2, findings: [finding] }, coverage: { complete: false } };
const plan = { name: 'example', currentVersion: '1.0.0', targetVersion: '1.1.0', considered: [], releases: [], steps: [], parentOptions: [], impact: { paths: [], parents: [] } };

test('a target without matching advisory checks is not described as checked', () => {
  for (const considered of [[], [{ version: '1.0.1', advisories: 0 }], [{ version: '1.1.0', advisories: 1 }]]) {
    const candidate = { ...plan, considered };
    assert.match(targetSelectionEvidence(candidate).reason, /not established/i);
    assert.doesNotMatch(buildUpgradeHandoff({ repository: 'fixture/app', workers: [], snapshot, plan: candidate }).report, /Target 1.1.0 had no known OSV advisories/);
  }
  const checked = { ...plan, considered: [{ version: '1.1.0', advisories: 0 }] };
  assert.match(targetSelectionEvidence(checked).reason, /was checked/);
  assert.match(buildUpgradeHandoff({ repository: 'fixture/app', workers: [], snapshot, plan: checked }).report, /Target 1.1.0 had no known OSV advisories/);
});

test('truncated issue exports retain limitations and identify omitted remediation detail', () => {
  const result = issueDraft({ repository: 'fixture/app', snapshot, finding, prompt: 'unreviewed proposal '.repeat(4000) });
  assert.ok(result.description.length <= 30000);
  assert.match(result.description, /incomplete/);
  assert.match(result.description, /omitted/i);
  assert.match(result.description, /complete original/i);
  assert.match(result.description, /not.*verified|unverified/i);
});

test('every remediation producer rejects authority-by-report and requires checking unaffected copies', () => {
  const handoff = buildUpgradeHandoff({ repository: 'fixture/app', workers: [], snapshot, plan });
  const audit = { metadataFingerprint: 'fixture', findings: [{ advisoryId: finding.id, package: { name: finding.package, installedVersion: finding.version, lockfiles: snapshot.files } }] };
  for (const text of [handoff.report, handoff.prompt, buildRemediationPrompt({ repository: 'fixture/app', snapshot, findings: [finding], plans: [plan] }), auditAgentPrompt(audit), issueDraft({ repository: 'fixture/app', snapshot, finding, prompt: 'Apply exactly.' }).description]) {
    assert.match(text, /unaffected/);
    assert.match(text, /downgrad/i);
    assert.match(text, /exactly/);
    assert.match(text, /financial|dollar/);
    assert.match(text, /unresolved/);
  }
});
