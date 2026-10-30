import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRemediationPrompt, buildOneShotPrompt, buildLockfilePrompt } from '../src/remediation-prompts.js';

test('declaration prompts never call a sampled version an installed version or a verified vulnerability', () => {
  const finding = { id: 'GHSA-example', package: 'example', version: '1.0.0', declaredRange: '^1.0.0', resolved: false, assessmentKind: 'declared_range' };
  const input = { repository: 'org/project', snapshot: { revision: 'a'.repeat(40), files: ['package.json'], coverage: { missingLockfiles: [{ manifest: 'package.json' }], complete: false }, vulnerabilityCheck: { findings: [finding] } }, findings: [finding] };
  for (const builder of [buildRemediationPrompt, buildOneShotPrompt, buildLockfilePrompt]) {
    const prompt = builder(input);
    assert.match(prompt, /"representativeVersionChecked": "1.0.0"/);
    assert.match(prompt, /"declaredRange": "\^1.0.0"/);
    assert.doesNotMatch(prompt, /"installedVersion"\s*:/);
    assert.match(prompt, /existing package manager/);
    assert.match(prompt, /lifecycle scripts disabled/);
    assert.match(prompt, /not proof of what is deployed/);
    assert.match(prompt, /Run Offense again/);
  }
});
