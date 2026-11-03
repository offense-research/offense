import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { TOOL_CATALOG } from '../shared/tool-catalog.js';

test('guided evaluation scenarios cover the catalog and reference readable sanitized receipts', async () => {
  const fixture = JSON.parse(await readFile('test/fixtures/guided-assessment/scenarios.json'));
  assert.equal(fixture.schemaVersion, 1);
  const ids = new Set(), covered = new Set(), catalog = new Set(TOOL_CATALOG.map(tool => tool.id));
  for (const scenario of fixture.scenarios) {
    assert.ok(scenario.id && !ids.has(scenario.id)); ids.add(scenario.id);
    assert.ok(scenario.prompt.trim());
    assert.ok(scenario.assertions.length);
    assert.deepEqual(scenario.entrypoints, ['hosted', 'instructions-only', 'plugin']);
    assert.deepEqual(scenario.transports, ['cli', 'mcp']);
    for (const tool of scenario.candidateTools) { assert.ok(catalog.has(tool), tool); covered.add(tool); }
    for (const file of scenario.projectFiles) assert.ok(!file.startsWith('/') && !file.split('/').includes('..'));
    for (const name of scenario.receipts) {
      assert.match(name, /^[a-z-]+\.json$/);
      const receipt = JSON.parse(await readFile('test/fixtures/guided-assessment/receipts/' + name));
      assert.ok(Array.isArray(receipt.findings));
      assert.ok(receipt.coverage);
      assert.ok(receipt.schemaVersion === 'offense.audit.v1' || receipt.id && receipt.status);
    }
  }
  assert.deepEqual([...covered].sort(), [...catalog].sort());
  for (const id of ['npm-workflows', 'python', 'paid-declined', 'conditional-advisory', 'partial-empty', 'selected-fix', 'plugin-lifecycle', 'injected-output', 'uncertain-submit']) assert.ok(ids.has(id));
});

test('remediation safety scenarios bind reproducible project inputs and expected evidence boundaries', async () => {
  const { scenarios } = JSON.parse(await readFile('test/fixtures/guided-assessment/scenarios.json'));
  const expectedIds = ['mixed-major-override', 'newer-copy-downgrade', 'missing-spec-input', 'historical-spec-input', 'fixed-host-triage', 'unverified-exact-handoff'];
  for (const id of expectedIds) {
    const scenario = scenarios.find(value => value.id === id);
    assert.ok(scenario, `Missing safety scenario: ${id}`);
    assert.match(scenario.fixture, /^test\/fixtures\/remediation-safety\/[a-z-]+\.json$/);
    const fixture = JSON.parse(await readFile(scenario.fixture));
    assert.equal(fixture.synthetic, true);
    assert.ok(fixture.revision);
    assert.deepEqual(Object.keys(fixture.projectFiles).sort(), [...scenario.projectFiles].sort());
    assert.ok(fixture.expectedOutcomes.length >= 2);
    for (const [file, content] of Object.entries(fixture.projectFiles)) {
      assert.ok(!file.startsWith('/') && !file.split('/').includes('..'));
      assert.equal(typeof content, 'string');
      if (file.endsWith('.json')) assert.doesNotThrow(() => JSON.parse(content));
    }
    for (const receipt of scenario.receipts) {
      const evidence = JSON.parse(await readFile('test/fixtures/guided-assessment/receipts/' + receipt));
      for (const finding of evidence.findings) assert.ok(finding.id || finding.advisoryId);
    }
    assert.equal(scenario.authorization.paid, false);
    assert.equal(scenario.authorization.liveCredentials, false);
    assert.equal(scenario.authorization.sourceUpload, false);
  }
});
