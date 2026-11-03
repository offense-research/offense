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
