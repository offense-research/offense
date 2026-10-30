import assert from 'node:assert/strict';
import test from 'node:test';
import {landingCatalog} from '../scripts/catalog.mjs';
import {localToolDetails} from '../src/local-tools.js';
const toolDetails = landingCatalog();

test('local capabilities remain separate from the hosted scanner inventory', () => {
  assert.deepEqual(Object.keys(localToolDetails).sort(), ['local-api', 'local-source']);
  assert.equal(Object.keys(toolDetails).length, 29);
  for (const id of Object.keys(localToolDetails)) assert.equal(Object.hasOwn(toolDetails, id), false);
});

test('local tool dialogs provide prerequisites and the maintained skill entrypoint', () => {
  for (const detail of Object.values(localToolDetails)) {
    assert.ok(detail.title.length > 0);
    assert.equal(detail.points.length, 3);
    assert.equal(detail.url, 'https://offense.sh/skills/purple/SKILL.md');
    assert.equal(detail.action, 'Read Offense skill');
  }
  assert.match(JSON.stringify(localToolDetails['local-source']), /scanner binaries/i);
  assert.match(JSON.stringify(localToolDetails['local-source']), /does not install/i);
  assert.match(JSON.stringify(localToolDetails['local-api']), /Docker/);
});
