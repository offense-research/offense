import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { hostedScanTools } from '../../server/hosted-scans.js';
import { landingCatalog, renderToolRows } from '../scripts/catalog.mjs';

test('landing lists the canonical tool IDs and coverage without promising live availability or prices', () => {
  const tools = landingCatalog(), canonical = hostedScanTools().tools;
  assert.deepEqual(Object.keys(tools), ['dependency-audit', ...canonical.map(tool => tool.id)]);
  for (const tool of canonical) {
    assert.equal(tools[tool.id].title, tool.name);
    assert.equal(tools[tool.id].description, tool.coverage);
    assert.equal(tools[tool.id].url, 'https://offense.sh/app#tools');
    assert.equal(tools[tool.id].action, 'View tool and pricing');
    assert.equal('priceMicros' in tools[tool.id], false);
    assert.equal('availability' in tools[tool.id], false);
  }
  assert.match(tools['dependency-audit'].points.join(' '), /free.*no account/);
  assert.match(tools.nuclei.points.join(' '), /ownership verification.*explicit authorization/);
  assert.match(tools['prowler-cloudflare'].points.join(' '), /optional tool.*no cloud connection is needed/);
  assert.equal((renderToolRows(tools).match(/class="tool-row"/g) || []).length, Object.keys(tools).length);
});

test('landing setup keeps CLI approval and the API key portal in the agent workflow', async () => {
  const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  const llms = await readFile(new URL('../public/llms.txt', import.meta.url), 'utf8');
  assert.match(html, /Set up Offense from/);
  assert.match(html, /https:\/\/<wbr>offense\.sh\/<wbr>llms\.txt/);
  assert.match(html, /offense\.sh\/account#keys/);
  assert.match(html, /alongside tools already in your agent/);
  assert.match(llms, /human checks the comparison code and approves/);
  assert.match(llms, /No GitHub App\s+installation, repository connection, Cloudflare connection or OpenRouter key/);
  assert.match(llms, /existing local tools/);
});
