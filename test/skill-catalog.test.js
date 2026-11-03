import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { TOOL_CATALOG } from '../shared/tool-catalog.js';
import { renderSkillCatalog, buildSkillCatalog } from '../scripts/build-skill-catalog.mjs';

test('distributed catalog contains every canonical tool exactly once with its coverage', () => {
  const output = renderSkillCatalog();
  const ids = [...output.matchAll(/^## `([^`]+)`/gm)].map(match => match[1]);
  assert.deepEqual(ids, TOOL_CATALOG.map(tool => tool.id));
  for (const tool of TOOL_CATALOG) {
    assert.ok(output.includes(tool.name));
    assert.ok(output.includes(tool.coverage));
    assert.ok(output.includes(`Input family: \`${tool.inputType}\``));
  }
  assert.match(output, /static capability information/i);
  assert.match(output, /runtime.*authoritative/i);
});

test('catalog preserves assessment boundaries and required Kubernetes inputs', () => {
  const output = renderSkillCatalog();
  assert.match(output, /## `nuclei`[\s\S]*?Four fixed checks/);
  assert.match(output, /## `mobsf-static`[\s\S]*?no emulator or dynamic execution/);
  for (const id of ['k8s-deprecations', 'k8s-manifest-validate']) {
    const section = output.split(`## \`${id}\``)[1].split('\n## ')[0];
    assert.match(section, /Required fields: `files`, `kubernetesVersion`/);
    assert.match(section, /Supported Kubernetes versions:/);
  }
});

test('catalog rendering is deterministic and follows changed source facts', () => {
  assert.equal(renderSkillCatalog(), renderSkillCatalog());
  const changed = [{ id: 'example', name: 'Example check', inputType: 'example-input', requiredInput: ['artifact'], coverage: 'Only the supplied artifact' }];
  const output = renderSkillCatalog(changed);
  assert.match(output, /## `example` — Example check/);
  assert.match(output, /Required fields: `artifact`/);
  assert.match(output, /Only the supplied artifact/);
  assert.doesNotMatch(output, /`nuclei`/);
});

test('catalog build writes exactly the rendered resource', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'offense-catalog-'));
  try {
    const target = path.join(directory, 'catalog.md');
    await buildSkillCatalog(target);
    assert.equal(await readFile(target, 'utf8'), renderSkillCatalog());
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
