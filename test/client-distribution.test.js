import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, realpath, writeFile, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { verifyClientDistribution } from '../scripts/verify-client-distribution.mjs';
import { checkSkillUpdates } from '../scripts/skill-updater.mjs';

test('guided skill installs every linked resource as one checksum-verified release', async t => {
  const source = 'public/skills/offense';
  const manifest = JSON.parse(await readFile(path.join(source, 'manifest.json'), 'utf8'));
  const required = ['references/catalog.md', 'references/assessment.md', 'references/check-selection.md',
    'references/findings.md', 'references/follow-up.md', 'agents/openai.yaml'];
  const names = new Set(manifest.files.map(file => file.path));
  for (const file of required) assert.ok(names.has(file), `missing guided resource: ${file}`);
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'offense-guided-install-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  for (const file of manifest.files) {
    const bytes = await readFile(path.join(source, file.path));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256);
    assert.equal(bytes.length, file.bytes);
    await mkdir(path.dirname(path.join(directory, file.path)), { recursive: true });
    await writeFile(path.join(directory, file.path), bytes);
    if (file.path.endsWith('.md')) {
      for (const [, link] of bytes.toString().matchAll(/\]\(([^)]+)\)/g)) {
        if (/^(?:https?:|#)/.test(link)) continue;
        const target = path.posix.normalize(path.posix.join(path.posix.dirname(file.path), link.split('#')[0]));
        assert.ok(names.has(target), `${file.path} links an unpackaged resource: ${target}`);
      }
    }
  }
  const outcome = await checkSkillUpdates({ skill: 'offense', root: directory, fetchImpl: async url => {
    assert.ok(String(url).endsWith('/manifest.json'), 'complete installation should require no resource download');
    return Response.json(manifest);
  } });
  assert.equal(outcome.status, 'initialized', outcome.message);
  for (const file of required) assert.deepEqual(await readFile(path.join(directory, file)), await readFile(path.join(source, file)));
});

test('release gate checks fixed public origins and exact distribution bytes before app activation', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'offense-distribution-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(path.join(directory, 'downloads'));
  await writeFile(path.join(directory, 'downloads/offense-cli.tgz'), 'expected archive');
  await writeFile(path.join(directory, 'index.html'), 'not a client distribution');
  const ok = await verifyClientDistribution({ directory, fetchImpl: async (url, options) => {
    assert.equal(url.href, 'https://offense.sh/downloads/offense-cli.tgz');
    assert.equal(options.redirect, 'manual'); assert.equal(options.cache, 'no-store');
    return new Response('expected archive');
  } });
  assert.equal(ok.verifiedFiles, 1);
  for (const response of [new Response('expected archive', { status: 302 }), new Response('stale archive'), new Response('expected archive plus unbounded trailing data')])
    await assert.rejects(verifyClientDistribution({ directory, fetchImpl: async () => response }), /Publish the matching public client assets/);
});
