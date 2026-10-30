import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { verifyClientDistribution } from '../scripts/verify-client-distribution.mjs';

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
