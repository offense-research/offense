import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm, lstat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { createOffenseCli } from '../scripts/offense-cli.mjs';

const KEY = `offense_sk_${'a'.repeat(64)}`, ARTIFACT = 'b'.repeat(32), JOB = 'c'.repeat(32);
const json = (body, status = 200) => Response.json(body, { status });
async function fixture(t, handler) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'offense-advanced-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const config = path.join(directory, 'config.json'), file = path.join(directory, 'fixture.tar');
  const stdout = [], stderr = [], calls = [], bytes = Buffer.from('synthetic selected artifact');
  await writeFile(file, bytes);
  const cli = createOffenseCli({ env: { OFFENSE_CONFIG_DIR: directory },
    output: text => stdout.push(text), diagnostic: text => stderr.push(text), uuid: () => 'advanced-job-0001',
    fetchImpl: async (url, request) => {
      const address = new URL(url); calls.push({ address, request });
      assert.equal(address.origin, 'https://offense.sh');
      assert.equal(request.headers.authorization, `Bearer ${KEY}`);
      assert.equal(request.redirect, 'manual'); assert.equal(request.credentials, 'omit');
      return handler(address, request);
    } });
  const save = () => writeFile(config, JSON.stringify({ endpoint: 'https://offense.sh', apiKey: KEY }), { mode: 0o600 });
  return { directory, file, bytes, cli, calls, stdout, stderr, save,
    out: () => JSON.parse(stdout.at(-1)), error: () => JSON.parse(stderr.at(-1)) };
}
function quoted(request, tool, unit = 'per_mib') {
  const body = JSON.parse(request.body);
  return json({ currency: 'usd', billable: true, toolIds: [tool], inputBytes: body.inputBytes, fileCount: body.fileCount,
    maximumMicros: 100_000, prices: [{ tool, unit, maximumMicros: 100_000 }] });
}

test('artifact and assessment previews stay offline without a key, while the same real helper checks local scope', async t => {
  const f = await fixture(t, () => { throw Error('Preview must not use the network'); });
  assert.equal(await f.cli.run(['artifact', 'trivy-image', '--file', f.file]), 0);
  assert.equal(f.out().kind, 'image-tar'); assert.equal(f.out().bytes, f.bytes.length);
  assert.equal(await f.cli.run(['assess', 'mobsf-static', '--file', f.file, '--format', 'apk', '--preview']), 0);
  assert.equal(f.out().mode, 'preview'); assert.equal(f.out().format, 'apk');
  assert.equal(await f.cli.run(['target', 'challenge', '--target', 'https://example.com', '--preview']), 0);
  assert.equal(f.out().networkRequests, 0); assert.equal(f.calls.length, 0);
  await assert.rejects(readFile(path.join(f.directory, 'config.json')), { code: 'ENOENT' });
});

test('new discovery and public repository assessments preview offline through the CLI', async t => {
  const f = await fixture(t, () => { throw Error('Preview must not use the network'); });
  for (const tool of ['katana', 'httpx']) {
    assert.equal(await f.cli.run(['assess', tool, '--target', 'https://example.com']), 0);
    assert.equal(f.out().tool, tool); assert.equal(f.out().ownershipRequired, true); assert.equal(f.out().networkRequests, 0);
  }
  assert.equal(await f.cli.run(['assess', 'openssf-scorecard', '--repository', 'fixture/public-project']), 0);
  assert.equal(f.out().repository, 'fixture/public-project'); assert.equal(f.out().source, 'published-scorecard');
  assert.equal(f.out().publicRepositoryOnly, true); assert.equal(f.calls.length, 0);
  assert.equal(await f.cli.run(['assess', 'openssf-scorecard', '--repository', 'https://github.com/fixture/project']), 1);
  assert.match(f.error().error.message, /owner\/repo/); assert.equal(f.calls.length, 0);
});

test('scorecard CLI quotes one selected public repository and reports observations without vulnerability inflation', async t => {
  const f = await fixture(t, (url, request) => {
    if (url.pathname === '/v1/tools') return json({ tools: [{ id: 'openssf-scorecard', billingUnit: 'bounded_assessment', availability: 'available' }] });
    if (url.pathname === '/v1/quotes') return quoted(request, 'openssf-scorecard', 'bounded_assessment');
    if (url.pathname === '/v1/usage') return json({ enabled: true, availableMicros: 500_000 });
    assert.equal(url.pathname, '/v1/scans');
    assert.deepEqual(JSON.parse(request.body), { tools: ['openssf-scorecard'], repository: 'fixture/project', maxChargeMicros: 100_000 });
    return json({ id: JOB, status: 'completed', selectedTools: ['openssf-scorecard'], findings: [], observations: [
      { kind: 'supply-chain-score', tool: 'openssf-scorecard', repository: 'fixture/project', source: 'published-scorecard',
        score: 8, assessedAt: '2026-10-28', commit: 'd'.repeat(40), checks: [{ name: 'Code-Review', score: 8 }] }
    ], coverage: { scope: 'Published snapshot; no fresh scan.' } }, 202);
  });
  await f.save(); const output = path.join(f.directory, 'scorecard');
  assert.equal(await f.cli.run(['assess', 'openssf-scorecard', '--repository', 'fixture/project', '--run', '--max-price', '0.10', '--output', output]), 0);
  assert.equal(f.out().findings, 0); assert.equal(f.out().observations, 1);
  const report = JSON.parse(await readFile(path.join(output, 'assessment.json'), 'utf8'));
  assert.equal(report.confirmedVulnerabilities, 0); assert.equal(report.observations[0].score, 8);
  assert.equal(f.calls.filter(({ address }) => address.pathname === '/v1/scans').length, 1);
  assert.ok(!f.stdout.join('').includes(KEY));
});

test('artifact dispatch enforces the exact reviewed ceiling before any binary upload or scan creation', async t => {
  const f = await fixture(t, (url, request) => {
    if (url.pathname === '/v1/quotes') return quoted(request, 'trivy-image');
    assert.equal(url.pathname, '/v1/usage'); return json({ enabled: true, availableMicros: 500_000 });
  });
  await f.save();
  assert.equal(await f.cli.run(['artifact', 'trivy-image', '--file', f.file, '--run']), 1);
  assert.equal(f.error().error.code, 'budget_required');
  assert.equal(await f.cli.run(['artifact', 'trivy-image', '--file', f.file, '--run', '--max-price', '0.09']), 1);
  assert.equal(f.error().error.code, 'budget_exceeded');
  assert.ok(f.calls.every(({ address }) => ['/v1/quotes', '/v1/usage'].includes(address.pathname)));
});

test('private login credential streams a bounded artifact, saves a key-free exact recovery input and preserves partial results', async t => {
  let uploaded;
  const f = await fixture(t, async (url, request) => {
    if (url.pathname === '/v1/quotes') return quoted(request, 'trivy-image');
    if (url.pathname === '/v1/usage') return json({ enabled: true, availableMicros: 500_000 });
    if (url.pathname === '/v1/artifacts') {
      const parts = []; for await (const part of request.body) parts.push(part); uploaded = Buffer.concat(parts);
      assert.equal(request.headers['x-purple-artifact-kind'], 'image-tar');
      assert.equal(request.headers['x-content-sha256'], createHash('sha256').update(uploaded).digest('hex'));
      assert.equal(Number(request.headers['content-length']), uploaded.length);
      return json({ id: ARTIFACT }, 201);
    }
    assert.equal(url.pathname, '/v1/scans');
    assert.deepEqual(JSON.parse(request.body), { artifactId: ARTIFACT, tools: ['trivy-image'], maxChargeMicros: 100_000 });
    assert.equal(request.headers['idempotency-key'], 'advanced-job-0001');
    return json({ id: JOB, status: 'partial', selectedTools: ['trivy-image'], findings: [], tools: [], coverage: { scope: 'Fixture only.' } }, 202);
  });
  await f.save(); const before = await readFile(path.join(f.directory, 'config.json'), 'utf8');
  const output = path.join(f.directory, 'results');
  assert.equal(await f.cli.run(['artifact', 'trivy-image', '--file', f.file, '--run', '--max-price', '0.10', '--output', output]), 2);
  assert.deepEqual(uploaded, f.bytes); assert.equal(f.out().status, 'partial');
  const recovery = await readFile(path.join(output, 'submission.json'), 'utf8');
  assert.deepEqual(JSON.parse(recovery), { artifactId: ARTIFACT, inputBytes: f.bytes.length, fileCount: 1 });
  assert.equal((await lstat(path.join(output, 'submission.json'))).mode & 0o077, 0);
  assert.ok(!recovery.includes(KEY)); assert.ok(!recovery.includes(f.bytes.toString()));
  assert.ok(!f.stdout.join('').includes(KEY)); assert.ok(!f.stderr.join('').includes(KEY));
  assert.equal(await readFile(path.join(f.directory, 'config.json'), 'utf8'), before);
});

test('target challenge and verification use the existing login account without submitting or paying for a scan', async t => {
  const challenge = { origin: 'https://example.com', recordName: '_purple-scan.example.com',
    recordValue: 'purple-scan-verification=' + 'd'.repeat(32), token: 'd'.repeat(32), signature: 'e'.repeat(64), expiresAt: Date.now() + 600_000 };
  const f = await fixture(t, (url, request) => {
    if (url.pathname === '/v1/targets/challenge') { assert.deepEqual(JSON.parse(request.body), { target: challenge.origin }); return json(challenge); }
    assert.equal(url.pathname, '/v1/targets/verify');
    assert.deepEqual(JSON.parse(request.body), { challenge });
    return json({ origin: challenge.origin, verifiedAt: Date.now(), expiresAt: challenge.expiresAt });
  });
  await f.save();
  assert.equal(await f.cli.run(['target', 'challenge', '--target', challenge.origin, '--output', path.join(f.directory, 'proof')]), 0);
  const filename = f.out().challengeFile;
  assert.equal(f.out().recordName, challenge.recordName); assert.equal((await lstat(filename)).mode & 0o077, 0);
  assert.equal(await f.cli.run(['target', 'verify', '--input', filename]), 0);
  assert.equal(f.out().origin, challenge.origin);
  assert.deepEqual(f.calls.map(({ address }) => address.pathname), ['/v1/targets/challenge', '/v1/targets/verify']);
  assert.ok(!f.stdout.join('').includes(KEY));
});

test('mobile assessment reuses the same key, approved quote, streamed upload and ordinary job lifecycle', async t => {
  const f = await fixture(t, async (url, request) => {
    if (url.pathname === '/v1/tools') return json({ tools: [{ id: 'mobsf-static', billingUnit: 'bounded_assessment', availability: 'available' }] });
    if (url.pathname === '/v1/quotes') return quoted(request, 'mobsf-static', 'bounded_assessment');
    if (url.pathname === '/v1/usage') return json({ enabled: true, availableMicros: 500_000 });
    if (url.pathname === '/v1/artifacts') {
      const parts = []; for await (const part of request.body) parts.push(part);
      assert.deepEqual(Buffer.concat(parts), f.bytes); assert.equal(request.headers['x-purple-artifact-kind'], 'mobile-app');
      return json({ id: ARTIFACT }, 201);
    }
    assert.equal(url.pathname, '/v1/scans');
    assert.deepEqual(JSON.parse(request.body), { tools: ['mobsf-static'], format: 'apk', artifactId: ARTIFACT, maxChargeMicros: 100_000 });
    return json({ id: JOB, status: 'completed', selectedTools: ['mobsf-static'], findings: [], coverage: { scope: 'Static fixture.' } }, 202);
  });
  await f.save();
  assert.equal(await f.cli.run(['assess', 'mobsf-static', '--file', f.file, '--format', 'apk', '--run', '--max-price', '0.10', '--output', path.join(f.directory, 'mobile')]), 0);
  assert.equal(f.out().status, 'completed');
  const receipt = JSON.parse(await readFile(path.join(f.directory, 'mobile/submission.json'), 'utf8'));
  assert.equal(receipt.artifactId, ARTIFACT); assert.equal(receipt.format, 'apk');
  assert.equal(f.calls.filter(({ address }) => address.pathname === '/v1/scans').length, 1);
});

test('advanced calls reject a different origin, mismatched quote and invalid receipt without a second mutation', async t => {
  const mismatch = await fixture(t, () => { throw Error('Must not send an old credential to another origin'); });
  await mismatch.save();
  assert.equal(await mismatch.cli.run(['artifact', 'trivy-image', '--file', mismatch.file, '--run', '--endpoint', 'https://different.example']), 1);
  assert.equal(mismatch.error().error.code, 'endpoint_mismatch'); assert.equal(mismatch.calls.length, 0);
  for (const problem of ['quote', 'receipt']) {
    const f = await fixture(t, (url, request) => {
      if (url.pathname === '/v1/quotes') return problem === 'quote' ? json({ currency: 'usd', billable: true, toolIds: ['gitleaks'], maximumMicros: 100_000 }) : quoted(request, 'trivy-image');
      if (url.pathname === '/v1/usage') return json({ enabled: true, availableMicros: 500_000 });
      if (url.pathname === '/v1/artifacts') return json({ id: ARTIFACT });
      return json({ id: JOB, status: 'made_up_success' });
    });
    await f.save();
    assert.equal(await f.cli.run(['artifact', 'trivy-image', '--file', f.file, '--run', '--max-price', '0.10']), 1);
    assert.equal(f.error().error.code, problem === 'quote' ? 'invalid_quote' : 'invalid_receipt');
    assert.equal(f.calls.filter(({ address }) => address.pathname === '/v1/scans').length, problem === 'quote' ? 0 : 1);
  }
});

test('active assessment confirmations and separate provider tokens remain required before requests', async t => {
  const f = await fixture(t, () => { throw Error('Must stop before a scan'); });
  await f.save();
  assert.equal(await f.cli.run(['assess', 'schemathesis', '--target', 'https://example.com', '--schema', f.file, '--run', '--max-price', '1']), 1);
  assert.match(f.error().error.message, /confirm-active-testing/);
  assert.equal(await f.cli.run(['assess', 'prowler-cloudflare', '--account-id', 'd'.repeat(32), '--token-env', 'OFFENSE_API_KEY', '--run', '--max-price', '1']), 1);
  assert.match(f.error().error.message, /separate read-only provider token/); assert.equal(f.calls.length, 0);
});

test('an uncertain artifact submission retains exact private recovery input and never automatically uploads or submits again', async t => {
  const f = await fixture(t, async (url, request) => {
    if (url.pathname === '/v1/quotes') return quoted(request, 'trivy-image');
    if (url.pathname === '/v1/usage') return json({ enabled: true, availableMicros: 500_000 });
    if (url.pathname === '/v1/artifacts') { for await (const chunk of request.body) assert.ok(chunk.length); return json({ id: ARTIFACT }); }
    assert.equal(url.pathname, '/v1/scans'); throw Error('Synthetic response lost');
  });
  await f.save(); const output = path.join(f.directory, 'recovery');
  assert.equal(await f.cli.run(['artifact', 'trivy-image', '--file', f.file, '--run', '--max-price', '0.10', '--output', output]), 1);
  assert.equal(f.calls.filter(({ address }) => address.pathname === '/v1/artifacts').length, 1);
  assert.equal(f.calls.filter(({ address }) => address.pathname === '/v1/scans').length, 1);
  const saved = JSON.parse(await readFile(path.join(output, 'submission.json'), 'utf8'));
  assert.deepEqual(saved, { artifactId: ARTIFACT, inputBytes: f.bytes.length, fileCount: 1 });
  const resume = f.stderr.map(line => JSON.parse(line)).find(line => line.resume);
  assert.equal(resume.idempotencyKey, 'advanced-job-0001'); assert.match(resume.resume, /offense call trivy-image/);
  assert.ok(!JSON.stringify(resume).includes(KEY));
});
