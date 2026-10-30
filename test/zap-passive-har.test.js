import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runZapPassiveHar, sanitizeHarForPassiveScan, zapPassiveHarPlan } from '../agent/zap-passive-har.mjs';

const target = 'https://app.example.com';
const secret = 'ghp_never_retain_this_secret';
const captured = JSON.stringify({ log: { entries: [{
  startedDateTime: '2026-01-01T00:00:00.000Z',
  request: { method: 'GET', url: `${target}/account/reset?token=${secret}`,
    headers: [{ name: 'Authorization', value: `Bearer ${secret}` }],
    cookies: [{ name: 'session', value: secret }], postData: { text: secret } },
  response: { status: 200, headers: [
    { name: 'Set-Cookie', value: `session=${secret}; Secure; HttpOnly; SameSite=Lax` },
    { name: 'X-Frame-Options', value: 'DENY' },
    { name: 'X-Secret-Header', value: secret }
  ], cookies: [{ name: 'session', value: secret }],
  content: { text: secret, mimeType: 'text/html', size: 100 } }
}] } });

test('sanitizes captured responses before ZAP receives them', () => {
  const sanitized = sanitizeHarForPassiveScan(captured, target);
  const output = JSON.stringify(sanitized);
  assert.ok(!output.includes(secret));
  assert.ok(!output.includes('/account/reset'));
  assert.ok(!output.includes('Authorization'));
  assert.equal(sanitized.log.entries[0].request.url.startsWith(`${target}/purple-har/`), true);
  assert.deepEqual(sanitized.log.entries[0].response.headers, [
    { name: 'Set-Cookie', value: 'purple_redacted=redacted; Secure; HttpOnly; SameSite=Lax' },
    { name: 'x-frame-options', value: 'DENY' }
  ]);
  assert.equal(sanitized.log.entries[0].response.content.text, '');
});

test('rejects out-of-scope, active, malformed, and oversized captures', () => {
  const entry = JSON.parse(captured).log.entries[0];
  for (const changed of [
    { request: { ...entry.request, url: 'http://app.example.com/' } },
    { request: { ...entry.request, url: 'https://other.example.com/' } },
    { request: { ...entry.request, method: 'POST' } },
    { response: { ...entry.response, status: 0 } }
  ]) {
    assert.throws(() => sanitizeHarForPassiveScan(JSON.stringify({ log: { entries: [{ ...entry, ...changed }] } }), target),
      /invalid or out-of-scope/);
  }
  assert.throws(() => sanitizeHarForPassiveScan('not json', target), /valid JSON/);
  assert.throws(() => sanitizeHarForPassiveScan('x'.repeat(2 * 1024 * 1024 + 1), target), /2 MiB/);
  assert.throws(() => sanitizeHarForPassiveScan(JSON.stringify({ log: { entries: Array(201).fill(entry) } }), target), /1 to 200/);
});

test('offline ZAP plan imports HAR without replay or active jobs', () => {
  const plan = zapPassiveHarPlan('/tmp/capture.har', '/tmp/report', target);
  assert.match(plan, /contexts:[\s\S]*https:\/\/app\.example\.com\//);
  assert.match(plan, /type: import[\s\S]*type: har/);
  assert.match(plan, /type: passiveScan-wait/);
  assert.match(plan, /template: traditional-json/);
  assert.doesNotMatch(plan, /spider|activeScan|sendRequests: true/);
});

test('runs ZAP only on a sanitized HAR and removes capture and report afterward', async () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'purple-zap-test-'));
  try {
    let invoked = false;
    const result = await runZapPassiveHar(captured, { target, tempRoot, execute(binary, args, options) {
      invoked = true;
      assert.equal(binary, '/zap/zap.sh');
      assert.deepEqual(args.slice(0, 2), ['-cmd', '-autorun']);
      assert.equal(args[3], '-Xmx768m');
      assert.equal(options.timeout, 180_000);
      assert.deepEqual(options.stdio, ['ignore', 'ignore', 'ignore']);
      const plan = readFileSync(args[2], 'utf8');
      assert.doesNotMatch(plan, /sendRequests: true|spider|activeScan/);
      const har = readFileSync(path.join(options.cwd, 'input.har'), 'utf8');
      assert.ok(!har.includes(secret));
      writeFileSync(path.join(options.cwd, 'report.json'), JSON.stringify({ site: [{ alerts: [{
        pluginid: '10020', riskcode: '2', alert: 'Missing X-Frame-Options Header',
        instances: [{ uri: `${target}/purple-har/1` }], evidence: secret
      }] }] }));
      return { status: 0 };
    } });
    assert.equal(invoked, true);
    assert.equal(result.status, 'completed');
    assert.equal(result.tools[0].name, 'zap-passive-har');
    assert.equal(result.tools[0].version, '2.17.0');
    assert.equal(result.findings[0].tool, 'zap-passive-har');
    assert.match(result.coverage.scope, /no live crawl or active requests/);
    assert.ok(!JSON.stringify(result).includes(secret));
    assert.deepEqual(readdirSync(tempRoot), []);
  } finally { rmSync(tempRoot, { recursive: true, force: true }); }
});

test('a failed ZAP process removes its temporary capture and returns no scanner output', async () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'purple-zap-fail-'));
  try {
    await assert.rejects(runZapPassiveHar(captured, { target, tempRoot, execute() {
      return { status: 1, stdout: secret, stderr: secret };
    } }), /ZAP passive HAR processing failed/);
    assert.deepEqual(readdirSync(tempRoot), []);
  } finally { rmSync(tempRoot, { recursive: true, force: true }); }
});

test('ZAP warnings produce partial coverage even when a report was written', async () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'purple-zap-warn-'));
  try {
    const result = await runZapPassiveHar(captured, { target, tempRoot, execute(_binary, _args, options) {
      writeFileSync(path.join(options.cwd, 'report.json'), JSON.stringify({ site: [{ alerts: [] }] }));
      return { status: 2 };
    } });
    assert.equal(result.status, 'partial');
    assert.equal(result.tools[0].status, 'partial');
    assert.match(result.warnings[0], /may be incomplete/);
    assert.deepEqual(readdirSync(tempRoot), []);
  } finally { rmSync(tempRoot, { recursive: true, force: true }); }
});
