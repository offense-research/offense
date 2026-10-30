import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { createHostedScans } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';
import { createToolGateway } from '../server/offense-platform.js';

const prices = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url)));
const ids = ['osv-scanner', 'semgrep', 'openssf-scorecard', 'katana', 'httpx', 'k8s-deprecations', 'k8s-manifest-validate'];

test('new tools share one account, quote, idempotency and settlement flow without counting discovery as vulnerabilities', async t => {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: prices });
  let current;
  const starts = [];
  const scans = createHostedScans(db, { metering: meter, encrypt: value => value, decrypt: value => value,
    assessmentTools: ['openssf-scorecard', 'katana', 'httpx'], sandbox: {
      async start(input) { current = input; starts.push(input); return { status: 'running' }; },
      async get() {
        const tool = current.tools[0];
        return { status: 'completed', tools: [{ name: tool, status: 'complete', durationMs: 10 }], findings: [],
          ...(tool === 'katana' || tool === 'httpx' ? { observations: [{ kind: 'endpoint', url: 'https://example.com/health' }] } : {}),
          ...(tool === 'openssf-scorecard' ? { checks: [{ name: 'Pinned-Dependencies', score: 8 }] } : {}) };
      }, async destroy() {}
    } });
  const key = scans.issueKey('new-tools-account', 'fixture-user');
  const gateway = createToolGateway({ scans, billing: {}, accounts: {}, baseUrl: 'https://offense.sh' });
  meter.recordVerifiedPurchase({ workspaceId: 'new-tools-account', paymentId: 'synthetic-new-tools-credit', amountMicros: 1_000_000 });
  const target = 'https://example.com';
  db.prepare('INSERT INTO scan_verified_targets VALUES (?, ?, ?, ?)').run('new-tools-account', target,
    JSON.stringify({ origin: target, addresses: ['93.184.216.34'] }), Date.now() + 60_000);
  const inputs = {
    'osv-scanner': { files: [{ path: 'package-lock.json', content: '{"lockfileVersion":3,"packages":{}}' }] },
    semgrep: { files: [{ path: 'src/app.js', content: 'console.log("synthetic fixture");' }] },
    'k8s-deprecations': { kubernetesVersion: '1.32.0', files: [{ path: 'pod.yaml', content: 'apiVersion: v1\nkind: Pod\n' }] },
    'k8s-manifest-validate': { kubernetesVersion: '1.35.0', files: [{ path: 'pod.yaml', content: 'apiVersion: v1\nkind: Pod\n' }] },
    'openssf-scorecard': { repository: 'ossf/scorecard' }, katana: { target }, httpx: { target }
  };
  let charge = 0;
  for (const tool of ids) {
    const quote = await gateway.execute('offense.security_quote', { tool, inputBytes: 100, fileCount: 1 }, key.token);
    assert.equal(quote.maximumMicros, prices[tool].baseMicros);
    const args = { tool, input: inputs[tool], maxChargeMicros: quote.maximumMicros, idempotencyKey: `new-tool-${tool}` };
    const first = await gateway.execute('offense.security_call', args, key.token);
    assert.equal((await gateway.execute('offense.security_call', args, key.token)).id, first.id);
    if (inputs[tool].kubernetesVersion) {
      assert.equal(first.kubernetesVersion, inputs[tool].kubernetesVersion);
      for (const kubernetesVersion of [undefined, 'latest', '../1.34.0', '1.34.1'])
        await assert.rejects(gateway.execute('offense.security_call', { ...args, input: { ...inputs[tool], kubernetesVersion } }, key.token), /kubernetesVersion/);
      await assert.rejects(gateway.execute('offense.security_call', { ...args, input: { ...inputs[tool], kubernetesVersion: '1.34.0' } }, key.token), /different source files or tools/);
    }
    await scans.dispatch(); await scans.dispatch();
    const result = await gateway.execute('offense.security_result', { id: first.id }, key.token);
    assert.equal(result.status, 'completed');
    assert.deepEqual(result.selectedTools, [tool]);
    assert.equal(result.findings.length, 0);
    if (tool === 'katana' || tool === 'httpx') assert.equal(result.observations.length, 1);
    if (tool === 'openssf-scorecard') assert.equal(result.checks[0].score, 8);
    charge += quote.maximumMicros;
  }
  assert.deepEqual(starts.map(input => input.tools[0]), ids);
  assert.equal(meter.status('new-tools-account').balanceMicros, 1_000_000 - charge);
  assert.equal(db.prepare('SELECT SUM(findings_count) AS n FROM scan_usage_jobs').get().n, 0);
  assert.equal(db.prepare('SELECT SUM(findings_count) AS n FROM scan_usage_tools').get().n, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'vulnerability_discoveries'").get().n, 0);
  assert.equal(starts.find(input => input.tools[0] === 'openssf-scorecard').assessment.options.repository, 'ossf/scorecard');
  assert.equal(starts.find(input => input.tools[0] === 'k8s-deprecations').kubernetesVersion, '1.32.0');
  assert.equal(starts.find(input => input.tools[0] === 'k8s-manifest-validate').kubernetesVersion, '1.35.0');
});
