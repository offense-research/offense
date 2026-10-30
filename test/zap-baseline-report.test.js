import test from 'node:test';
import assert from 'node:assert/strict';
import { parseZapBaselineReport, normalizeZapBaselineReport } from '../agent/zap-baseline-report.mjs';

test('ZAP report drops raw evidence, query secrets, cookies and offsite URLs', () => {
  const secret = 'ghp_never_show_this_token';
  const report = { site: [{ alerts: [
    { pluginid: '10020', riskcode: '2', alert: 'Missing X-Frame-Options Header',
      evidence: secret, desc: secret, solution: secret, instances: [{ uri: `https://app.example.com/reset?token=${secret}`, param: secret, evidence: secret }] },
    { pluginid: '10021', riskcode: '3', alert: `https://app.example.com/?secret=${secret}`,
      instances: [{ uri: 'https://app.example.com/' }] },
    { pluginid: '10022', riskcode: '3', alert: 'External redirect',
      instances: [{ uri: `https://internal.example.net/?token=${secret}` }] }
  ] }] };
  const result = normalizeZapBaselineReport(report, 'https://app.example.com');
  assert.equal(result.status, 'partial');
  assert.equal(result.findings.length, 2);
  assert.deepEqual(result.findings.map(f => f.ruleId), ['10020', '10021']);
  assert.ok(!JSON.stringify(result).includes(secret));
  assert.ok(!JSON.stringify(result).includes('/reset'));
  assert.ok(!JSON.stringify(result).includes('internal.example.net'));
  assert.equal(result.findings[0].file, 'https://app.example.com');
});

test('ZAP report rejects invalid and oversized scanner output', () => {
  assert.throws(() => parseZapBaselineReport('{broken', 'https://app.example.com'), /valid JSON/);
  assert.throws(() => parseZapBaselineReport('x'.repeat(2 * 1024 * 1024 + 1), 'https://app.example.com'), /2 MiB/);
  assert.throws(() => normalizeZapBaselineReport({}, 'https://app.example.com'), /valid site report/);
  const empty = parseZapBaselineReport('{"site":[{"alerts":[]}]}', 'https://app.example.com');
  assert.equal(empty.status, 'completed');
  assert.deepEqual(empty.findings, []);
});
